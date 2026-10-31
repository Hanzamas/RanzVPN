package sidecar

// The stretch of a gateway against FRR, the reference BGP speaker of a data-centre fabric (SDN-64 #291; ADR-0032 amendment
// of 2026-10-22). The job "EVPN with FRR" of ranz.yml runs two leaves of a fabric, FRR in a container of its own each, on a
// bridge of the runner (testdata/frr-stretch/stretch.sh), which stands in for the second host (ADR-0002 amendment of
// 2026-10-21): each carries the L2 VNI 5010 of the stretched Network, with ARP suppression on its VXLAN device, and has a host
// of the fabric behind it. The job sets RANZ_FRR_STRETCH; without it the test is skipped. The test is the gateway on the
// runner, 172.31.26.1: its sidecar, which the leaves dial on port 1179, and its VTEP on UDP port 4789, which does with the
// frames of the VNI what the node does (src/Cedar/NodeStretch.c, which vpntest stretch runs on Windows): a frame to a MAC
// address of a type-2 route of the fabric goes to the VTEP of that route, and any other, a broadcast among them, to each VTEP
// of the type-3 routes of the fabric once (ingress replication). Behind the gateway is a host of the overlay, which answers
// ARP for its address and ICMP echo requests, as the switch of the Network hands them to it.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// The addresses, the VTEPs and the MAC addresses of stretch.sh, leaf-a.conf and leaf-b.conf
const (
	stretchGatewayAddr = "172.31.26.1"
	stretchLeafA       = "172.31.26.10"
	stretchLeafB       = "172.31.26.11"
	stretchOverlayMAC  = "02:52:5a:64:00:01"
	stretchHostAMAC    = "02:00:5e:50:00:0a"
	stretchBroadcast   = "ff:ff:ff:ff:ff:ff"
)

// The host of the overlay behind the gateway, the hosts of the fabric behind leaf a and leaf b, and the broadcast address of
// the Network
var (
	stretchOverlayHost = netip.MustParseAddr("10.50.0.1")
	stretchHostA       = netip.MustParseAddr("10.50.0.10")
	stretchHostB       = netip.MustParseAddr("10.50.0.11")
	stretchAllHosts    = netip.MustParseAddr("10.50.0.255")
)

// The EtherTypes and the ARP operations of the frames of the test
const (
	etherIPv4  = 0x0800
	etherARP   = 0x0806
	arpRequest = 1
	arpReply   = 2
)

// stretchGateway is the gateway on the runner: its VTEP, with the routes of the fabric that its node holds, and the host of
// the overlay behind it, with what came to it
type stretchGateway struct {
	t       *testing.T
	conn    *net.UDPConn
	overlay net.HardwareAddr

	mu       sync.Mutex
	macs     map[string]netip.Addr // the VTEP of each MAC address of a type-2 route of the fabric
	flood    []netip.Addr          // the VTEPs of the type-3 routes of the fabric
	arps     int                   // ARP requests for the host of the overlay that came through VXLAN
	asked    map[netip.Addr]int    // ICMP echo requests to the host of the overlay, by source
	replies  map[string]int        // ICMP echo replies to the host of the overlay, by "<source> <seq>"
	answered map[netip.Addr]string // the MAC address of each host that answered an ARP request of the host of the overlay
}

func openStretchGateway(t *testing.T) *stretchGateway {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(stretchGatewayAddr), frrVTEPPort)))
	if err != nil {
		t.Fatalf("the VTEP of the gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	overlay, _ := net.ParseMAC(stretchOverlayMAC)
	g := &stretchGateway{t: t, conn: conn, overlay: overlay, macs: make(map[string]netip.Addr), asked: make(map[netip.Addr]int),
		replies: make(map[string]int), answered: make(map[netip.Addr]string)}
	go g.serve()
	return g
}

// take sets the routes of the fabric that the node holds now (learnedStretch)
func (g *stretchGateway) take(learned map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	clear(g.macs)
	g.flood = g.flood[:0]
	for k, v := range learned {
		vtep, err := netip.ParseAddr(v)
		f := strings.Split(k, " ")
		if err != nil || len(f) != 3 {
			continue
		}
		if f[1] == "vtep" {
			g.flood = append(g.flood, vtep)
		} else {
			g.macs[f[1]] = vtep
		}
	}
}

// floods reports whether the flood list is the VTEPs vteps, in any order
func (g *stretchGateway) floods(vteps ...string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.flood) != len(vteps) {
		return false
	}
	for _, v := range vteps {
		found := false
		for _, f := range g.flood {
			found = found || f.String() == v
		}
		if !found {
			return false
		}
	}
	return true
}

// vtepOf is the VTEP of a MAC address of the fabric, "" for none
func (g *stretchGateway) vtepOf(mac string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if v, ok := g.macs[mac]; ok {
		return v.String()
	}
	return ""
}

// count reads one counter under the lock
func (g *stretchGateway) count(f func() int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return f()
}

// answer is the MAC address with which the host of ip answered an ARP request of the host of the overlay, "" for none
func (g *stretchGateway) answer(ip netip.Addr) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.answered[ip]
}

// send sends the frame to its destination MAC address as the node does: to the VTEP of the type-2 route of the address, or
// to each VTEP of the flood list once, for a broadcast and for an address that no route holds
func (g *stretchGateway) send(frame []byte) {
	g.t.Helper()
	dst := net.HardwareAddr(frame[:6]).String()
	g.mu.Lock()
	vteps := []netip.Addr{}
	if v, ok := g.macs[dst]; ok && dst != stretchBroadcast {
		vteps = append(vteps, v)
	} else {
		vteps = append(vteps, g.flood...)
	}
	g.mu.Unlock()

	vni := uint32(testStretchVNI)
	b := make([]byte, 8+len(frame))
	b[0] = 0x08
	b[4], b[5], b[6] = byte(vni>>16), byte(vni>>8), byte(vni)
	copy(b[8:], frame)
	for _, v := range vteps {
		if _, err := g.conn.WriteToUDPAddrPort(b, netip.AddrPortFrom(v, frrVTEPPort)); err != nil {
			g.t.Errorf("a frame to the VTEP %s: %v", v, err)
		}
	}
}

// ethernet is a frame of the payload from src to dst, untagged
func ethernet(dst, src string, ether uint16, payload []byte) []byte {
	d, _ := net.ParseMAC(dst)
	s, _ := net.ParseMAC(src)
	b := make([]byte, 14+len(payload))
	copy(b, d)
	copy(b[6:], s)
	binary.BigEndian.PutUint16(b[12:], ether)
	copy(b[14:], payload)
	return b
}

// arp is an ARP packet of IPv4 over Ethernet
func arp(op uint16, sha string, spa netip.Addr, tha string, tpa netip.Addr) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], etherIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], op)
	s, _ := net.ParseMAC(sha)
	t, _ := net.ParseMAC(tha)
	copy(b[8:], s)
	copy(b[14:], spa.AsSlice())
	copy(b[18:], t)
	copy(b[24:], tpa.AsSlice())
	return b
}

// echo is the IPv4 packet of an ICMP echo request or reply from src to dst
func echo(typ ipv4.ICMPType, src, dst netip.Addr, id, seq int) []byte {
	msg, _ := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("ranz stretch")}}).Marshal(nil)
	ip := make([]byte, 20+len(msg))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = protocolICMP
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip[:20]))
	copy(ip[20:], msg)
	return ip
}

// serve takes the datagrams of the VTEP of the gateway until it closes
func (g *stretchGateway) serve() {
	buf := make([]byte, 2048)
	for {
		n, _, err := g.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		b := buf[:n]
		if len(b) < 8+14 || b[0]&0x08 == 0 || uint32(b[4])<<16|uint32(b[5])<<8|uint32(b[6]) != testStretchVNI {
			continue
		}
		g.input(b[8:])
	}
}

// input is a frame of the VNI for the host of the overlay: an ARP request for its address, which it answers and counts, an
// ARP reply to it, an ICMP echo request, which it answers, or an ICMP echo reply to it
func (g *stretchGateway) input(f []byte) {
	src := net.HardwareAddr(f[6:12]).String()
	switch binary.BigEndian.Uint16(f[12:]) {
	case etherARP:
		a := f[14:]
		if len(a) < 28 {
			return
		}
		op := binary.BigEndian.Uint16(a[6:])
		spa, _ := netip.AddrFromSlice(a[14:18])
		tpa, _ := netip.AddrFromSlice(a[24:28])
		sha := net.HardwareAddr(a[8:14]).String()
		switch {
		case op == arpRequest && tpa == stretchOverlayHost:
			g.mu.Lock()
			g.arps++
			g.mu.Unlock()
			g.send(ethernet(sha, stretchOverlayMAC, etherARP, arp(arpReply, stretchOverlayMAC, stretchOverlayHost, sha, spa)))
		case op == arpReply && tpa == stretchOverlayHost:
			g.mu.Lock()
			g.answered[spa] = sha
			g.mu.Unlock()
		}
	case etherIPv4:
		ip := f[14:]
		if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != protocolICMP {
			return
		}
		hl := int(ip[0]&0x0F) * 4
		from, _ := netip.AddrFromSlice(ip[12:16])
		to, _ := netip.AddrFromSlice(ip[16:20])
		if hl < 20 || len(ip) < hl || to != stretchOverlayHost {
			return
		}
		m, err := icmp.ParseMessage(protocolICMP, ip[hl:])
		if err != nil {
			return
		}
		e, ok := m.Body.(*icmp.Echo)
		if !ok {
			return
		}
		g.mu.Lock()
		if m.Type == ipv4.ICMPTypeEcho {
			g.asked[from]++
		} else if m.Type == ipv4.ICMPTypeEchoReply {
			g.replies[fmt.Sprintf("%s %d", from, e.Seq)]++
		}
		g.mu.Unlock()
		if m.Type == ipv4.ICMPTypeEcho {
			g.send(ethernet(src, stretchOverlayMAC, etherIPv4, echo(ipv4.ICMPTypeEchoReply, stretchOverlayHost, from, e.ID, e.Seq)))
		}
	}
}

// hostRun runs a command in the network namespace of a host of the fabric: what it wrote, and whether it succeeded
func hostRun(t *testing.T, host string, args ...string) (string, bool) {
	t.Helper()
	out, err := exec.Command("sudo", append([]string{"ip", "netns", "exec", host}, args...)...).CombinedOutput()
	if err != nil {
		t.Logf("%s: %v: %v\n%s", host, args, err, out)
		return string(out), false
	}
	return string(out), true
}

// dumpStretch writes the state of a leaf and of the kernel of its container into the log of the test when it failed
func dumpStretch(f *frrRouter) {
	if !f.t.Failed() {
		return
	}
	for _, command := range []string{
		"show bgp summary",
		"show bgp l2vpn evpn route",
		"show evpn vni 5010 detail",
		"show evpn mac vni 5010",
		"show evpn arp-cache vni 5010",
	} {
		if out, ok := f.vtysh(command); ok {
			f.t.Logf("%s: %s:\n%s", f.container, command, out)
		}
	}
	pid, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", f.container).Output()
	if err != nil {
		return
	}
	for _, args := range [][]string{{"ip", "neigh", "show"}, {"bridge", "fdb", "show"}} {
		out, _ := exec.Command("sudo", append([]string{"nsenter", "-t", strings.TrimSpace(string(pid)), "-n"}, args...)...).CombinedOutput()
		f.t.Logf("%s: %v:\n%s", f.container, args, out)
	}
}

// The gateway against two leaves of FRR on one stretched Network. The gateway announces the host of the overlay as MAC only
// and as MAC plus IP, and the type-3 route of its VTEP; it learns the type-3 routes of both leaves, its flood list. Each
// leaf holds the address of the host of the overlay, so its bridge answers an ARP request for it itself: the host behind
// leaf a pings the host of the overlay through VXLAN, and no ARP request for it reaches the gateway. The other way, the MAC
// address of the host behind leaf a comes to the gateway as a type-2 route of leaf a; the ARP request of the host of the
// overlay, a broadcast, reaches it through the flood list, and its echo request goes to the VTEP of leaf a alone and is
// answered. A broadcast echo request of the overlay goes to each VTEP of the flood list once, and each host of the fabric
// answers it once.
func TestFRRStretch(t *testing.T) {
	if os.Getenv("RANZ_FRR_STRETCH") == "" {
		t.Skip("RANZ_FRR_STRETCH is not set; the job EVPN with FRR of ranz.yml runs this test against the leaves of stretch.sh")
	}
	leaves := []*frrRouter{{t: t, container: "ranz-leaf-a"}, {t: t, container: "ranz-leaf-b"}}
	for _, l := range leaves {
		if _, ok := l.vtysh("show version"); !ok {
			t.Fatalf("FRR in the container %s does not answer", l.container)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw := openStretchGateway(t)
	node := startNode(t, ctx)
	// The cleanups run last first: the state of the leaves goes into the log before the pipe of the node closes
	t.Cleanup(func() {
		for _, l := range leaves {
			dumpStretch(l)
		}
	})
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      frrBGPPort,
		ListenAddresses: []string{stretchGatewayAddr},
		Peers:           []Peer{{Address: stretchLeafA, ASN: 65010, Passive: true}, {Address: stretchLeafB, ASN: 65011, Passive: true}},
		EVPN:            &EVPN{VTEP: stretchGatewayAddr, Stretches: []EVPNStretch{{VNI: testStretchVNI, RouteTargets: []string{testStretchTarget}}}},
	})
	node.wait("ready", false, isType(TypeReady))
	node.wait("leaf a established", true, isPeer(stretchLeafA, StateEstablished))
	node.wait("leaf b established", true, isPeer(stretchLeafB, StateEstablished))

	// The host of the overlay, MAC only and MAC plus IP; the type-3 routes of both leaves are the flood list of the gateway
	node.resync([]StretchRoute{{VNI: testStretchVNI, MAC: stretchOverlayMAC}, {VNI: testStretchVNI, MAC: stretchOverlayMAC, IP: stretchOverlayHost.String()}})
	waitUntil(t, "the gateway learns the type-3 routes of both leaves", func() bool {
		gw.take(node.learnedStretch())
		return gw.floods(stretchLeafA, stretchLeafB)
	})

	// The MAC plus IP form: each leaf holds the address of the host of the overlay behind the VTEP of the gateway
	for _, l := range leaves {
		waitUntil(t, l.container+" holds the address of the host of the overlay", func() bool {
			out, _ := l.vtysh("show evpn arp-cache vni 5010 ip " + stretchOverlayHost.String())
			return strings.Contains(out, stretchOverlayMAC) && strings.Contains(out, stretchGatewayAddr)
		})
	}

	// The fabric to the overlay: host a pings the host of the overlay, and the bridge of leaf a answers its ARP request
	if out, ok := hostRun(t, "ranz-host-a", "ping", "-c", "3", "-W", "2", stretchOverlayHost.String()); !ok {
		t.Errorf("host a does not reach the host of the overlay through the stretch:\n%s", out)
	}
	if n := gw.count(func() int { return gw.asked[stretchHostA] }); n == 0 {
		t.Error("no echo request of host a reached the gateway through VXLAN")
	}
	if n := gw.count(func() int { return gw.arps }); n != 0 {
		t.Errorf("%d ARP requests for the host of the overlay reached the gateway through VXLAN: leaf a did not suppress ARP for it", n)
	}
	if out, _ := hostRun(t, "ranz-host-a", "ip", "neigh", "show", stretchOverlayHost.String()); !strings.Contains(out, stretchOverlayMAC) {
		t.Errorf("host a has no neighbour entry of the host of the overlay with its MAC address: %q", out)
	}

	// The overlay to the fabric: the MAC address of host a comes as a type-2 route of leaf a; the ARP request of the host of
	// the overlay reaches host a through the flood list, and its echo request goes to leaf a alone
	waitUntil(t, "the gateway learns the MAC address of host a behind leaf a", func() bool {
		gw.take(node.learnedStretch())
		return gw.vtepOf(stretchHostAMAC) == stretchLeafA
	})
	gw.send(ethernet(stretchBroadcast, stretchOverlayMAC, etherARP, arp(arpRequest, stretchOverlayMAC, stretchOverlayHost, "00:00:00:00:00:00", stretchHostA)))
	waitUntil(t, "host a answers the ARP request of the host of the overlay", func() bool { return gw.answer(stretchHostA) != "" })
	if mac := gw.answer(stretchHostA); mac != stretchHostAMAC {
		t.Errorf("host a answered the ARP request with the MAC address %s, not %s", mac, stretchHostAMAC)
	}
	for seq := 1; seq <= 3; seq++ {
		gw.send(ethernet(stretchHostAMAC, stretchOverlayMAC, etherIPv4, echo(ipv4.ICMPTypeEcho, stretchOverlayHost, stretchHostA, 64, seq)))
	}
	waitUntil(t, "host a answers the echo requests of the host of the overlay", func() bool {
		return gw.count(func() int {
			return gw.replies[fmt.Sprintf("%s 1", stretchHostA)] + gw.replies[fmt.Sprintf("%s 3", stretchHostA)]
		}) != 0
	})

	// A broadcast of the overlay reaches each VTEP of the flood list once: each host of the fabric answers it once
	gw.send(ethernet(stretchBroadcast, stretchOverlayMAC, etherIPv4, echo(ipv4.ICMPTypeEcho, stretchOverlayHost, stretchAllHosts, 64, 100)))
	waitUntil(t, "both hosts of the fabric answer the broadcast", func() bool {
		return gw.count(func() int {
			return min(gw.replies[fmt.Sprintf("%s 100", stretchHostA)], gw.replies[fmt.Sprintf("%s 100", stretchHostB)])
		}) != 0
	})
	time.Sleep(settleTime)
	a := gw.count(func() int { return gw.replies[fmt.Sprintf("%s 100", stretchHostA)] })
	b := gw.count(func() int { return gw.replies[fmt.Sprintf("%s 100", stretchHostB)] })
	if a != 1 || b != 1 {
		t.Errorf("the broadcast reached host a %d times and host b %d times, not once each", a, b)
	}
}
