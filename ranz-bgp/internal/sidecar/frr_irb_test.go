package sidecar

// The symmetric IRB of a stretch against FRR, the reference BGP speaker of a data-centre fabric (SDN-67 #294; ADR-0032
// amendment of 2026-10-22). The job "EVPN with FRR" of ranz.yml runs one leaf of a fabric with symmetric IRB, FRR in a
// container of its own on a bridge of the runner (testdata/frr-irb/irb.sh), which stands in for the second host (ADR-0002
// amendment of 2026-10-21): its VRFs red and blue, each with its L3 VNI and router MAC, have the same stretched Network
// 10.50.0.0/24 on an L2 VNI of their own, whose bridge is the SVI of the VRF, and behind it a host of the fabric with the same
// address in both, whose first hop is the leaf; the leaf carries the L2 VNI of a stretch without irb too. The job sets
// RANZ_FRR_IRB; without it the test is skipped. The test is the gateway on the runner, 172.31.27.1: its sidecar, which the
// leaf dials on port 1179, and its VTEP on UDP port 4789, which stands in for the forwarding of the node in its EVPN VRFs with
// the routes that the sidecar gives it, as the node takes and sends the frames of an L3 VNI (NodeEvpnReceive and NodeEvpnSend
// of src/Cedar/NodeEvpn.c): it takes a frame of an L3 VNI only from a VTEP of a route of the VRF of the VNI, to the router MAC
// of the gateway, with a packet whose source a route of that VRF holds, and it sends a packet of a VRF by the route of the VRF
// that holds its destination, on the VNI of the route, to its VTEP and its router MAC. Behind the gateway, in each VRF, is an
// overlay node of another Network of the VRF, 10.60.0.2 in the prefix 10.60.0.0/24 that the gateway announces there, which
// answers ICMP echo requests.

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

// The addresses, the VTEPs and the MAC addresses of irb.sh and leaf.conf, and of the hosts of the overlay at the gateway
const (
	irbGatewayAddr = "172.31.27.1"
	irbLeafAddr    = "172.31.27.10"
	irbFirstHop    = "10.50.0.254"       // the address of the leaf in each stretched Network, the first hop of its host
	irbGatewayIP   = "10.50.0.1"         // the gateway IP of each stretch with irb
	irbOverlayMAC  = "02:52:5a:67:00:01" // the host of the overlay on the stretched Network of red
	irbPlainMAC    = "02:52:5a:67:00:02" // the host of the overlay on the Network of the stretch without irb
	irbPlainVNI    = 5030
)

// The host of the fabric in each VRF, the overlay node of another Network in each VRF, and the hosts of the overlay on the
// stretched Network of red and on the Network of the stretch without irb
var (
	irbFabricHost  = netip.MustParseAddr("10.50.0.10")
	irbOverlayNode = netip.MustParseAddr("10.60.0.2")
	irbOverlayHost = netip.MustParseAddr("10.50.0.20")
	irbPlainHost   = netip.MustParseAddr("10.53.0.5")
)

// irbVRF is an EVPN VRF of the gateway in the test, with the name, the L3 VNI and the router MAC of the VRF of the leaf that
// imports and exports its route target, the L2 VNI of its stretched Network and the namespace of its host of the fabric.
type irbVRF struct {
	id   uint32
	name string
	vni  uint32
	mac  string
	l2   uint32
	host string
}

var irbVRFs = []irbVRF{
	{id: 101, name: "red", vni: 10201, mac: "02:00:5e:20:00:01", l2: 5020, host: "ranz-irb-red"},
	{id: 102, name: "blue", vni: 10202, mac: "02:00:5e:20:00:02", l2: 5021, host: "ranz-irb-blue"},
}

// irbGateway is the gateway on the runner: its VTEP, with the routes of its EVPN VRFs that its node holds, and the overlay
// node behind it in each VRF, with what came to it
type irbGateway struct {
	conn *net.UDPConn

	mu      sync.Mutex
	routes  map[uint32]map[netip.Prefix]Message // the routes of each EVPN VRF that the node holds: its learned messages with a vni
	asked   map[string]int                      // the echo requests to the overlay node, by "<vrf> <source> <router MAC of the frame>"
	dropped []string                            // the frames of an L3 VNI that the gateway did not take, and why
}

func openIRBGateway(t *testing.T) *irbGateway {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(irbGatewayAddr), frrVTEPPort)))
	if err != nil {
		t.Fatalf("the VTEP of the gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	g := &irbGateway{conn: conn, routes: make(map[uint32]map[netip.Prefix]Message), asked: make(map[string]int)}
	go g.serve()
	return g
}

// take sets the routes of the EVPN VRFs that the node holds now: the learned and withdrawn messages with a vni of seen, in
// order
func (g *irbGateway) take(seen []Message) {
	routes := make(map[uint32]map[netip.Prefix]Message)
	for _, m := range seen {
		p, err := netip.ParsePrefix(m.Prefix)
		if m.VNI == 0 || err != nil || (m.Type != TypeLearned && m.Type != TypeWithdrawn) {
			continue
		}
		if routes[m.VRF] == nil {
			routes[m.VRF] = make(map[netip.Prefix]Message)
		}
		if m.Type == TypeLearned {
			routes[m.VRF][p] = m
		} else {
			delete(routes[m.VRF], p)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routes = routes
}

// lookup is the route of the VRF vrf whose prefix holds a, the longest one; the caller holds mu
func (g *irbGateway) lookup(vrf uint32, a netip.Addr) (Message, bool) {
	best, bits := Message{}, -1
	for p, r := range g.routes[vrf] {
		if p.Contains(a) && p.Bits() > bits {
			best, bits = r, p.Bits()
		}
	}
	return best, bits >= 0
}

// knows reports whether vtep is a VTEP that the gateway knows for the VRF vrf: the next hop of one of its routes, or one of their
// vteps; the caller holds mu
func (g *irbGateway) knows(vrf uint32, vtep netip.Addr) bool {
	for _, r := range g.routes[vrf] {
		if r.NextHop == vtep.String() {
			return true
		}
		for _, v := range r.VTEPs {
			if v == vtep.String() {
				return true
			}
		}
	}
	return false
}

// count is the number of echo requests to the overlay node that came in the VRF vrf from the source src, in frames from the
// router MAC mac
func (g *irbGateway) count(vrf uint32, src netip.Addr, mac string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.asked[fmt.Sprintf("%d %s %s", vrf, src, mac)]
}

// report is what came to the overlay node and what the gateway did not take, for the log of a test that failed
func (g *irbGateway) report() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return fmt.Sprintf("echo requests %v; not taken %v", g.asked, g.dropped)
}

// serve takes the datagrams of the VTEP of the gateway until it closes: a frame of the L3 VNI of an EVPN VRF goes to input, and
// the frames of the L2 VNIs, the broadcasts of the leaf among them, are no concern of the test
func (g *irbGateway) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := g.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		b := buf[:n]
		if len(b) < 8 || b[0]&0x08 == 0 {
			continue
		}
		vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		for _, v := range irbVRFs {
			if v.vni == vni {
				g.input(v, from.Addr().Unmap(), b[8:])
			}
		}
	}
}

// input is a frame f of the L3 VNI of the VRF v from the address outer, which the gateway takes as the node takes one: from a
// VTEP that it knows for the VRF, to its router MAC, untagged with the EtherType of IPv4, and with a packet from a source that
// a route of the VRF holds. An echo request to the overlay node is counted and answered by the route of its source.
func (g *irbGateway) input(v irbVRF, outer netip.Addr, f []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.knows(v.id, outer) {
		g.dropped = append(g.dropped, fmt.Sprintf("a frame of VRF %d from %s, a VTEP that the gateway does not know for the VRF", v.id, outer))
		return
	}
	if len(f) < 14+20 || net.HardwareAddr(f[:6]).String() != DefaultRouterMAC || binary.BigEndian.Uint16(f[12:]) != etherIPv4 {
		g.dropped = append(g.dropped, fmt.Sprintf("a frame of VRF %d of %d bytes that is no IPv4 packet to the router MAC of the gateway", v.id, len(f)))
		return
	}
	ip := f[14:]
	hl := int(ip[0]&0x0F) * 4
	if ip[0]>>4 != 4 || hl < 20 || len(ip) < hl {
		g.dropped = append(g.dropped, fmt.Sprintf("a frame of VRF %d without an IPv4 packet", v.id))
		return
	}
	src, _ := netip.AddrFromSlice(ip[12:16])
	dst, _ := netip.AddrFromSlice(ip[16:20])
	back, ok := g.lookup(v.id, src)
	if !ok {
		g.dropped = append(g.dropped, fmt.Sprintf("a packet of VRF %d from %s, which no route of the VRF holds", v.id, src))
		return
	}
	if dst != irbOverlayNode || ip[9] != protocolICMP {
		return
	}
	m, err := icmp.ParseMessage(protocolICMP, ip[hl:])
	if err != nil || m.Type != ipv4.ICMPTypeEcho {
		return
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok {
		return
	}
	g.asked[fmt.Sprintf("%d %s %s", v.id, src, net.HardwareAddr(f[6:12]))]++

	// The overlay node answers with the data of the request, and the gateway sends the answer by the route of its destination
	reply, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: e.ID, Seq: e.Seq, Data: e.Data}}).Marshal(nil)
	if err != nil {
		return
	}
	packet := make([]byte, 20+len(reply))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocolICMP
	copy(packet[12:], irbOverlayNode.AsSlice())
	copy(packet[16:], src.AsSlice())
	binary.BigEndian.PutUint16(packet[10:], ipChecksum(packet[:20]))
	copy(packet[20:], reply)
	g.send(back, packet)
}

// send sends the IPv4 packet by the route r of the fabric, as the node sends one (NodeEvpnSend): behind an Ethernet header from
// the router MAC of the gateway to the router MAC of the route, untagged, on the VNI of the route, to its VTEP. The caller holds
// mu.
func (g *irbGateway) send(r Message, packet []byte) {
	dst, err := net.ParseMAC(r.RouterMAC)
	vtep, err2 := netip.ParseAddr(r.NextHop)
	if err != nil || err2 != nil {
		g.dropped = append(g.dropped, fmt.Sprintf("an answer by the route %+v, which has no router MAC or VTEP", r))
		return
	}
	src, _ := net.ParseMAC(DefaultRouterMAC)
	b := make([]byte, 8+14+len(packet))
	b[0] = 0x08
	b[4], b[5], b[6] = byte(r.VNI>>16), byte(r.VNI>>8), byte(r.VNI)
	copy(b[8:14], dst)
	copy(b[14:20], src)
	binary.BigEndian.PutUint16(b[20:22], etherIPv4)
	copy(b[22:], packet)
	if _, err := g.conn.WriteToUDPAddrPort(b, netip.AddrPortFrom(vtep.Unmap(), frrVTEPPort)); err != nil {
		g.dropped = append(g.dropped, fmt.Sprintf("an answer to %s: %v", vtep, err))
	}
}

// arpEntries are the addresses of the arp-cache of the L2 VNI vni of the leaf, the first field of each line that holds one
func arpEntries(f *frrRouter, vni uint32) (map[string]bool, bool) {
	out, ok := f.vtysh(fmt.Sprintf("show evpn arp-cache vni %d", vni))
	entries := make(map[string]bool)
	for _, l := range strings.Split(out, "\n") {
		if fields := strings.Fields(l); len(fields) != 0 {
			if _, err := netip.ParseAddr(fields[0]); err == nil {
				entries[fields[0]] = true
			}
		}
	}
	return entries, ok
}

// dumpIRB writes the state of the leaf and of the kernel of its container into the log of the test when it failed
func dumpIRB(f *frrRouter, g *irbGateway) {
	if !f.t.Failed() {
		return
	}
	f.t.Logf("the gateway: %s", g.report())
	for _, command := range []string{
		"show bgp summary",
		"show bgp l2vpn evpn route",
		"show evpn vni detail",
		"show evpn mac vni all",
		"show evpn arp-cache vni all",
		"show evpn rmac vni all",
		"show evpn next-hops vni all",
		"show bgp vrf all ipv4 unicast",
		"show ip route vrf all",
	} {
		if out, ok := f.vtysh(command); ok {
			f.t.Logf("%s: %s:\n%s", f.container, command, out)
		}
	}
	pid, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", f.container).Output()
	if err != nil {
		return
	}
	for _, args := range [][]string{{"ip", "neigh", "show"}, {"bridge", "fdb", "show"}, {"ip", "route", "show", "table", "1001"}, {"ip", "route", "show", "table", "1002"}} {
		out, _ := exec.Command("sudo", append([]string{"nsenter", "-t", strings.TrimSpace(string(pid)), "-n"}, args...)...).CombinedOutput()
		f.t.Logf("%s: %v:\n%s", f.container, args, out)
	}
}

// The gateway against a leaf of FRR with symmetric IRB, with two stretches with irb, one in each VRF, on the same Network
// addresses, and a stretch without irb.
//
// Into the fabric: the prefix of the overlay node reaches the VRF of the leaf that imports the route target of each EVPN VRF;
// a host of the overlay on the stretched Network of red reaches the leaf as a host route of red, through the L3 VNI of red and
// with the router MAC of the gateway, and is not in blue; the gateway IP of each stretch with irb is in the arp-cache of the
// leaf with the router MAC of the gateway and its VTEP. The stretch without irb announces no gateway IP or MAC of its Network:
// the leaf holds the host of the overlay on it and neither the router MAC nor a gateway IP, and no VRF of the leaf has a route
// of it.
//
// Out of the fabric: the host of the fabric of each VRF talks to its first hop, the leaf advertises its MAC and IP addresses,
// and the gateway takes them as a host route of its own VRF alone, with the L3 VNI and the router MAC of the VRF of the leaf.
//
// Both ways: the host of the fabric of each VRF pings the overlay node of another Network of its VRF. The leaf routes each echo
// request into the L3 VNI of its VRF, the gateway takes it in that VRF by the host route of its source, and the echo reply
// goes back on the same L3 VNI. The two hosts have the same address and stay apart: the requests of each come on the L3 VNI
// of its own VRF alone, from the router MAC of that VRF.
func TestFRRIRB(t *testing.T) {
	if os.Getenv("RANZ_FRR_IRB") == "" {
		t.Skip("RANZ_FRR_IRB is not set; the job EVPN with FRR of ranz.yml runs this test against the leaf of irb.sh")
	}
	leaf := &frrRouter{t: t, container: "ranz-irb-leaf"}
	if _, ok := leaf.vtysh("show version"); !ok {
		t.Fatalf("FRR in the container %s does not answer", leaf.container)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw := openIRBGateway(t)
	node := startNode(t, ctx)
	// The cleanups run last first: the state of the leaf goes into the log before the pipe of the node closes
	t.Cleanup(func() { dumpIRB(leaf, gw) })

	evpn := &EVPN{VTEP: irbGatewayAddr}
	for _, v := range irbVRFs {
		target := fmt.Sprintf("65000:%d", v.vni)
		evpn.VRFs = append(evpn.VRFs, EVPNVRF{VRF: v.id, VNI: v.vni, Import: []string{target}, Export: []string{target}, Accept: []string{"172.16.0.0/12"}})
		evpn.Stretches = append(evpn.Stretches, EVPNStretch{VNI: v.l2, RouteTargets: []string{fmt.Sprintf("65000:%d", v.l2)}, IRB: true, VRF: v.id,
			GatewayIPs: []string{irbGatewayIP + "/24"}})
	}
	evpn.Stretches = append(evpn.Stretches, EVPNStretch{VNI: irbPlainVNI, RouteTargets: []string{fmt.Sprintf("65000:%d", irbPlainVNI)}})
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      frrBGPPort,
		ListenAddresses: []string{irbGatewayAddr},
		Peers:           []Peer{{Address: irbLeafAddr, ASN: 65020, Passive: true}},
		EVPN:            evpn,
	})
	node.wait("ready", false, isType(TypeReady))
	node.wait("the leaf established", true, isPeer(irbLeafAddr, StateEstablished))

	// The overlay node of another Network of each VRF, and the hosts of the overlay on the stretched Network of red and on the
	// Network of the stretch without irb, MAC only and MAC plus IP
	for _, v := range irbVRFs {
		node.send(Message{Type: TypeAnnounce, VRF: v.id, Prefix: "10.60.0.0/24"})
	}
	node.resync([]StretchRoute{
		{VNI: irbVRFs[0].l2, MAC: irbOverlayMAC}, {VNI: irbVRFs[0].l2, MAC: irbOverlayMAC, IP: irbOverlayHost.String()},
		{VNI: irbPlainVNI, MAC: irbPlainMAC}, {VNI: irbPlainVNI, MAC: irbPlainMAC, IP: irbPlainHost.String()},
	})

	// Into the fabric: the prefix of the overlay node in each VRF of the leaf, and the host of the overlay of red, a host route of
	// red alone
	overlayHost := netip.PrefixFrom(irbOverlayHost, 32).String()
	waitUntil(t, "the leaf has 10.60.0.0/24 in red and in blue, and the host of the overlay of red in red", func() bool {
		red, blue := leaf.table("red", "ipv4"), leaf.table("blue", "ipv4")
		return red["10.60.0.0/24"] != nil && blue["10.60.0.0/24"] != nil && red[overlayHost] != nil
	})
	if leaf.table("blue", "ipv4")[overlayHost] != nil {
		t.Errorf("the leaf has %s, a host of the overlay on the stretched Network of red, in blue", overlayHost)
	}

	// The gateway IP of each stretch with irb, with the router MAC of the gateway behind its VTEP, which the leaf answers ARP with
	for _, v := range irbVRFs {
		waitUntil(t, fmt.Sprintf("the leaf holds the gateway IP of VNI %d", v.l2), func() bool {
			out, _ := leaf.vtysh(fmt.Sprintf("show evpn arp-cache vni %d ip %s", v.l2, irbGatewayIP))
			return strings.Contains(out, DefaultRouterMAC) && strings.Contains(out, irbGatewayAddr)
		})
	}

	// With irb off, no gateway IP or MAC of the Network: the leaf holds the host of the overlay of the stretch without irb, and
	// neither the router MAC nor a gateway IP on its VNI, nor a route of it in a VRF
	waitUntil(t, "the leaf holds the host of the overlay of the stretch without irb", func() bool {
		out, _ := leaf.vtysh(fmt.Sprintf("show evpn arp-cache vni %d ip %s", irbPlainVNI, irbPlainHost))
		return strings.Contains(out, irbPlainMAC) && strings.Contains(out, irbGatewayAddr)
	})
	time.Sleep(settleTime)
	if macs, ok := leaf.vtysh(fmt.Sprintf("show evpn mac vni %d", irbPlainVNI)); !ok || !strings.Contains(macs, irbPlainMAC) || strings.Contains(macs, DefaultRouterMAC) {
		t.Errorf("the MAC addresses of VNI %d at the leaf, which hold the host of the overlay and not the router MAC of the gateway:\n%s", irbPlainVNI, macs)
	}
	if arps, ok := arpEntries(leaf, irbPlainVNI); !ok || len(arps) != 1 || !arps[irbPlainHost.String()] {
		t.Errorf("the arp-cache of VNI %d at the leaf, which holds the host of the overlay alone: %v", irbPlainVNI, arps)
	}
	plainHost := netip.PrefixFrom(irbPlainHost, 32).String()
	for _, v := range irbVRFs {
		if leaf.table(v.name, "ipv4")[plainHost] != nil {
			t.Errorf("the leaf has %s, a host of the overlay of the stretch without irb, in %s", plainHost, v.name)
		}
	}

	// Out of the fabric: the host of each VRF talks to its first hop, and the gateway takes its MAC and IP addresses as a host route
	// of its own VRF, with the L3 VNI and the router MAC of the VRF of the leaf
	fabricHost := netip.PrefixFrom(irbFabricHost, 32).String()
	for _, v := range irbVRFs {
		if out, ok := hostRun(t, v.host, "ping", "-c", "1", "-W", "2", irbFirstHop); !ok {
			t.Errorf("the host of the fabric in %s does not reach its first hop:\n%s", v.name, out)
		}
		r := node.wait(fmt.Sprintf("the host route %s in VRF %d", fabricHost, v.id), true, isEVPNRoute(TypeLearned, v.id, fabricHost))
		if r.NextHop != irbLeafAddr || r.VNI != v.vni || r.RouterMAC != v.mac || r.Peer != irbLeafAddr {
			t.Errorf("the host route %s in VRF %d: %+v", fabricHost, v.id, r)
		}
	}
	node.drain()
	gw.take(node.seen)

	// Both ways through the L3 VNI of each VRF: the host of the fabric reaches the overlay node of another Network of its VRF
	for _, v := range irbVRFs {
		if out, ok := hostRun(t, v.host, "ping", "-c", "3", "-W", "2", irbOverlayNode.String()); !ok {
			t.Errorf("the host of the fabric in %s does not reach the overlay node through the L3 VNI; the gateway: %s\n%s", v.name, gw.report(), out)
		}
	}

	// The VRFs stay apart: the echo requests of each host came on the L3 VNI of its own VRF alone, from the router MAC of that VRF,
	// and each host route of the gateway has the VNI and the router MAC of its own VRF
	for _, v := range irbVRFs {
		for _, o := range irbVRFs {
			n := gw.count(v.id, irbFabricHost, o.mac)
			if o.id == v.id && n == 0 {
				t.Errorf("no echo request of the host of %s came in VRF %d", o.name, v.id)
			}
			if o.id != v.id && n != 0 {
				t.Errorf("%d echo requests of the host of %s came in VRF %d", n, o.name, v.id)
			}
		}
	}
	node.drain()
	for _, m := range node.seen {
		for _, v := range irbVRFs {
			if m.Type == TypeLearned && m.VRF == v.id && m.VNI != 0 && (m.VNI != v.vni || m.RouterMAC != v.mac) {
				t.Errorf("a route of VRF %d with the VNI or the router MAC of another VRF: %+v", v.id, m)
			}
		}
	}
}
