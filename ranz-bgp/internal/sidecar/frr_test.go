package sidecar

// The EVPN of a gateway against FRR, the reference BGP speaker of a data-centre fabric (SDN-25 #201; ADR-0032). The job
// "EVPN with FRR" of ranz.yml runs FRR in a container of its own on a bridge of the runner (testdata/frr/fabric.sh), which
// stands in for the second host (ADR-0002 amendment of 2026-10-21): one leaf of the fabric, whose VTEP is 172.31.25.10,
// with the VRFs red and blue of its kernel, which hand the same LAN to the gateway, each on its own L3 VNI and route
// target, through the VXLAN of the kernel. The job names the container in RANZ_FRR_CONTAINER; without it the test is
// skipped. The test is the gateway on the runner, 172.31.25.1: its sidecar, which FRR dials on port 1179, and its VTEP on
// UDP port 4789, whose frames the test makes and reads as the node does (NodeEvpnSend, NodeEvpnReceive and NodeEvpnParseFrame
// of src/Cedar/NodeEvpn.c, which vpntest evpn runs against a harness VTEP on Windows): it takes a frame of FRR only from the
// VTEP of the route, as the node takes one only from a VTEP that it knows for the VRF (SDN-25-R1 #549).

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// The addresses, the ports and the router MACs of fabric.sh and frr.conf
const (
	frrGatewayAddr = "172.31.25.1"
	frrFabricAddr  = "172.31.25.10"
	frrBGPPort     = 1179
	frrVTEPPort    = 4789
	frrRedMAC      = "02:00:5e:10:00:01"
	frrBlueMAC     = "02:00:5e:10:00:02"
)

// protocolICMP is the IP protocol number of ICMP for IPv4.
const protocolICMP = 1

// The host of the overlay behind the gateway, in the prefix 10.10.0.0/24 that the gateway announces in each VRF, and the
// host of the fabric on the LAN 172.16.1.0/24 of each VRF of FRR
var (
	frrOverlayHost = netip.MustParseAddr("10.10.0.1")
	frrFabricHost  = netip.MustParseAddr("172.16.1.1")
)

// frrVRF is an EVPN VRF of the gateway in the test, with the name, the L3 VNI and the router MAC of the VRF of FRR that
// imports and exports its route target.
type frrVRF struct {
	id   uint32
	name string
	vni  uint32
	mac  string
}

var frrVRFs = []frrVRF{
	{id: 101, name: "red", vni: 10101, mac: frrRedMAC},
	{id: 102, name: "blue", vni: 10102, mac: frrBlueMAC},
}

// frrRouter is FRR in its container.
type frrRouter struct {
	t         *testing.T
	container string
}

// vtysh runs command in the vtysh of FRR: what it wrote to its standard output, or false when it failed. What it writes
// to its standard error stays out of the output, which may be JSON.
func (f *frrRouter) vtysh(command string) (string, bool) {
	out, err := exec.Command("docker", "exec", f.container, "vtysh", "-c", command).Output()
	if err != nil {
		var exit *exec.ExitError
		var stderr []byte
		if errors.As(err, &exit) {
			stderr = exit.Stderr
		}
		f.t.Logf("vtysh -c %q: %v\n%s%s", command, err, out, stderr)
		return "", false
	}
	return string(out), true
}

// table is the BGP table of the address family family (ipv4 or ipv6) of the VRF vrf of FRR, by prefix; nil when vtysh
// did not show it.
func (f *frrRouter) table(vrf, family string) map[string]json.RawMessage {
	command := "show bgp vrf " + vrf + " " + family + " unicast json"
	out, ok := f.vtysh(command)
	if !ok {
		return nil
	}
	var shown struct {
		Routes map[string]json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.Routes == nil {
		f.t.Logf("%s: %v\n%s", command, err, out)
		return nil
	}
	return shown.Routes
}

// dump writes the state of FRR into the log of the test when it failed.
func (f *frrRouter) dump() {
	if !f.t.Failed() {
		return
	}
	for _, command := range []string{
		"show bgp summary",
		"show bgp l2vpn evpn route",
		"show evpn vni detail",
		"show evpn rmac vni all",
		"show evpn next-hops vni all",
		"show bgp vrf all ipv4 unicast",
		"show bgp vrf all ipv6 unicast",
		"show ip route vrf all",
	} {
		if out, ok := f.vtysh(command); ok {
			f.t.Logf("%s:\n%s", command, out)
		}
	}
}

// frrVTEP is the VTEP of the gateway on the runner.
type frrVTEP struct {
	t    *testing.T
	conn *net.UDPConn
}

func openVTEP(t *testing.T) *frrVTEP {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(frrGatewayAddr), frrVTEPPort)))
	if err != nil {
		t.Fatalf("the VTEP of the gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &frrVTEP{t: t, conn: conn}
}

// ipChecksum is the checksum of an IPv4 header whose checksum field is 0 (RFC 791, RFC 1071).
func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xFFFF {
		sum = sum>>16 + sum&0xFFFF
	}
	return ^uint16(sum)
}

// echoFrame is the VXLAN datagram of the ICMP echo request id and seq of the host of the overlay to the host of the
// fabric, on the VNI vni of an IP prefix route of the fabric, in the frame that the node sends (NodeEvpnSend): from the
// router MAC of the gateway to the router MAC mac of the route, untagged, with the EtherType of IPv4.
func echoFrame(t *testing.T, vni uint32, mac string, id, seq int) []byte {
	t.Helper()
	dst, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("router MAC %q: %v", mac, err)
	}
	src, err := net.ParseMAC(DefaultRouterMAC)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("ranz evpn")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8+14+20+len(msg))

	// VXLAN (RFC 7348): the I flag and the VNI; then the Ethernet header
	b[0] = 0x08
	b[4], b[5], b[6] = byte(vni>>16), byte(vni>>8), byte(vni)
	copy(b[8:14], dst)
	copy(b[14:20], src)
	binary.BigEndian.PutUint16(b[20:22], 0x0800)

	// IPv4 without options, TTL 64
	ip := b[22:42]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(msg)))
	ip[8] = 64
	ip[9] = protocolICMP
	copy(ip[12:16], frrOverlayHost.AsSlice())
	copy(ip[16:20], frrFabricHost.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	copy(b[42:], msg)
	return b
}

// echoReply reads the datagram b from the address outer as the answer of FRR to the echo request id and seq by the IP prefix
// route r of the fabric, as the node takes a frame of the fabric (NodeEvpnReceive, NodeEvpnParseFrame): from the VTEP of the
// route, its next hop, which is a VTEP that the gateway knows for the VRF, from any source port; on the VNI of the route, a
// frame from its router MAC to the router MAC of the gateway, untagged, with the EtherType of IPv4, and in it the echo reply
// of the host of the fabric to the host of the overlay. "" for that answer, else what b is.
func echoReply(b []byte, outer netip.Addr, r Message, id, seq int) string {
	vni, mac := r.VNI, r.RouterMAC
	if vtep, err := netip.ParseAddr(r.NextHop); err != nil || outer != vtep.Unmap() {
		return fmt.Sprintf("a datagram from %s, which is not the VTEP %q of the route", outer, r.NextHop)
	}
	if len(b) < 8+14+20 || b[0]&0x08 == 0 {
		return fmt.Sprintf("%d bytes of no VXLAN datagram", len(b))
	}
	if got := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]); got != vni {
		return fmt.Sprintf("a datagram on VNI %d", got)
	}
	dst, src, ether := net.HardwareAddr(b[8:14]).String(), net.HardwareAddr(b[14:20]).String(), binary.BigEndian.Uint16(b[20:22])
	if dst != DefaultRouterMAC || src != mac || ether != 0x0800 {
		return fmt.Sprintf("a frame from %s to %s with the EtherType %#04x", src, dst, ether)
	}
	ip := b[22:]
	hl := int(ip[0]&0x0F) * 4
	if ip[0]>>4 != 4 || hl < 20 || len(ip) < hl || ip[9] != protocolICMP {
		return "a frame without an ICMP packet of IPv4"
	}
	from, _ := netip.AddrFromSlice(ip[12:16])
	to, _ := netip.AddrFromSlice(ip[16:20])
	if from != frrFabricHost || to != frrOverlayHost {
		return fmt.Sprintf("an ICMP packet from %s to %s", from, to)
	}
	m, err := icmp.ParseMessage(protocolICMP, ip[hl:])
	if err != nil {
		return fmt.Sprintf("an ICMP packet that is none: %v", err)
	}
	echo, ok := m.Body.(*icmp.Echo)
	if m.Type != ipv4.ICMPTypeEchoReply || !ok || echo.ID != id || echo.Seq != seq {
		return fmt.Sprintf("ICMP %v, not the echo reply %d/%d", m.Type, id, seq)
	}
	return ""
}

// drain drops what came to the VTEP of the gateway and was not read, such as a late reply to an echo request sent again.
func (g *frrVTEP) drain() {
	g.t.Helper()
	buf := make([]byte, 2048)
	for {
		if err := g.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			g.t.Fatal(err)
		}
		if _, _, err := g.conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// exchange sends FRR the echo request seq of the VRF v by the route r of the fabric every second, until its echo reply
// comes back or timeout passes: whether it came, and what else came.
func (g *frrVTEP) exchange(v frrVRF, r Message, seq int, timeout time.Duration) (bool, []string) {
	g.t.Helper()
	g.drain()
	frame := echoFrame(g.t, r.VNI, r.RouterMAC, int(v.vni), seq)
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(r.NextHop), frrVTEPPort))
	buf := make([]byte, 2048)
	var others []string
	for end := time.Now().Add(timeout); time.Now().Before(end); {
		if _, err := g.conn.WriteToUDP(frame, to); err != nil {
			g.t.Fatalf("the echo request of VRF %d to %s: %v", v.id, to, err)
		}
		if err := g.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			g.t.Fatal(err)
		}
		for {
			n, outer, err := g.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			why := echoReply(buf[:n], outer.Addr().Unmap(), r, int(v.vni), seq)
			if why == "" {
				return true, others
			}
			others = append(others, why)
		}
	}
	return false, others
}

// The gateway against FRR: FRR has the prefixes of each EVPN VRF of the gateway in its VRF that imports their route
// target, the IPv4 prefix in red and in blue, where they overlap, and the IPv6 prefix in red alone; the gateway learns
// the LAN of each VRF of FRR in its own VRF, with the L3 VNI and the router MAC of the VRF of FRR and its VTEP. An ICMP
// echo request of the overlay to the LAN of the fabric, in the frame that the node sends on the L3 VNI of each VRF, is
// answered by the kernel of FRR in the frame that the node takes, on the same VNI and from the VTEP of FRR, the next hop of
// its routes, which the node checks the outer source of a frame against: the packets of each VRF go both ways through
// VXLAN. When the gateway withdraws its prefix of red, FRR loses it in red and keeps it in blue: red no longer answers, and
// blue still does.
func TestFRREVPN(t *testing.T) {
	container := os.Getenv("RANZ_FRR_CONTAINER")
	if container == "" {
		t.Skip("RANZ_FRR_CONTAINER names no container of FRR; the job EVPN with FRR of ranz.yml runs this test")
	}
	frr := &frrRouter{t: t, container: container}
	if _, ok := frr.vtysh("show version"); !ok {
		t.Fatalf("FRR in the container %s does not answer", container)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vtep := openVTEP(t)

	accept := []string{"172.16.0.0/12", "fd16::/48"}
	evpn := &EVPN{VTEP: frrGatewayAddr, VRFs: []EVPNVRF{
		{VRF: 101, VNI: 10101, Import: []string{"65000:10101"}, Export: []string{"65000:10101"}, Accept: accept},
		{VRF: 102, VNI: 10102, Import: []string{"65000:10102"}, Export: []string{"65000:10102"}, Accept: accept},
	}}
	node := startNode(t, ctx)
	// The cleanups run last first: the state of FRR goes into the log before the pipe of the node closes
	t.Cleanup(frr.dump)
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      frrBGPPort,
		ListenAddresses: []string{frrGatewayAddr},
		Peers:           []Peer{{Address: frrFabricAddr, ASN: 65010, Passive: true}},
		EVPN:            evpn,
	})
	node.wait("ready", false, isType(TypeReady))
	node.wait("FRR established", true, isPeer(frrFabricAddr, StateEstablished))

	// The LAN of each VRF of FRR comes to the gateway in its VRF, with the VNI and the router MAC of the VRF of FRR
	routes := make(map[uint32]Message)
	for _, v := range frrVRFs {
		r := node.wait("learned 172.16.1.0/24 in VRF "+v.name, true, isEVPNRoute(TypeLearned, v.id, "172.16.1.0/24"))
		if r.NextHop != frrFabricAddr || r.VNI != v.vni || r.RouterMAC != v.mac || r.Peer != frrFabricAddr {
			t.Errorf("learned 172.16.1.0/24 in VRF %d: %+v", v.id, r)
		}
		routes[v.id] = r
	}
	six := node.wait("learned fd16::/64 in VRF red", true, isEVPNRoute(TypeLearned, 101, "fd16::/64"))
	if six.NextHop != frrFabricAddr || six.VNI != 10101 || six.RouterMAC != frrRedMAC {
		t.Errorf("learned fd16::/64 in VRF 101: %+v", six)
	}

	// The prefixes of the gateway reach the VRFs of FRR: the IPv4 one in both, the IPv6 one in red alone
	node.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.10.0.0/24"})
	node.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "10.10.0.0/24"})
	node.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "fd10::/64"})
	waitUntil(t, "FRR has 10.10.0.0/24 in red and in blue, and fd10::/64 in red", func() bool {
		red, blue, red6 := frr.table("red", "ipv4"), frr.table("blue", "ipv4"), frr.table("red", "ipv6")
		return red["10.10.0.0/24"] != nil && blue["10.10.0.0/24"] != nil && red6["fd10::/64"] != nil
	})
	if frr.table("blue", "ipv6")["fd10::/64"] != nil {
		t.Error("FRR has fd10::/64 of red in blue")
	}
	node.drain()
	if c := node.count(isEVPNRoute(TypeLearned, 102, "fd16::/64")); c != 0 {
		t.Errorf("fd16::/64 of red came to VRF 102 %d times", c)
	}

	// Both ways through VXLAN in each VRF: the echo request of the overlay to the LAN of the fabric, and its reply
	for _, v := range frrVRFs {
		if ok, others := vtep.exchange(v, routes[v.id], 1, waitTimeout); !ok {
			t.Errorf("VRF %s: no echo reply on VNI %d from %s; what came: %v", v.name, v.vni, frrFabricAddr, others)
		}
	}

	// The gateway withdraws its prefix of red: FRR keeps it in blue, and blue alone still answers
	node.send(Message{Type: TypeWithdraw, VRF: 101, Prefix: "10.10.0.0/24"})
	waitUntil(t, "FRR loses 10.10.0.0/24 in red and keeps it in blue", func() bool {
		red, blue := frr.table("red", "ipv4"), frr.table("blue", "ipv4")
		return red != nil && red["10.10.0.0/24"] == nil && blue["10.10.0.0/24"] != nil
	})
	time.Sleep(settleTime)
	if ok, others := vtep.exchange(frrVRFs[0], routes[101], 2, 3*time.Second); ok || len(others) != 0 {
		t.Errorf("VRF red answered after the gateway withdrew 10.10.0.0/24 of it: %v, %v", ok, others)
	}
	if ok, others := vtep.exchange(frrVRFs[1], routes[102], 2, waitTimeout); !ok {
		t.Errorf("VRF blue no longer answers after the gateway withdrew 10.10.0.0/24 of red; what came: %v", others)
	}
}
