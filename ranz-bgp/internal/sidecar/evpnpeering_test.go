package sidecar

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The EVPN of the tests of the peering of the standard mode (SDN-78 #358): VRF 101 peers by EVPN with the L3 VNI 10101 and the
// L2 Network of the L2 VNI 5010 in it, and VRF 102 peers by BGP
const (
	testPeeringL3VNI = 10101
	testPeeringL2VNI = 5010
)

// evpnPeeringStart is the start of the Ranz node at addr with the router id id, which listens on port, with the EVPN of VRF 101
// and of its L2 Network, as the node writes it: its VTEP at its address, the route distinguishers of the router id, the route
// targets of the VRF id and of the L2 VNI, and no accept list.
func evpnPeeringStart(id, addr string, port int, peers ...Peer) Message {
	m := peeringStart(id, addr, port, peers...)
	m.EVPN = &EVPN{
		VTEP:      addr,
		VRFs:      []EVPNVRF{{VRF: 101, VNI: testPeeringL3VNI, RD: id + ":1", Import: []string{"0:101"}, Export: []string{"0:101"}}},
		Stretches: []EVPNStretch{{VNI: testPeeringL2VNI, RD: id + ":17", RouteTargets: []string{"1:5010"}}},
	}
	return m
}

func isMoved(mac, via string) func(Message) bool {
	return func(m Message) bool {
		if m.Type != TypeStretch {
			return false
		}
		return slices.ContainsFunc(m.Routes, func(r StretchRoute) bool { return r.MAC == mac && r.NextHop == via && r.Moved && !r.Withdraw })
	}
}

// Two Ranz nodes, a at 127.0.0.2 and b at 127.0.0.3, peer by EVPN in VRF 101 and by BGP in VRF 102, over one session. Each learns
// the type-3 route of the other on the L2 VNI, which is its flood list; a MAC of a is a type-2 route at b, MAC only and MAC plus
// IP, with the VTEP of a; and a prefix that a may announce in VRF 101 is an IP prefix route at b with the L3 VNI of the VRF, while
// one that it may not announce is never learned. The prefix of VRF 102 goes as a VPN route. When b announces the MAC of a, the
// MAC moves: a hears it with moved, GoBGP of a withdraws the routes of a, and b no longer has them; a withdraws them without an
// error, and the MAC moving back is heard by b. A session from an address that no peer has is refused.
func TestEVPNPeering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	fromB := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.3/32", "192.168.20.0/24"}}, {ID: 102, Accept: []string{"192.168.40.0/24"}}}
	fromA := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.2/32", "192.168.10.0/24"}}, {ID: 102, Accept: []string{"192.168.30.0/24"}}}
	a := startNode(t, ctx)
	b := startNode(t, ctx)
	a.send(evpnPeeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, fromB...)))
	b.send(evpnPeeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, fromA...)))
	for _, n := range []*testNode{a, b} {
		if ready := n.wait("ready", false, isType(TypeReady)); ready.Protocol != ProtocolVersion {
			t.Errorf("ready: protocol %d, want %d", ready.Protocol, ProtocolVersion)
		}
	}
	a.wait("a established with b", true, isPeer("127.0.0.3", StateEstablished))
	b.wait("b established with a", true, isPeer("127.0.0.2", StateEstablished))

	// The type-3 route of each on the L2 VNI: the flood list of the other
	waitUntil(t, "a has the type-3 route of b", func() bool { return a.learnedStretch()["5010 vtep 127.0.0.3"] == "127.0.0.3" })
	waitUntil(t, "b has the type-3 route of a", func() bool { return b.learnedStretch()["5010 vtep 127.0.0.2"] == "127.0.0.2" })

	// IP prefix routes in VRF 101, and a VPN route in VRF 102
	for _, prefix := range []string{"10.0.0.2/32", "192.168.10.0/24", "192.168.99.0/24"} {
		a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: prefix})
	}
	b.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.40.0/24"})
	for _, prefix := range []string{"10.0.0.2/32", "192.168.10.0/24"} {
		l := b.wait("b learns "+prefix+" of VRF 101", true, isEVPNRoute(TypeLearned, 101, prefix))
		if l.VNI != testPeeringL3VNI || l.NextHop != "127.0.0.2" || l.RouterMAC != DefaultRouterMAC || l.Peer != "127.0.0.2" || !slices.Equal(l.VTEPs, []string{"127.0.0.2"}) {
			t.Errorf("b learns %s of VRF 101: %+v, want the IP prefix route of the VTEP 127.0.0.2 with the L3 VNI %d", prefix, l, testPeeringL3VNI)
		}
	}
	if l := a.wait("a learns 192.168.40.0/24 of VRF 102", true, isVRFRoute(TypeLearned, 102, "192.168.40.0/24")); l.VNI != 0 || l.NextHop != "127.0.0.3" {
		t.Errorf("a learns 192.168.40.0/24 of VRF 102: %+v, want a VPN route via 127.0.0.3", l)
	}
	time.Sleep(settleTime)
	b.drain()
	if c := b.count(isRoute(TypeLearned, "192.168.99.0/24")); c != 0 {
		t.Errorf("b learned 192.168.99.0/24, which a may not announce in VRF 101, %d times", c)
	}

	// A MAC of a, MAC only and MAC plus IP
	mac := testMAC(false, 1)
	a.send(Message{Type: TypeStretch, Full: true, Routes: []StretchRoute{{VNI: testPeeringL2VNI, MAC: mac}, {VNI: testPeeringL2VNI, MAC: mac, IP: "10.50.0.1"}}})
	waitUntil(t, "b has the type-2 routes of the MAC of a", func() bool {
		got := b.learnedStretch()
		return got["5010 "+mac+" "] == "127.0.0.2" && got["5010 "+mac+" 10.50.0.1"] == "127.0.0.2"
	})

	// The MAC moves to b: a hears it with moved and withdraws its routes of it, which GoBGP of a may have withdrawn already, without
	// an error, and b no longer has them
	before := a.count(isType(TypeError))
	b.send(Message{Type: TypeStretch, Full: true, Routes: []StretchRoute{{VNI: testPeeringL2VNI, MAC: mac}}})
	a.wait("a hears that its MAC moved to b", false, isMoved(mac, "127.0.0.3"))
	a.send(Message{Type: TypeStretch, Routes: []StretchRoute{{VNI: testPeeringL2VNI, MAC: mac, Withdraw: true}, {VNI: testPeeringL2VNI, MAC: mac, IP: "10.50.0.1", Withdraw: true}}})
	waitUntil(t, "b no longer has the type-2 routes of a", func() bool {
		got := b.learnedStretch()
		_, only := got["5010 "+mac+" "]
		_, both := got["5010 "+mac+" 10.50.0.1"]
		return !only && !both
	})

	// ... and back to a: b hears it
	a.send(Message{Type: TypeStretch, Routes: []StretchRoute{{VNI: testPeeringL2VNI, MAC: mac}}})
	b.wait("b hears that its MAC moved to a", false, isMoved(mac, "127.0.0.2"))
	time.Sleep(settleTime)
	a.drain()
	if c := a.count(isType(TypeError)); c != before {
		t.Errorf("a answered %d errors to the withdraws of the routes of a MAC that moved: %+v", c-before, a.seen)
	}

	// A session from 127.0.0.9, an address that no peer of a has, is refused and reported
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9")}, Timeout: waitTimeout}
	conn, err := d.Dial("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("a session from 127.0.0.9: %v", err)
	}
	a.wait("a refuses the session from 127.0.0.9", false, isRefused("127.0.0.9"))
	conn.Close()
}

// A start of the peering whose evpn has its VTEP elsewhere than the address of the node, or an accept list in a VRF, ends the
// session with an error; an announce of a VRF that peers by EVPN goes as an IP prefix route and one of another VRF as a VPN route.
func TestEVPNPeeringStart(t *testing.T) {
	elsewhere := evpnPeeringStart("192.0.2.2", "127.0.0.2", 1790)
	elsewhere.EVPN.VTEP = "127.0.0.5"
	accept := evpnPeeringStart("192.0.2.2", "127.0.0.2", 1790)
	accept.EVPN.VRFs[0].Accept = []string{"10.0.0.0/8"}
	for _, c := range []struct {
		name  string
		start Message
		want  string
	}{
		{"a VTEP elsewhere", elsewhere, "VTEP of the node is that address"},
		{"an accept list", accept, "names no accept list"},
	} {
		ev, err := parseEVPN(c.start.EVPN, netip.MustParseAddr("192.0.2.2"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := peeringEVPN(ev, netip.MustParseAddr("127.0.0.2")); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.want)
		}
		if err := peeringEVPN(ev, netip.Addr{}); err != nil {
			t.Errorf("%s at a gateway: %v", c.name, err)
		}
	}

	ev, err := parseEVPN(evpnPeeringStart("192.0.2.2", "127.0.0.2", 1790).EVPN, netip.MustParseAddr("192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	peering := &session{evpn: ev, address: netip.MustParseAddr("127.0.0.2")}
	gateway := &session{evpn: ev}
	none := &session{address: netip.MustParseAddr("127.0.0.2")}
	if !peering.evpnRoute(101) || peering.evpnRoute(102) || peering.evpnRoute(0) || !gateway.evpnRoute(102) || none.evpnRoute(101) {
		t.Errorf("the routes of the VRFs: 101 and 102 at a node of the peering %v %v, 102 at a gateway %v, 101 without EVPN %v", peering.evpnRoute(101),
			peering.evpnRoute(102), gateway.evpnRoute(102), none.evpnRoute(101))
	}
	if p := peering.importPolicies("ranz-peering-import-1"); len(p) != 2 || p[1].Name != evpnImportPolicy {
		t.Errorf("the import policies of a node of the peering with EVPN: %v", p)
	}
	if p := none.importPolicies("ranz-peering-import-1"); len(p) != 1 {
		t.Errorf("the import policies of a node of the peering without EVPN: %v", p)
	}

	// A MAC of a VNI that a peer announces with a higher sequence number than the node moved away; one with a lower or the same did not
	st := &stretchState{own: map[macKey]map[string]int64{{vni: 5010, mac: "02:52:5a:64:00:01"}: {"a": 1, "b": 0}}}
	if seq, ok := st.ownSeq(macKey{vni: 5010, mac: "02:52:5a:64:00:01"}); !ok || seq != 1 {
		t.Errorf("the sequence number of the routes of the node: %d %v, want 1", seq, ok)
	}
	if _, ok := st.ownSeq(macKey{vni: 5010, mac: "02:52:5a:64:00:02"}); ok {
		t.Error("a MAC that the node does not announce has a sequence number")
	}
	routes := st.markMoved([]StretchRoute{{VNI: 5010, MAC: "02:52:5a:64:00:01", NextHop: "127.0.0.3"}, {VNI: 5010, NextHop: "127.0.0.3"}}, map[macKey]bool{{vni: 5010, mac: "02:52:5a:64:00:01"}: true})
	if len(routes) != 2 || !routes[0].Moved || routes[1].Moved {
		t.Errorf("the routes marked moved: %+v", routes)
	}
	if routes := st.markMoved(nil, nil); routes != nil {
		t.Errorf("no move marks %+v", routes)
	}
}
