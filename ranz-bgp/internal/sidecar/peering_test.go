package sidecar

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// peeringASN is the AS of the Ranz nodes in the tests of the peering of the standard mode.
const peeringASN = 4200000000

// peeringHoldTime is the hold time of their sessions in seconds.
const peeringHoldTime = 9

// peeringStart is the start message of the Ranz node at addr with the router id id, which listens on
// port, with its peers.
func peeringStart(id, addr string, port int, peers ...Peer) Message {
	return Message{Type: TypeStart, ASN: peeringASN, RouterID: id, ListenPort: int32(port), Address: addr, Peers: peers}
}

// peeringPeer is the Ranz node at addr, which listens on port and shares vrfs with the node.
func peeringPeer(addr string, port int, vrfs ...PeerVRF) Peer {
	return Peer{Address: addr, ASN: peeringASN, Port: uint32(port), HoldTime: peeringHoldTime, VRFs: vrfs}
}

func isVRFRoute(typ string, vrf uint32, prefix string) func(Message) bool {
	return func(m Message) bool { return m.Type == typ && m.VRF == vrf && m.Prefix == prefix }
}

func isRefused(addr string) func(Message) bool {
	return func(m Message) bool { return m.Type == TypeRefused && m.Peer == addr }
}

// Two Ranz nodes, a at 127.0.0.2 and b at 127.0.0.3, share the VRFs 101 and 102 and peer on one
// session. Each learns what the other announces in a VRF that the two share and that the other may
// announce there, in that VRF only, with the other's address as the next hop; the same prefix in
// another VRF stays apart, and a prefix that the other may not announce, or one of a VRF that the
// two do not share, is never learned. A withdraw is withdrawn at the other node; a peers message
// without the peer ends the session and withdraws the routes of both ends, and the peer back brings
// them back. A session from an address that no peer has is refused and reported. When a node stops,
// the other withdraws its routes within the hold time.
func TestPeering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	// What a takes from b, and b from a: their addresses and LANs
	fromB := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.3/32", "fd00::3/128", "192.168.20.0/24"}}, {ID: 102, Accept: []string{"192.168.10.0/24"}}}
	fromA := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.2/32", "fd00::2/128", "192.168.10.0/24"}}, {ID: 102, Accept: []string{"192.168.30.0/24"}}}
	a := startNode(t, ctx)
	b := startNode(t, ctx)
	a.send(peeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, fromB...)))
	b.send(peeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, fromA...)))
	for _, n := range []*testNode{a, b} {
		if ready := n.wait("ready", false, isType(TypeReady)); ready.Protocol != ProtocolVersion {
			t.Errorf("ready: protocol %d, want %d", ready.Protocol, ProtocolVersion)
		}
	}
	a.wait("a established with b", true, isPeer("127.0.0.3", StateEstablished))
	b.wait("b established with a", true, isPeer("127.0.0.2", StateEstablished))

	// a announces its addresses and its LAN 192.168.10.0/24 in VRF 101. b announces the same LAN
	// prefix in VRF 102, then a prefix outside what a takes from it, a prefix of VRF 103, which the
	// two do not share, and last its LAN 192.168.20.0/24 in VRF 101.
	for _, m := range []Message{
		{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.2/32"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "fd00::2/128"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.10.0/24"},
	} {
		a.send(m)
	}
	for _, m := range []Message{
		{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.10.0/24"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.99.0/24"},
		{Type: TypeAnnounce, VRF: 103, Prefix: "192.168.20.0/24"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.20.0/24"},
	} {
		b.send(m)
	}

	for _, prefix := range []string{"10.0.0.2/32", "fd00::2/128", "192.168.10.0/24"} {
		l := b.wait("b learns "+prefix+" in VRF 101", true, isVRFRoute(TypeLearned, 101, prefix))
		if l.NextHop != "127.0.0.2" || l.Peer != "127.0.0.2" {
			t.Errorf("b learns %s in VRF 101 via %q from %q, want via 127.0.0.2 from 127.0.0.2", prefix, l.NextHop, l.Peer)
		}
	}
	l := a.wait("a learns 192.168.10.0/24 in VRF 102", true, isVRFRoute(TypeLearned, 102, "192.168.10.0/24"))
	if l.NextHop != "127.0.0.3" || l.Peer != "127.0.0.3" {
		t.Errorf("a learns 192.168.10.0/24 in VRF 102 via %q from %q, want via 127.0.0.3 from 127.0.0.3", l.NextHop, l.Peer)
	}
	// The LAN of b in 101 comes after the routes that a may not take, which so had their chance
	a.wait("a learns 192.168.20.0/24 in VRF 101", true, isVRFRoute(TypeLearned, 101, "192.168.20.0/24"))
	time.Sleep(settleTime)
	a.drain()
	b.drain()
	if c := a.count(isVRFRoute(TypeLearned, 101, "192.168.10.0/24")); c != 0 {
		t.Errorf("a learned 192.168.10.0/24 in VRF 101, where it is its own LAN, %d times: the route of b in VRF 102 crossed", c)
	}
	if c := b.count(isVRFRoute(TypeLearned, 102, "192.168.10.0/24")); c != 0 {
		t.Errorf("b learned 192.168.10.0/24 in VRF 102, where it is its own LAN, %d times: the route of a in VRF 101 crossed", c)
	}
	if c := a.count(isRoute(TypeLearned, "192.168.99.0/24")); c != 0 {
		t.Errorf("a learned 192.168.99.0/24, which b may not announce, %d times", c)
	}
	if c := a.count(isVRFRoute(TypeLearned, 103, "192.168.20.0/24")); c != 0 {
		t.Errorf("a learned 192.168.20.0/24 in VRF 103, which it does not share with b, %d times", c)
	}

	// A withdraw of a is withdrawn at b
	a.send(Message{Type: TypeWithdraw, VRF: 101, Prefix: "192.168.10.0/24"})
	if w := b.wait("b: 192.168.10.0/24 of VRF 101 withdrawn", false, isVRFRoute(TypeWithdrawn, 101, "192.168.10.0/24")); w.Peer != "127.0.0.2" {
		t.Errorf("192.168.10.0/24 of VRF 101 withdrawn from %q, want 127.0.0.2", w.Peer)
	}

	// A session from 127.0.0.9, an address that no peer of a has, is refused and reported
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9")}, Timeout: waitTimeout}
	conn, err := d.Dial("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("a session from 127.0.0.9: %v", err)
	}
	a.wait("a refuses the session from 127.0.0.9", false, isRefused("127.0.0.9"))
	conn.Close()

	// What the node cannot apply is answered with an error; the sessions go on
	for _, m := range []Message{
		{Type: TypeAnnounce, Prefix: "10.0.0.2/32"},
		{Type: TypeWithdraw, VRF: 101, Prefix: "10.9.0.0/16"},
		{Type: TypePeers, Peers: []Peer{{Address: "127.0.0.4", ASN: peeringASN}}},
		{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", port, fromB...), peeringPeer("127.0.0.3", port, fromB...)}},
	} {
		a.send(m)
		if e := a.wait("an error for "+m.Type, false, isType(TypeError)); e.Error == "" {
			t.Errorf("%+v: an error message without the error", m)
		}
	}

	// Without b in its peers, a ends the session: each end withdraws the routes of the other
	a.send(Message{Type: TypePeers})
	a.wait("a: 192.168.20.0/24 of VRF 101 withdrawn without b", false, isVRFRoute(TypeWithdrawn, 101, "192.168.20.0/24"))
	b.wait("b: 10.0.0.2/32 of VRF 101 withdrawn without a", false, isVRFRoute(TypeWithdrawn, 101, "10.0.0.2/32"))

	// b back in the peers of a brings the routes back
	a.send(Message{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", port, fromB...)}})
	a.wait("a learns 192.168.20.0/24 of VRF 101 again", false, isVRFRoute(TypeLearned, 101, "192.168.20.0/24"))
	b.wait("b learns 10.0.0.2/32 of VRF 101 again", false, isVRFRoute(TypeLearned, 101, "10.0.0.2/32"))

	// b stops: a withdraws its routes within the hold time
	stopped := time.Now()
	b.conn.Close()
	a.wait("a: 192.168.20.0/24 of VRF 101 withdrawn when b stops", false, isVRFRoute(TypeWithdrawn, 101, "192.168.20.0/24"))
	if took := time.Since(stopped); took > peeringHoldTime*time.Second {
		t.Errorf("a withdrew the routes of b %v after b stopped, after the hold time of %d s", took, peeringHoldTime)
	}
}

// A start of the peering of the standard mode that is not complete ends the session with an error.
func TestPeeringBadStart(t *testing.T) {
	good := peeringPeer("127.0.0.3", 1790, PeerVRF{ID: 101})
	start := func(addr string, peers ...Peer) Message {
		return Message{Type: TypeStart, ASN: peeringASN, RouterID: "192.0.2.2", Address: addr, Peers: peers}
	}
	withListen := start("127.0.0.2", good)
	withListen.ListenAddresses = []string{"127.0.0.2"}
	withAccept := start("127.0.0.2", good)
	withAccept.Accept = []string{"10.0.0.0/8"}
	cases := []Message{
		start("not-an-address", good),
		start("0.0.0.0", good),
		withListen,
		withAccept,
		start("127.0.0.2", Peer{Address: "127.0.0.3", ASN: peeringASN}),
		start("127.0.0.2", Peer{Address: "::3", ASN: peeringASN, VRFs: []PeerVRF{{ID: 101}}}),
		start("127.0.0.2", Peer{Address: "127.0.0.2", ASN: peeringASN, VRFs: []PeerVRF{{ID: 101}}}),
		start("127.0.0.2", Peer{Address: "127.0.0.3", ASN: peeringASN, HoldTime: 2, VRFs: []PeerVRF{{ID: 101}}}),
		start("127.0.0.2", Peer{Address: "127.0.0.3", ASN: peeringASN, VRFs: []PeerVRF{{ID: 0}}}),
		start("127.0.0.2", Peer{Address: "127.0.0.3", ASN: peeringASN, VRFs: []PeerVRF{{ID: 101}, {ID: 101}}}),
		start("127.0.0.2", Peer{Address: "127.0.0.3", ASN: peeringASN, VRFs: []PeerVRF{{ID: 101, Accept: []string{"10.0.0.1/8"}}}}),
		start("127.0.0.2", good, good),
		{Type: TypeStart, ASN: 65001, RouterID: "192.0.2.1", Peers: []Peer{{Address: "127.0.0.3", ASN: 65002, VRFs: []PeerVRF{{ID: 101}}}}},
	}
	for _, m := range cases {
		node := startNode(t, context.Background())
		node.send(m)
		if e := node.wait("an error for a bad start", false, isType(TypeError)); e.Error == "" {
			t.Errorf("%+v: an error message without the error", m)
		}
		select {
		case err := <-node.done:
			if err == nil {
				t.Errorf("%+v: the session ended without an error", m)
			}
		case <-time.After(waitTimeout):
			t.Fatalf("%+v: the session did not end", m)
		}
	}
}

// A sidecar that peers with the routers of the operator takes neither a VRF nor a peers message.
func TestPeeringNeedsAnAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startNode(t, ctx)
	node.send(Message{
		Type:       TypeStart,
		ASN:        65001,
		RouterID:   "192.0.2.1",
		ListenPort: -1,
		Peers:      []Peer{{Address: "127.0.0.1", ASN: 65002, Passive: true}},
	})
	node.wait("ready", false, isType(TypeReady))
	for _, m := range []Message{
		{Type: TypeAnnounce, VRF: 101, Prefix: "203.0.113.0/24"},
		{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", 179, PeerVRF{ID: 101})}},
	} {
		node.send(m)
		if e := node.wait("an error for "+m.Type, false, isType(TypeError)); e.Error == "" {
			t.Errorf("%+v: an error message without the error", m)
		}
	}
}
