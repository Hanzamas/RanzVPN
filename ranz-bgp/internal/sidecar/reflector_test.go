package sidecar

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rrVRF is a VRF that a node shares with a peer, the role of the peer there and what the peer may
// announce there.
func rrVRF(id uint32, role string, accept ...string) PeerVRF {
	return PeerVRF{ID: id, Role: role, Accept: accept}
}

// isLearnedVia matches the learned message of prefix of vrf via the next hop via, from peer.
func isLearnedVia(vrf uint32, prefix, via, peer string) func(Message) bool {
	return func(m Message) bool {
		return m.Type == TypeLearned && m.VRF == vrf && m.Prefix == prefix && m.NextHop == via && m.Peer == peer
	}
}

// vpnPathsFrom is the number of paths of prefix of vrf from peer in the global RIB of the sidecar, the
// best paths and the others. It is for after ready.
func (n *testNode) vpnPathsFrom(peer string, vrf uint32, prefix string) int {
	n.t.Helper()
	if n.bgp == nil {
		n.bgp = <-n.started
	}
	want := netip.MustParsePrefix(prefix)
	family := bgp.RF_IPv4_VPN
	if want.Addr().Is6() {
		family = bgp.RF_IPv6_VPN
	}
	count := 0
	err := n.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, p := range paths {
			if key, ok := pathKey(p); ok && key.vrf == vrf && key.prefix == want && p.PeerAddress.String() == peer {
				count++
			}
		}
	})
	if err != nil {
		n.t.Fatalf("sidecar RIB: %v", err)
	}
	return count
}

// One route reflector r (127.0.0.2) and three clients a (127.0.0.3), b (127.0.0.4) and c (127.0.0.5)
// (SDN-79 #359). All four are in VRF 101 (red), and r, b and c in VRF 102 (blue); 192.168.1.0/24 is the
// LAN of a in red and the LAN of c in blue. Every client learns the routes of the others through r, each
// via the client that announced it, and has a session with r alone: a session from the address of another
// client is refused, as is one from an address that no peer has. The routes stay in their VRFs: a, in no
// VRF blue, gets no path of blue from r, and b takes the LAN of a in red and the LAN of c in blue. A client
// does not take its own route back. A hostile a announces its LAN in blue and a prefix outside its accept
// list: r copies neither, and the route of c in blue stays where it was.
func TestReflector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	r := startNode(t, ctx)
	a := startNode(t, ctx)
	b := startNode(t, ctx)
	c := startNode(t, ctx)
	clients := map[string]*testNode{"127.0.0.3": a, "127.0.0.4": b, "127.0.0.5": c}
	r.send(peeringStart("192.0.2.2", "127.0.0.2", port))
	a.send(peeringStart("192.0.2.3", "127.0.0.3", port))
	b.send(peeringStart("192.0.2.4", "127.0.0.4", port))
	c.send(peeringStart("192.0.2.5", "127.0.0.5", port))
	for _, n := range []*testNode{r, a, b, c} {
		n.wait("ready", false, isType(TypeReady))
	}

	// What each node may announce, in red and in blue
	ofR := []string{"10.0.0.1/32"}
	ofA := []string{"192.168.1.0/24"}
	ofBRed, ofBBlue := []string{"192.168.2.0/24"}, []string{"192.168.4.0/24"}
	ofCRed, ofCBlue := []string{"192.168.3.0/24"}, []string{"192.168.1.0/24"}
	r.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.3", port, rrVRF(101, RoleClient, ofA...)),
		peeringPeer("127.0.0.4", port, rrVRF(101, RoleClient, ofBRed...), rrVRF(102, RoleClient, ofBBlue...)),
		peeringPeer("127.0.0.5", port, rrVRF(101, RoleClient, ofCRed...), rrVRF(102, RoleClient, ofCBlue...)),
	}})
	a.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.2", port, rrVRF(101, RoleReflector, ofR...)),
		peeringPeer("127.0.0.4", port, rrVRF(101, RoleReflected, ofBRed...)),
		peeringPeer("127.0.0.5", port, rrVRF(101, RoleReflected, ofCRed...)),
	}})
	b.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.2", port, rrVRF(101, RoleReflector, ofR...), rrVRF(102, RoleReflector)),
		peeringPeer("127.0.0.3", port, rrVRF(101, RoleReflected, ofA...)),
		peeringPeer("127.0.0.5", port, rrVRF(101, RoleReflected, ofCRed...), rrVRF(102, RoleReflected, ofCBlue...)),
	}})
	c.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.2", port, rrVRF(101, RoleReflector, ofR...), rrVRF(102, RoleReflector)),
		peeringPeer("127.0.0.3", port, rrVRF(101, RoleReflected, ofA...)),
		peeringPeer("127.0.0.4", port, rrVRF(101, RoleReflected, ofBRed...), rrVRF(102, RoleReflected, ofBBlue...)),
	}})
	for addr, n := range clients {
		r.wait("r established with "+addr, true, isPeer(addr, StateEstablished))
		n.wait(addr+" established with r", true, isPeer("127.0.0.2", StateEstablished))
	}

	r.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.1/32"})
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.1.0/24"})
	b.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.2.0/24"})
	b.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.4.0/24"})
	c.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.3.0/24"})
	c.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.1.0/24"})

	// Each client learns from r what the others announce, via them, and the address of r via r
	for _, w := range []struct {
		node        *testNode
		name        string
		vrf         uint32
		prefix, via string
	}{
		{a, "a", 101, "192.168.2.0/24", "127.0.0.4"},
		{a, "a", 101, "192.168.3.0/24", "127.0.0.5"},
		{a, "a", 101, "10.0.0.1/32", "127.0.0.2"},
		{b, "b", 101, "192.168.1.0/24", "127.0.0.3"},
		{b, "b", 101, "192.168.3.0/24", "127.0.0.5"},
		{b, "b", 102, "192.168.1.0/24", "127.0.0.5"},
		{b, "b", 101, "10.0.0.1/32", "127.0.0.2"},
		{c, "c", 101, "192.168.1.0/24", "127.0.0.3"},
		{c, "c", 101, "192.168.2.0/24", "127.0.0.4"},
		{c, "c", 102, "192.168.4.0/24", "127.0.0.4"},
		{c, "c", 101, "10.0.0.1/32", "127.0.0.2"},
	} {
		w.node.wait(fmt.Sprintf("%s learns %s of VRF %d via %s from r", w.name, w.prefix, w.vrf, w.via), true, isLearnedVia(w.vrf, w.prefix, w.via, "127.0.0.2"))
	}
	// ... and r learns each from the client itself
	r.wait("r learns 192.168.1.0/24 of red from a", true, isLearnedVia(101, "192.168.1.0/24", "127.0.0.3", "127.0.0.3"))
	r.wait("r learns 192.168.1.0/24 of blue from c", true, isLearnedVia(102, "192.168.1.0/24", "127.0.0.5", "127.0.0.5"))
	r.wait("r learns 192.168.4.0/24 of blue from b", true, isLearnedVia(102, "192.168.4.0/24", "127.0.0.4", "127.0.0.4"))

	time.Sleep(settleTime)
	for _, n := range []*testNode{r, a, b, c} {
		n.drain()
	}
	for addr, n := range clients {
		if k := n.count(func(m Message) bool { return m.Type == TypePeer && m.Peer != "127.0.0.2" }); k != 0 {
			t.Errorf("client %s named the state of a session with another client %d times", addr, k)
		}
	}
	if k := a.count(func(m Message) bool { return m.Type == TypeLearned && m.VRF == 102 }); k != 0 {
		t.Errorf("a, in no VRF blue, learned %d routes of blue", k)
	}
	for _, p := range []string{"192.168.1.0/24", "192.168.4.0/24"} {
		if n := a.vpnPathsFrom("127.0.0.2", 102, p); n != 0 {
			t.Errorf("r sent a, which is no client of it in blue, %d paths of %s of blue", n, p)
		}
	}
	if k := b.count(func(m Message) bool {
		return m.Type == TypeLearned && m.Prefix == "192.168.1.0/24" && (m.VRF == 101) != (m.NextHop == "127.0.0.3")
	}); k != 0 {
		t.Errorf("b learned 192.168.1.0/24 of one VRF via the node of the other %d times: a route crossed into another VRF", k)
	}
	// The copy of r names a as the originator, so a takes its own route back from r not at all
	if n := a.vpnPathsFrom("127.0.0.2", 101, "192.168.1.0/24"); n != 0 {
		t.Errorf("a holds %d paths of its own LAN from r", n)
	}

	// A hostile a announces its LAN in blue, where it is the LAN of c, and a prefix outside its accept list
	// in red: r copies neither. The path of the LAN in blue reaches the table of r, as its prefix is one
	// that a may announce in red, and a policy sees no route distinguisher.
	learnedBefore := b.count(isVRFRoute(TypeLearned, 102, "192.168.1.0/24"))
	withdrawnBefore := b.count(isVRFRoute(TypeWithdrawn, 102, "192.168.1.0/24"))
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.99.0/24"})
	a.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.1.0/24"})
	waitUntil(t, "r holds the path of the LAN of the hostile a in blue", func() bool {
		return r.vpnPathsFrom("127.0.0.3", 102, "192.168.1.0/24") == 1
	})
	time.Sleep(settleTime)
	b.drain()
	c.drain()
	for name, n := range map[string]*testNode{"b": b, "c": c} {
		if k := n.vpnPathsFrom("127.0.0.2", 101, "192.168.99.0/24"); k != 0 {
			t.Errorf("r reflected 192.168.99.0/24, which a may not announce, to %s: %d paths", name, k)
		}
		if k := n.count(isRoute(TypeLearned, "192.168.99.0/24")); k != 0 {
			t.Errorf("%s learned 192.168.99.0/24, which a may not announce, %d times", name, k)
		}
	}
	if k := b.vpnPathsFrom("127.0.0.2", 102, "192.168.1.0/24"); k != 1 {
		t.Errorf("b holds %d paths of 192.168.1.0/24 of blue from r, want the one copy of the route of c", k)
	}
	if l, w := b.count(isVRFRoute(TypeLearned, 102, "192.168.1.0/24")), b.count(isVRFRoute(TypeWithdrawn, 102, "192.168.1.0/24")); l != learnedBefore || w != withdrawnBefore {
		t.Errorf("the hostile a moved the route of c in blue at b: %d learned and %d withdrawn messages, before %d and %d", l, w, learnedBefore, withdrawnBefore)
	}

	// A session from the address of client b to client a is refused, and so is one from 127.0.0.9 to r
	for _, s := range []struct {
		from, to string
		node     *testNode
	}{{"127.0.0.4", "127.0.0.3", a}, {"127.0.0.9", "127.0.0.2", r}} {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(s.from)}, Timeout: waitTimeout}
		conn, err := d.Dial("tcp", net.JoinHostPort(s.to, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("a session from %s to %s: %v", s.from, s.to, err)
		}
		s.node.wait(s.to+" refuses the session from "+s.from, false, isRefused(s.from))
		conn.Close()
	}
}

// Two route reflectors r (127.0.0.2) and s (127.0.0.6) of VRF 101 and two clients a (127.0.0.3) and b
// (127.0.0.4) (SDN-79 #359). a holds the route of b from both reflectors. r stops: a keeps the route of b
// through s, without a withdrawn message, past the hold time. s stops too: with no reflector left, a
// withdraws the route of b within the hold time.
func TestReflectorRedundancy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	r := startNode(t, ctx)
	s := startNode(t, ctx)
	a := startNode(t, ctx)
	b := startNode(t, ctx)
	r.send(peeringStart("192.0.2.2", "127.0.0.2", port))
	s.send(peeringStart("192.0.2.6", "127.0.0.6", port))
	a.send(peeringStart("192.0.2.3", "127.0.0.3", port))
	b.send(peeringStart("192.0.2.4", "127.0.0.4", port))
	for _, n := range []*testNode{r, s, a, b} {
		n.wait("ready", false, isType(TypeReady))
	}

	ofA, ofB := []string{"192.168.1.0/24"}, []string{"192.168.2.0/24"}
	for _, n := range []struct {
		node  *testNode
		other string
	}{{r, "127.0.0.6"}, {s, "127.0.0.2"}} {
		n.node.send(Message{Type: TypePeers, Peers: []Peer{
			peeringPeer(n.other, port, rrVRF(101, RoleReflector)),
			peeringPeer("127.0.0.3", port, rrVRF(101, RoleClient, ofA...)),
			peeringPeer("127.0.0.4", port, rrVRF(101, RoleClient, ofB...)),
		}})
	}
	a.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.2", port, rrVRF(101, RoleReflector)),
		peeringPeer("127.0.0.6", port, rrVRF(101, RoleReflector)),
		peeringPeer("127.0.0.4", port, rrVRF(101, RoleReflected, ofB...)),
	}})
	b.send(Message{Type: TypePeers, Peers: []Peer{
		peeringPeer("127.0.0.2", port, rrVRF(101, RoleReflector)),
		peeringPeer("127.0.0.6", port, rrVRF(101, RoleReflector)),
		peeringPeer("127.0.0.3", port, rrVRF(101, RoleReflected, ofA...)),
	}})
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.1.0/24"})
	b.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.2.0/24"})

	a.wait("a learns 192.168.2.0/24 via b", false, func(m Message) bool {
		return m.Type == TypeLearned && m.VRF == 101 && m.Prefix == "192.168.2.0/24" && m.NextHop == "127.0.0.4"
	})
	waitUntil(t, "a holds the route of b from both reflectors", func() bool {
		return a.vpnPathsFrom("127.0.0.2", 101, "192.168.2.0/24") == 1 && a.vpnPathsFrom("127.0.0.6", 101, "192.168.2.0/24") == 1
	})
	a.drain()
	withdrawn := a.count(isVRFRoute(TypeWithdrawn, 101, "192.168.2.0/24"))

	// r stops: a keeps the route of b through s, past the hold time
	r.conn.Close()
	a.wait("a: the session with r ends", false, func(m Message) bool {
		return m.Type == TypePeer && m.Peer == "127.0.0.2" && m.State != StateEstablished
	})
	time.Sleep(peeringHoldTime*time.Second + settleTime)
	a.drain()
	if w := a.count(isVRFRoute(TypeWithdrawn, 101, "192.168.2.0/24")); w != withdrawn {
		t.Errorf("a withdrew the route of b %d times when r stopped, though s reflects it", w-withdrawn)
	}
	if n := a.vpnPathsFrom("127.0.0.6", 101, "192.168.2.0/24"); n != 1 {
		t.Errorf("a holds %d paths of the route of b from s after r stopped, want 1", n)
	}
	var last Message
	for _, m := range a.seen {
		if m.VRF == 101 && m.Prefix == "192.168.2.0/24" {
			last = m
		}
	}
	if last.Type != TypeLearned || last.NextHop != "127.0.0.4" {
		t.Errorf("after r stopped, a names the route of b last as %+v, want learned via 127.0.0.4", last)
	}

	// s stops too: with no reflector left, a withdraws the route of b within the hold time
	stopped := time.Now()
	s.conn.Close()
	a.wait("a: 192.168.2.0/24 withdrawn without a reflector", false, isVRFRoute(TypeWithdrawn, 101, "192.168.2.0/24"))
	if took := time.Since(stopped); took > peeringHoldTime*time.Second {
		t.Errorf("a withdrew the route of b %v after the last reflector stopped, after the hold time of %d s", took, peeringHoldTime)
	}
}

// The role of a VRF of a peer comes only in a peers message, and only as one of the three roles.
func TestReflectorRoles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	// A start with a role ends the session with an error
	withRole := startNode(t, ctx)
	withRole.send(peeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, rrVRF(101, RoleClient))))
	if e := withRole.wait("an error for a start with a role", false, isType(TypeError)); !strings.Contains(e.Error, "role") {
		t.Errorf("a start with a role: error %q, want one that names the role", e.Error)
	}

	// A peers message with another role is refused, and the peers before it stay
	node := startNode(t, ctx)
	node.send(peeringStart("192.0.2.2", "127.0.0.2", port))
	node.wait("ready", false, isType(TypeReady))
	node.send(Message{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", port, rrVRF(101, "boss"))}})
	if e := node.wait("an error for a role that is none", false, isType(TypeError)); !strings.Contains(e.Error, "boss") {
		t.Errorf("a peers message with the role boss: error %q, want one that names it", e.Error)
	}
	node.send(Message{Type: TypePing})
	node.wait("pong after the refused peers", false, isType(TypePong))
}
