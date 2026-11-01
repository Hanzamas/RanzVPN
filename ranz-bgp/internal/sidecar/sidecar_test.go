package sidecar

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// waitTimeout bounds every wait for the other side.
const waitTimeout = 30 * time.Second

// settleTime is how long a test waits before it checks that something did not happen.
const settleTime = 2 * time.Second

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// freePort is a TCP port of 127.0.0.1 that nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// testNode is the node's end of a session over an in-memory pipe: it sends messages and keeps
// every message of the sidecar.
type testNode struct {
	t       *testing.T
	conn    net.Conn
	w       *Writer
	msgs    chan Message
	seen    []Message
	done    chan error
	started chan *server.BgpServer
	bgp     *server.BgpServer // the GoBGP of the sidecar, from started
}

func startNode(t *testing.T, ctx context.Context) *testNode {
	return startNodeLog(t, ctx, testLogger())
}

// startNodeLog is startNode with the log of the sidecar in log: a test that reads what the sidecar logged passes its own.
func startNodeLog(t *testing.T, ctx context.Context, log *slog.Logger) *testNode {
	nodeEnd, sidecarEnd := net.Pipe()
	n := &testNode{
		t:       t,
		conn:    nodeEnd,
		w:       NewWriter(nodeEnd),
		msgs:    make(chan Message, 1024),
		done:    make(chan error, 1),
		started: make(chan *server.BgpServer, 1),
	}
	opts := Options{Logger: log, started: func(b *server.BgpServer) { n.started <- b }}
	go func() { n.done <- Run(ctx, sidecarEnd, opts) }()
	go func() {
		r := NewReader(nodeEnd)
		for {
			m, err := r.Read()
			if err != nil {
				close(n.msgs)
				return
			}
			n.msgs <- m
		}
	}()
	t.Cleanup(func() { nodeEnd.Close() })
	return n
}

func (n *testNode) send(m Message) {
	n.t.Helper()
	if err := n.w.Write(m); err != nil {
		n.t.Fatalf("send %s: %v", m.Type, err)
	}
}

// wait returns the first message that matches, from the messages seen so far when old is true,
// or from the messages that come after the last wait; it fails the test after waitTimeout.
func (n *testNode) wait(what string, old bool, match func(Message) bool) Message {
	n.t.Helper()
	if old {
		for _, m := range n.seen {
			if match(m) {
				return m
			}
		}
	}
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	for {
		select {
		case m, ok := <-n.msgs:
			if !ok {
				n.t.Fatalf("waiting for %s: the sidecar closed the pipe; seen %+v", what, n.seen)
			}
			n.seen = append(n.seen, m)
			if match(m) {
				return m
			}
		case <-timer.C:
			n.t.Fatalf("waiting for %s: nothing after %v; seen %+v", what, waitTimeout, n.seen)
		}
	}
}

// drain takes the messages that came so far, without waiting.
func (n *testNode) drain() {
	for {
		select {
		case m, ok := <-n.msgs:
			if !ok {
				return
			}
			n.seen = append(n.seen, m)
		default:
			return
		}
	}
}

// hasPath reports whether the global RIB of the sidecar holds a path to prefix from peer, the
// best path or another one. It is for after ready.
func (n *testNode) hasPath(prefix, peer string) bool {
	n.t.Helper()
	if n.bgp == nil {
		n.bgp = <-n.started
	}
	family := bgp.RF_IPv4_UC
	if netip.MustParsePrefix(prefix).Addr().Is6() {
		family = bgp.RF_IPv6_UC
	}
	found := false
	err := n.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(nlri bgp.NLRI, paths []*apiutil.Path) {
		if nlri.String() != prefix {
			return
		}
		for _, p := range paths {
			if p.PeerAddress.String() == peer {
				found = true
			}
		}
	})
	if err != nil {
		n.t.Fatalf("sidecar RIB: %v", err)
	}
	return found
}

// count is the number of messages seen that match.
func (n *testNode) count(match func(Message) bool) int {
	return n.countFrom(0, match)
}

// countFrom is the number of messages seen from the index from of the messages seen on that match: a test takes len(n.seen) before
// what it checks and counts only the messages that came after.
func (n *testNode) countFrom(from int, match func(Message) bool) int {
	c := 0
	for _, m := range n.seen[from:] {
		if match(m) {
			c++
		}
	}
	return c
}

func isType(typ string) func(Message) bool {
	return func(m Message) bool { return m.Type == typ }
}

func isPeer(addr, state string) func(Message) bool {
	return func(m Message) bool { return m.Type == TypePeer && m.Peer == addr && m.State == state }
}

func isRoute(typ, prefix string) func(Message) bool {
	return func(m Message) bool { return m.Type == typ && m.Prefix == prefix }
}

// testRouter is a router of the operator: GoBGP in the test, which connects to the sidecar.
type testRouter struct {
	t   *testing.T
	bgp *server.BgpServer
	ids map[string]uuid.UUID
}

// startRouter starts the router AS asn, which connects from the address local to the sidecar's
// AS 65001 on 127.0.0.1:port.
func startRouter(t *testing.T, asn uint32, routerID, local string, port int) *testRouter {
	t.Helper()
	b := server.NewBgpServer(server.LoggerOption(testLogger(), nil))
	go b.Serve()
	ctx := context.Background()
	err := b.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: asn, RouterId: routerID, ListenPort: -1}})
	if err != nil {
		t.Fatalf("router %s: %v", routerID, err)
	}
	t.Cleanup(b.Stop)
	err = b.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{LocalAddress: local, RemotePort: uint32(port)},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis:  []*api.AfiSafi{unicast(api.Family_AFI_IP), unicast(api.Family_AFI_IP6)},
	}})
	if err != nil {
		t.Fatalf("router %s: peer: %v", routerID, err)
	}
	return &testRouter{t: t, bgp: b, ids: make(map[string]uuid.UUID)}
}

// announce announces prefix via nextHop to the sidecar.
func (r *testRouter) announce(prefix, nextHop string) {
	r.t.Helper()
	p := netip.MustParsePrefix(prefix)
	nh := netip.MustParseAddr(nextHop)
	nlri, err := bgp.NewIPAddrPrefix(p)
	if err != nil {
		r.t.Fatal(err)
	}
	family := bgp.RF_IPv4_UC
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)}
	if p.Addr().Is4() {
		a, err := bgp.NewPathAttributeNextHop(nh)
		if err != nil {
			r.t.Fatal(err)
		}
		attrs = append(attrs, a)
	} else {
		family = bgp.RF_IPv6_UC
		a, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nh)
		if err != nil {
			r.t.Fatal(err)
		}
		attrs = append(attrs, a)
	}
	resp, err := r.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: family,
		Nlri:   nlri,
		Attrs:  attrs,
		Age:    time.Now().Unix(),
	}}})
	if err != nil {
		r.t.Fatalf("router announces %s: %v", prefix, err)
	}
	r.ids[prefix] = resp[0].UUID
}

// withdraw withdraws an announced prefix.
func (r *testRouter) withdraw(prefix string) {
	r.t.Helper()
	if err := r.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{r.ids[prefix]}}); err != nil {
		r.t.Fatalf("router withdraws %s: %v", prefix, err)
	}
	delete(r.ids, prefix)
}

// has reports whether the router has a route to prefix, its own or one from the sidecar.
func (r *testRouter) has(prefix string) bool {
	r.t.Helper()
	found := false
	for _, family := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		err := r.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(n bgp.NLRI, _ []*apiutil.Path) {
			if n.String() == prefix {
				found = true
			}
		})
		if err != nil {
			r.t.Fatalf("router RIB: %v", err)
		}
	}
	return found
}

// established reports whether the session with the sidecar is up.
func (r *testRouter) established() bool {
	r.t.Helper()
	up := false
	err := r.bgp.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		up = p.State != nil && p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED
	})
	if err != nil {
		r.t.Fatalf("router peers: %v", err)
	}
	return up
}

// waitUntil polls cond until it holds; it fails the test after waitTimeout.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("%s: not after %v", what, waitTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A session with two routers of the operator: the node's prefixes reach both and leave both again;
// the node learns what accept covers, with the next hop the router gave, and hears when a route
// goes or moves to the other router; one router never gets the routes of the other (no transit);
// messages that cannot be applied are answered with an error and the session goes on; and when the
// node closes the pipe, BGP stops and both sessions end.
func TestSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	node := startNode(t, ctx)
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      int32(port),
		ListenAddresses: []string{"127.0.0.1"},
		Peers:           []Peer{{Address: "127.0.0.1", ASN: 65002, Passive: true}, {Address: "127.0.0.2", ASN: 65003, Passive: true}},
		Accept:          []string{"198.51.100.0/24", "2001:db8:100::/48"},
	})
	ready := node.wait("ready", false, isType(TypeReady))
	if ready.Protocol != ProtocolVersion || !strings.Contains(ready.Version, "GoBGP") {
		t.Errorf("ready: protocol %d, version %q", ready.Protocol, ready.Version)
	}

	a := startRouter(t, 65002, "192.0.2.2", "127.0.0.1", port)
	b := startRouter(t, 65003, "192.0.2.3", "127.0.0.2", port)
	node.wait("router a established", true, isPeer("127.0.0.1", StateEstablished))
	node.wait("router b established", true, isPeer("127.0.0.2", StateEstablished))

	// The node's prefix reaches both routers and leaves both again.
	node.send(Message{Type: TypeAnnounce, Prefix: "203.0.113.0/24"})
	waitUntil(t, "router a gets 203.0.113.0/24", func() bool { return a.has("203.0.113.0/24") })
	waitUntil(t, "router b gets 203.0.113.0/24", func() bool { return b.has("203.0.113.0/24") })
	node.send(Message{Type: TypeWithdraw, Prefix: "203.0.113.0/24"})
	waitUntil(t, "router a loses 203.0.113.0/24", func() bool { return !a.has("203.0.113.0/24") })
	waitUntil(t, "router b loses 203.0.113.0/24", func() bool { return !b.has("203.0.113.0/24") })

	// Router a: a prefix outside accept first, then two inside it.
	a.announce("192.0.2.128/25", "192.0.2.254")
	a.announce("198.51.100.0/24", "192.0.2.254")
	a.announce("2001:db8:100::/48", "2001:db8::fe")
	l4 := node.wait("learned 198.51.100.0/24", true, isRoute(TypeLearned, "198.51.100.0/24"))
	if l4.NextHop != "192.0.2.254" || l4.Peer != "127.0.0.1" {
		t.Errorf("learned 198.51.100.0/24: next hop %q from %q, want 192.0.2.254 from 127.0.0.1", l4.NextHop, l4.Peer)
	}
	l6 := node.wait("learned 2001:db8:100::/48", true, isRoute(TypeLearned, "2001:db8:100::/48"))
	if l6.NextHop != "2001:db8::fe" || l6.Peer != "127.0.0.1" {
		t.Errorf("learned 2001:db8:100::/48: next hop %q from %q, want 2001:db8::fe from 127.0.0.1", l6.NextHop, l6.Peer)
	}

	// The node's prefix, announced after the routes of router a, reaches router b; so router b has
	// had every update the sidecar sent it before, and none carried a route of router a.
	node.send(Message{Type: TypeAnnounce, Prefix: "203.0.113.0/24", NextHop: "192.0.2.1"})
	waitUntil(t, "router b gets 203.0.113.0/24 again", func() bool { return b.has("203.0.113.0/24") })
	time.Sleep(settleTime)
	if b.has("198.51.100.0/24") || b.has("2001:db8:100::/48") || b.has("192.0.2.128/25") {
		t.Error("router b got a route of router a through the sidecar")
	}
	node.drain()
	if c := node.count(isRoute(TypeLearned, "192.0.2.128/25")); c != 0 {
		t.Errorf("192.0.2.128/25 is outside accept, but the node learned it %d times", c)
	}

	// The best route to 2001:db8:100::/48 moves to router b when router a withdraws it. The route of
	// router a stays the best one until then, so no message tells when the sidecar has the route of
	// router b: the test looks into the RIB of the sidecar, or the withdraw could overtake it.
	b.announce("2001:db8:100::/48", "2001:db8::fb")
	waitUntil(t, "the sidecar has 2001:db8:100::/48 from router b", func() bool { return node.hasPath("2001:db8:100::/48", "127.0.0.2") })
	a.withdraw("2001:db8:100::/48")
	moved := node.wait("2001:db8:100::/48 via router b", false, func(m Message) bool {
		return m.Type == TypeLearned && m.Prefix == "2001:db8:100::/48" && m.Peer == "127.0.0.2"
	})
	if moved.NextHop != "2001:db8::fb" {
		t.Errorf("2001:db8:100::/48 via router b: next hop %q, want 2001:db8::fb", moved.NextHop)
	}
	if c := node.count(isRoute(TypeWithdrawn, "2001:db8:100::/48")); c != 0 {
		t.Errorf("2001:db8:100::/48 moved to router b with %d withdrawn messages between", c)
	}

	// A withdrawn route is withdrawn at the node.
	a.withdraw("198.51.100.0/24")
	w := node.wait("withdrawn 198.51.100.0/24", false, isRoute(TypeWithdrawn, "198.51.100.0/24"))
	if w.Peer != "127.0.0.1" {
		t.Errorf("withdrawn 198.51.100.0/24: from %q, want 127.0.0.1", w.Peer)
	}

	// What cannot be applied is answered with an error; the session goes on. A prefix with a vrf
	// is of an EVPN VRF (evpn.go; SDN-25 #201) or of the peering of the standard mode (peering.go),
	// and this session runs neither: it goes nowhere, and its withdraw takes no unicast route away.
	refused := []Message{
		{Type: TypeWithdraw, Prefix: "198.18.0.0/15"},
		{Type: TypeAnnounce, Prefix: "203.0.113.1/24"},
		{Type: TypeAnnounce, Prefix: "198.18.0.0/15", NextHop: "2001:db8::1"},
		{Type: TypeStart, ASN: 65001},
		{Type: "bogus"},
		{Type: TypeAnnounce, Prefix: "198.18.0.0/15", VRF: 101},
		{Type: TypeWithdraw, Prefix: "203.0.113.0/24", VRF: 101},
	}
	for _, m := range refused {
		node.send(m)
		e := node.wait("an error for "+m.Type+" "+m.Prefix, false, isType(TypeError))
		if e.Prefix != m.Prefix || e.Error == "" {
			t.Errorf("error for %+v: %+v", m, e)
		}
	}
	if !a.established() || !b.established() {
		t.Error("a session ended after a refused message")
	}
	time.Sleep(settleTime)
	if b.has("198.18.0.0/15") || !b.has("203.0.113.0/24") {
		t.Error("an announce or withdraw with a vrf changed the unicast routes that router b has from the sidecar")
	}

	// The node closes the pipe: the sidecar stops BGP and both routers see their session end.
	node.conn.Close()
	select {
	case err := <-node.done:
		if err != nil {
			t.Errorf("the session ended with %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the session did not end after the node closed the pipe")
	}
	waitUntil(t, "router a sees the session end", func() bool { return !a.established() })
	waitUntil(t, "router b sees the session end", func() bool { return !b.established() })
}

// Without accept the node learns nothing: the sidecar takes no route from the peers.
func TestNothingAccepted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	node := startNode(t, ctx)
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      int32(port),
		ListenAddresses: []string{"127.0.0.1"},
		Peers:           []Peer{{Address: "127.0.0.1", ASN: 65002, Passive: true}},
	})
	node.wait("ready", false, isType(TypeReady))
	a := startRouter(t, 65002, "192.0.2.2", "127.0.0.1", port)
	node.wait("router a established", true, isPeer("127.0.0.1", StateEstablished))

	a.announce("198.51.100.0/24", "192.0.2.254")
	node.send(Message{Type: TypeAnnounce, Prefix: "203.0.113.0/24"})
	waitUntil(t, "router a gets 203.0.113.0/24", func() bool { return a.has("203.0.113.0/24") })
	time.Sleep(settleTime)
	node.drain()
	if c := node.count(isType(TypeLearned)); c != 0 {
		t.Errorf("no accept, but the node learned %d routes", c)
	}
}

// A session that does not begin with a good start ends with an error, after an error message.
func TestBadStart(t *testing.T) {
	cases := []Message{
		{Type: TypeAnnounce, Prefix: "203.0.113.0/24"},
		{Type: TypeStart, RouterID: "192.0.2.1", Peers: []Peer{{Address: "192.0.2.2", ASN: 65002}}},
		{Type: TypeStart, ASN: 65001, RouterID: "192.0.2.1"},
	}
	for _, m := range cases {
		node := startNode(t, context.Background())
		node.send(m)
		e := node.wait("an error for a bad start", false, isType(TypeError))
		if e.Error == "" {
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
