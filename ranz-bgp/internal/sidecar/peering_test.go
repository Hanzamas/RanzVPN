package sidecar

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
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

// vpnPaths is the number of IPv4 VPN paths from peer in the global RIB of the sidecar, the best
// paths and the others. It is for after ready.
func (n *testNode) vpnPaths(peer string) int {
	n.t.Helper()
	if n.bgp == nil {
		n.bgp = <-n.started
	}
	count := 0
	err := n.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_IPv4_VPN}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, p := range paths {
			if p.PeerAddress.String() == peer {
				count++
			}
		}
	})
	if err != nil {
		n.t.Fatalf("sidecar RIB: %v", err)
	}
	return count
}

// vpnKeys is the VPN paths from peer in the global RIB of the sidecar, by VRF and prefix: the best paths and the others,
// IPv4 and IPv6. It is for after ready.
func (n *testNode) vpnKeys(peer string) map[routeKey]bool {
	n.t.Helper()
	if n.bgp == nil {
		n.bgp = <-n.started
	}
	keys := make(map[routeKey]bool)
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN} {
		err := n.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(_ bgp.NLRI, paths []*apiutil.Path) {
			for _, p := range paths {
				if key, ok := pathKey(p); ok && p.PeerAddress.String() == peer {
					keys[key] = true
				}
			}
		})
		if err != nil {
			n.t.Fatalf("sidecar RIB: %v", err)
		}
	}
	return keys
}

// logText is the log of a sidecar that a test reads: the sidecar writes it from goroutines of its own.
type logText struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *logText) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *logText) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

// logger is a log that writes to l and to the output of the test.
func (l *logText) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, l), &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func vpnFamily(afi api.Family_Afi) *api.AfiSafi {
	return &api.AfiSafi{Config: &api.AfiSafiConfig{
		Family:  &api.Family{Afi: afi, Safi: api.Family_SAFI_MPLS_VPN},
		Enabled: true,
	}}
}

// hostileNode is a member of the peering that abuses it: GoBGP, which speaks the VPN families as a Ranz node does and announces
// any path that the test names, in any VRF, with any route target and any LOCAL_PREF, which a sidecar never announces.
type hostileNode struct {
	t    *testing.T
	bgp  *server.BgpServer
	addr netip.Addr
}

// startHostile starts the hostile node at addr, with the router id id, which listens on port and waits for the sidecar at toward
// to connect: the sidecar of the lower address connects.
func startHostile(t *testing.T, addr, id string, port int, toward string) *hostileNode {
	t.Helper()
	b := server.NewBgpServer(server.LoggerOption(testLogger(), nil))
	go b.Serve()
	ctx := context.Background()
	err := b.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             peeringASN,
		RouterId:        id,
		ListenPort:      int32(port),
		ListenAddresses: []string{addr},
	}})
	if err != nil {
		t.Fatalf("hostile node %s: %v", addr, err)
	}
	t.Cleanup(b.Stop)
	err = b.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: toward, PeerAsn: peeringASN},
		Transport: &api.Transport{LocalAddress: addr, PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{HoldTime: peeringHoldTime, KeepaliveInterval: peeringHoldTime / 3}},
		AfiSafis:  []*api.AfiSafi{vpnFamily(api.Family_AFI_IP), vpnFamily(api.Family_AFI_IP6)},
	}})
	if err != nil {
		t.Fatalf("hostile node %s: peer %s: %v", addr, toward, err)
	}
	return &hostileNode{t: t, bgp: b, addr: netip.MustParseAddr(addr)}
}

// announce announces prefix to the sidecar as a VPN path with the route distinguisher of VRF rd, the route target of VRF rt and
// the LOCAL_PREF local.
func (h *hostileNode) announce(rd, rt uint32, prefix string, local uint32) {
	h.t.Helper()
	p := netip.MustParsePrefix(prefix)
	family := bgp.RF_IPv4_VPN
	if p.Addr().Is6() {
		family = bgp.RF_IPv6_VPN
	}
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(p, *bgp.NewMPLSLabelStack(), bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, rd))
	if err != nil {
		h.t.Fatal(err)
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		reach,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, rdAdmin, rt, true)}),
		bgp.NewPathAttributeLocalPref(local),
	}
	_, err = h.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{Family: family, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix()}}})
	if err != nil {
		h.t.Fatalf("hostile node announces %s of VRF %d: %v", prefix, rd, err)
	}
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

// The peers of a node may be more than one line holds, so they go in several peers messages: the
// sidecar takes the peers of the messages with more only with the next one without it, all together,
// and checks them together (SDN-77-R1 #531).
func TestPeeringMore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	a := startNode(t, ctx)
	b := startNode(t, ctx)
	a.send(peeringStart("192.0.2.2", "127.0.0.2", port))
	b.send(peeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, PeerVRF{ID: 101, Accept: []string{"10.0.0.2/32"}})))
	a.wait("a ready", false, isType(TypeReady))
	b.wait("b ready", false, isType(TypeReady))

	// The first part names b: a has no session with it yet
	a.send(Message{Type: TypePeers, More: true, Peers: []Peer{peeringPeer("127.0.0.3", port, PeerVRF{ID: 101, Accept: []string{"10.0.0.3/32"}})}})
	time.Sleep(settleTime)
	a.drain()
	if c := a.count(func(m Message) bool { return m.Type == TypePeer && m.Peer == "127.0.0.3" }); c != 0 {
		t.Errorf("a named the session with b %d times before the last part of its peers came", c)
	}

	// The last part, empty here, applies them all: the session comes up, and the routes go
	a.send(Message{Type: TypePeers})
	a.wait("a established with b", true, isPeer("127.0.0.3", StateEstablished))
	b.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.3/32"})
	a.wait("a learns 10.0.0.3/32 of b", false, isVRFRoute(TypeLearned, 101, "10.0.0.3/32"))

	// A peer that comes twice over two parts is refused as in one message, and the session with b stays
	a.send(Message{Type: TypePeers, More: true, Peers: []Peer{peeringPeer("127.0.0.4", port, PeerVRF{ID: 101})}})
	a.send(Message{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.4", port, PeerVRF{ID: 101})}})
	if e := a.wait("an error for a peer twice over two parts", false, isType(TypeError)); !strings.Contains(e.Error, "twice") {
		t.Errorf("a peer twice over two parts: error %q, want one that it comes twice", e.Error)
	}
	time.Sleep(settleTime)
	a.drain()
	if c := a.count(isVRFRoute(TypeWithdrawn, 101, "10.0.0.3/32")); c != 0 {
		t.Errorf("the peers that a refused ended the session with b: 10.0.0.3/32 withdrawn %d times", c)
	}
}

// A hostile node announces what its accept list does not hold: the exact prefixes of another node, with the route
// distinguisher of a VRF where it is no member too, and then more candidate prefixes than the 4096 learned routes that a node
// held at most for all its peers before SDN-77-R1 (#531), for each VRF id (SDN-77-R3, #570). The paths of the hostile node
// never reach the table of the sidecar, so they hide the route of no other node: the routes of another node, in two VRFs, stay
// learned and are learned again when their session starts again while those paths are there. The session of the hostile node
// ends once it holds more paths than its maximum, which the sidecar logs, and its paths go with it.
func TestPeeringHostile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)
	text := &logText{}

	// What a takes from b, the hostile node, and from c; what b and c take from a
	fromB := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.3/32", "10.20.0.0/16"}}}
	fromC := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.4/32", "192.168.30.0/24"}}, {ID: 102, Accept: []string{"192.168.40.0/24"}}}
	a := startNodeLog(t, ctx, text.logger())
	b := startNode(t, ctx)
	c := startNode(t, ctx)
	a.send(peeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, fromB...), peeringPeer("127.0.0.4", port, fromC...)))
	b.send(peeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, PeerVRF{ID: 101, Accept: []string{"10.0.0.2/32"}})))
	c.send(peeringStart("192.0.2.4", "127.0.0.4", port, peeringPeer("127.0.0.2", port, PeerVRF{ID: 101, Accept: []string{"10.0.0.2/32"}}, PeerVRF{ID: 102})))
	for _, n := range []*testNode{a, b, c} {
		n.wait("ready", false, isType(TypeReady))
	}
	a.wait("a established with b", true, isPeer("127.0.0.3", StateEstablished))
	a.wait("a established with c", true, isPeer("127.0.0.4", StateEstablished))

	// c announces in VRF 101 and 102
	cRoutes := []Message{
		{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.4/32"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.30.0/24"},
		{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.40.0/24"},
	}
	for _, m := range cRoutes {
		c.send(m)
	}
	for _, m := range cRoutes {
		a.wait("a learns "+m.Prefix+" of c", true, isVRFRoute(TypeLearned, m.VRF, m.Prefix))
	}

	// b announces the exact prefixes of c, in VRF 101 and in VRF 102, where it is no member, then its LAN and, last, its address:
	// a legit path, which a learns after it took or refused the paths before it
	for _, m := range cRoutes {
		b.send(m)
	}
	b.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.20.0.0/16"})
	b.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.3/32"})
	a.wait("a learns the address of b", true, isVRFRoute(TypeLearned, 101, "10.0.0.3/32"))
	a.wait("a learns the LAN of b", true, isVRFRoute(TypeLearned, 101, "10.20.0.0/16"))
	time.Sleep(settleTime)
	a.drain()
	isOfC := func(m Message) bool {
		for _, r := range cRoutes {
			if m.VRF == r.VRF && m.Prefix == r.Prefix {
				return true
			}
		}
		return false
	}
	if n := a.count(func(m Message) bool { return m.Type == TypeWithdrawn && isOfC(m) }); n != 0 {
		t.Errorf("a withdrew %d routes of c, which b announced as its own: the paths of b hid them", n)
	}
	if n := a.count(func(m Message) bool { return m.Type == TypeLearned && m.Peer == "127.0.0.3" && isOfC(m) }); n != 0 {
		t.Errorf("a learned %d routes of c from b, which may not announce them", n)
	}
	// The paths of b that its accept list does not hold never reach the table of the sidecar, where they would take part in
	// the choice of the best path
	wantB := map[routeKey]bool{
		{vrf: 101, prefix: netip.MustParsePrefix("10.20.0.0/16")}: true,
		{vrf: 101, prefix: netip.MustParsePrefix("10.0.0.3/32")}:  true,
	}
	if got := a.vpnKeys("127.0.0.3"); !maps.Equal(got, wantB) {
		t.Errorf("the table of the sidecar of a holds the paths %v of b, want %v", got, wantB)
	}

	// The session with c starts again while the paths of b are there: a takes its routes again, in both VRFs
	a.send(Message{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", port, fromB...)}})
	a.wait("a: 192.168.40.0/24 of VRF 102 withdrawn without c", false, isVRFRoute(TypeWithdrawn, 102, "192.168.40.0/24"))
	a.send(Message{Type: TypePeers, Peers: []Peer{peeringPeer("127.0.0.3", port, fromB...), peeringPeer("127.0.0.4", port, fromC...)}})
	// The routes of c come back in any order, so each wait takes the one that comes first
	again := make(map[string]bool)
	for _, m := range cRoutes {
		again[fmt.Sprintf("%d %s", m.VRF, m.Prefix)] = true
	}
	for len(again) > 0 {
		l := a.wait("a learns the routes of c again", false, func(m Message) bool {
			return m.Type == TypeLearned && m.Peer == "127.0.0.4" && again[fmt.Sprintf("%d %s", m.VRF, m.Prefix)]
		})
		delete(again, fmt.Sprintf("%d %s", l.VRF, l.Prefix))
	}

	// b announces more candidate prefixes than the old limit, for each VRF id: more specific prefixes of its LAN in VRF 101, and
	// others in VRF 102 and in VRF 103, which no node shares. The withdrawn messages of the routes of c above were the ones that
	// the end of its session sent; what a sends from here on is the flood's doing.
	flood := len(a.seen)
	const perVRF = 1400
	for i := 0; i < perVRF; i++ {
		for k, vrf := range []uint32{101, 102, 103} {
			b.send(Message{Type: TypeAnnounce, VRF: vrf, Prefix: fmt.Sprintf("10.%d.%d.%d/32", 20+10*k, i/256, i%256)})
		}
	}

	// a ends the session with b once it holds more paths of it than its maximum, says so in its log, and the paths of b go with it
	a.wait("a ends the session with b", false, func(m Message) bool {
		return m.Type == TypePeer && m.Peer == "127.0.0.3" && m.State != StateEstablished
	})
	if !strings.Contains(text.String(), "announced more paths than the maximum") {
		t.Errorf("the log of the sidecar of a does not say that b announced more paths than its maximum:\n%s", text.String())
	}
	waitUntil(t, "the paths of b leave the table of the sidecar of a", func() bool { return a.vpnPaths("127.0.0.3") == 0 })

	time.Sleep(settleTime)
	a.drain()
	if n := a.count(func(m Message) bool {
		return m.Type == TypeLearned && m.Peer == "127.0.0.3" && m.Prefix != "10.20.0.0/16" && m.Prefix != "10.0.0.3/32"
	}); n != 0 {
		t.Errorf("a learned %d of the candidate prefixes of b, which b may not announce", n)
	}
	if n := a.countFrom(flood, func(m Message) bool { return m.Type == TypeWithdrawn && isOfC(m) }); n != 0 {
		t.Errorf("a withdrew %d routes of c while b flooded it", n)
	}
}

// A hostile member of the peering announces, with a higher LOCAL_PREF than the paths of the others have, what it may not
// announce where it announces it (SDN-77-R3, #570): the exact prefixes of another node in the VRF of that node, an address
// among them and an IPv6 prefix, with the route distinguisher of a VRF that no node shares too; a prefix that it may announce in
// VRF 101 with the route distinguisher of VRF 102, where another node has the same prefix; and a prefix of a that it may announce
// in VRF 102, with the route distinguisher of VRF 101. None of them takes the route of v from a, none takes the route of a from
// v, and the routes that h may announce are learned all the while: a path that its peer may not announce does not take part in the
// choice of the best path, so a higher LOCAL_PREF does not make it the best.
func TestPeeringHostileRoutes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	// What a takes from v, the victim, and from h, the hostile node: h may announce 192.168.40.0/24, the LAN of v in VRF 102, in VRF
	// 101, and 192.168.20.0/24, the LAN of a in VRF 101, in VRF 102. What v takes from a.
	fromV := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.3/32", "192.168.30.0/24", "fd00:30::/64"}}, {ID: 102, Accept: []string{"192.168.40.0/24"}}}
	fromH := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.4/32", "10.0.0.5/32", "192.168.40.0/24"}}, {ID: 102, Accept: []string{"192.168.20.0/24"}}}
	fromA := []PeerVRF{{ID: 101, Accept: []string{"10.0.0.2/32", "10.0.0.12/32", "192.168.20.0/24"}}}
	a := startNode(t, ctx)
	v := startNode(t, ctx)
	a.send(peeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, fromV...), peeringPeer("127.0.0.4", port, fromH...)))
	v.send(peeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, fromA...)))
	h := startHostile(t, "127.0.0.4", "192.0.2.4", port, "127.0.0.2")
	a.wait("a ready", false, isType(TypeReady))
	v.wait("v ready", false, isType(TypeReady))
	a.wait("a established with v", true, isPeer("127.0.0.3", StateEstablished))
	a.wait("a established with h", true, isPeer("127.0.0.4", StateEstablished))
	v.wait("v established with a", true, isPeer("127.0.0.2", StateEstablished))

	// v, a and h announce what they may
	vRoutes := []Message{
		{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.3/32"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.30.0/24"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "fd00:30::/64"},
		{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.40.0/24"},
	}
	for _, m := range vRoutes {
		v.send(m)
	}
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.2/32"})
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.20.0/24"})
	h.announce(101, 101, "10.0.0.4/32", 100)
	h.announce(101, 101, "192.168.40.0/24", 100)
	for _, m := range vRoutes {
		if l := a.wait("a learns "+m.Prefix+" of v", true, isVRFRoute(TypeLearned, m.VRF, m.Prefix)); l.Peer != "127.0.0.3" {
			t.Errorf("a learns %s of VRF %d from %q, want from 127.0.0.3", m.Prefix, m.VRF, l.Peer)
		}
	}
	for _, prefix := range []string{"10.0.0.4/32", "192.168.40.0/24"} {
		if l := a.wait("a learns "+prefix+" of h in VRF 101", true, isVRFRoute(TypeLearned, 101, prefix)); l.Peer != "127.0.0.4" {
			t.Errorf("a learns %s of VRF 101 from %q, want from 127.0.0.4", prefix, l.Peer)
		}
	}
	for _, prefix := range []string{"10.0.0.2/32", "192.168.20.0/24"} {
		v.wait("v learns "+prefix+" of a", true, isVRFRoute(TypeLearned, 101, prefix))
	}

	// h announces, with a LOCAL_PREF of 200 where a path has 100 by default, what it may not announce there
	const high = 200
	h.announce(101, 101, "192.168.30.0/24", high) // the LAN of v, as if it were its own in VRF 101
	h.announce(101, 101, "10.0.0.3/32", high)     // the address of v
	h.announce(101, 101, "fd00:30::/64", high)    // an IPv6 prefix of v
	h.announce(103, 103, "192.168.30.0/24", high) // the LAN of v in VRF 103, which no node shares
	h.announce(102, 101, "192.168.40.0/24", high) // the LAN of v in VRF 102, a prefix that h may announce in VRF 101
	h.announce(101, 102, "192.168.20.0/24", high) // the LAN of a in VRF 101, a prefix that h may announce in VRF 102
	// ... and last an address that it may announce: a learns it after it took or refused the paths before it, and a announces
	// another address after that, which v learns after what a sent to it before
	h.announce(101, 101, "10.0.0.5/32", 100)
	a.wait("a learns 10.0.0.5/32 of h", true, isVRFRoute(TypeLearned, 101, "10.0.0.5/32"))
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.0.0.12/32"})
	v.wait("v learns 10.0.0.12/32 of a", true, isVRFRoute(TypeLearned, 101, "10.0.0.12/32"))
	time.Sleep(settleTime)
	a.drain()
	v.drain()

	if n := a.count(isType(TypeWithdrawn)); n != 0 {
		t.Errorf("a withdrew %d routes, though no peer withdrew one: the paths of h hid them", n)
	}
	if n := v.count(isType(TypeWithdrawn)); n != 0 {
		t.Errorf("v withdrew %d routes of a, which a never withdrew: the path of h hid the route of a at a", n)
	}
	for _, m := range vRoutes {
		if n := a.count(func(l Message) bool {
			return l.Type == TypeLearned && l.VRF == m.VRF && l.Prefix == m.Prefix && l.Peer != "127.0.0.3"
		}); n != 0 {
			t.Errorf("a learned %s of VRF %d %d times from a peer other than v, which is the only one that may announce it", m.Prefix, m.VRF, n)
		}
	}
	if n := a.count(isVRFRoute(TypeLearned, 101, "192.168.20.0/24")); n != 0 {
		t.Errorf("a learned its own LAN 192.168.20.0/24 of VRF 101 %d times from h", n)
	}

	// The paths of h in VRF 101 and in VRF 103 that its accept list holds in no VRF never reach the table of the sidecar
	keys := a.vpnKeys("127.0.0.4")
	for _, key := range []routeKey{
		{vrf: 101, prefix: netip.MustParsePrefix("192.168.30.0/24")},
		{vrf: 101, prefix: netip.MustParsePrefix("10.0.0.3/32")},
		{vrf: 101, prefix: netip.MustParsePrefix("fd00:30::/64")},
		{vrf: 103, prefix: netip.MustParsePrefix("192.168.30.0/24")},
	} {
		if keys[key] {
			t.Errorf("the table of the sidecar of a holds the path of h to %s of VRF %d, which its accept list holds in no VRF", key.prefix, key.vrf)
		}
	}
}

// The node asks whether the sidecar runs, and it answers pong once GoBGP answered it too
// (SDN-77-R1 #531): a node ends a sidecar that does not answer.
func TestPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	node := startNode(t, ctx)
	node.send(peeringStart("192.0.2.2", "127.0.0.2", port))
	node.wait("ready", false, isType(TypeReady))
	for i := 0; i < 3; i++ {
		node.send(Message{Type: TypePing})
		node.wait("pong", false, isType(TypePong))
	}
}
