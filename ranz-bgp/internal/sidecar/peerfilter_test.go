package sidecar

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
)

// A hostile member that ties with the honest paths (SDN-77-R3, #570): h announces with the highest LOCAL_PREF that a node announces,
// and has a lower router id than the other nodes, which wins a tie in GoBGP, a prefix that it may announce in VRF 101 with the
// route distinguisher of VRF 102, where v announces it too, and a prefix that it may announce in VRF 102 with the route
// distinguisher of VRF 101, where a announces it. The best path of GoBGP at a for the first is the one of h, which h may not
// announce in VRF 102. The sidecar takes the path of v all the same, whether v announces before h or after it, which no change of
// the best path tells it, and withdraws the route when v withdraws, though the path of h stays; and a keeps announcing its own
// prefix to v.
func TestPeeringHostileTies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	// What a takes from v and from h, and what v takes from a: h may announce 192.168.40.0/24 in VRF 101 and 192.168.20.0/24 in VRF 102
	fromV := []PeerVRF{{ID: 102, Accept: []string{"192.168.40.0/24"}}}
	fromH := []PeerVRF{{ID: 101, Accept: []string{"192.168.40.0/24"}}, {ID: 102, Accept: []string{"192.168.20.0/24"}}}
	fromA := []PeerVRF{{ID: 101, Accept: []string{"192.168.20.0/24"}}}
	a := startNode(t, ctx)
	v := startNode(t, ctx)
	a.send(peeringStart("192.0.2.2", "127.0.0.2", port, peeringPeer("127.0.0.3", port, fromV...), peeringPeer("127.0.0.4", port, fromH...)))
	v.send(peeringStart("192.0.2.3", "127.0.0.3", port, peeringPeer("127.0.0.2", port, fromA...)))
	h := startHostile(t, "127.0.0.4", "192.0.2.1", port, "127.0.0.2")
	a.wait("a ready", false, isType(TypeReady))
	v.wait("v ready", false, isType(TypeReady))
	a.wait("a established with v", true, isPeer("127.0.0.3", StateEstablished))
	a.wait("a established with h", true, isPeer("127.0.0.4", StateEstablished))
	v.wait("v established with a", true, isPeer("127.0.0.2", StateEstablished))

	// h announces first: its paths pass the policy of a, which holds both prefixes for h, and are in the table of a
	h.announce(102, 101, "192.168.40.0/24", math.MaxUint32)
	h.announce(101, 102, "192.168.20.0/24", math.MaxUint32)
	waitUntil(t, "the paths of h are in the table of a", func() bool { return a.vpnPaths("127.0.0.4") == 2 })

	// v announces after h, so its path ranks below the one of h in GoBGP and no best path changes; a takes it
	lan := Message{Type: TypeAnnounce, VRF: 102, Prefix: "192.168.40.0/24"}
	v.send(lan)
	if l := a.wait("a learns 192.168.40.0/24 of VRF 102 from v, which h hides in GoBGP", false, isVRFRoute(TypeLearned, 102, "192.168.40.0/24")); l.Peer != "127.0.0.3" {
		t.Errorf("a learns 192.168.40.0/24 of VRF 102 from %q, want from 127.0.0.3", l.Peer)
	}

	// a announces its own prefix, which h announces in VRF 101 too: v keeps what a announced
	a.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "192.168.20.0/24"})
	v.wait("v learns 192.168.20.0/24 of VRF 101 from a", false, isVRFRoute(TypeLearned, 101, "192.168.20.0/24"))
	time.Sleep(settleTime)
	a.drain()
	v.drain()
	if n := a.count(isType(TypeWithdrawn)); n != 0 {
		t.Errorf("a withdrew %d routes, though no peer withdrew one: the path of h hid them", n)
	}
	if n := v.count(isType(TypeWithdrawn)); n != 0 {
		t.Errorf("v withdrew %d routes of a, which a never withdrew", n)
	}
	if n := a.count(isRoute(TypeLearned, "192.168.20.0/24")); n != 0 {
		t.Errorf("a learned its own prefix 192.168.20.0/24 %d times", n)
	}
	if n := a.count(func(m Message) bool { return m.Type == TypeLearned && m.Peer == "127.0.0.4" && m.VRF == 102 }); n != 0 {
		t.Errorf("a learned %d routes of VRF 102 from h, which announced none there that it may announce", n)
	}

	// v withdraws: the path of h stays and is still the best one in GoBGP, which h may not announce in VRF 102, so a has no route
	v.send(Message{Type: TypeWithdraw, VRF: 102, Prefix: "192.168.40.0/24"})
	a.wait("a: 192.168.40.0/24 of VRF 102 withdrawn when v withdraws", false, isVRFRoute(TypeWithdrawn, 102, "192.168.40.0/24"))

	// ... and takes the route of v again when v announces it again
	v.send(lan)
	if l := a.wait("a learns 192.168.40.0/24 of VRF 102 from v again", false, isVRFRoute(TypeLearned, 102, "192.168.40.0/24")); l.Peer != "127.0.0.3" {
		t.Errorf("a learns 192.168.40.0/24 of VRF 102 again from %q, want from 127.0.0.3", l.Peer)
	}
}

// The prefixes that a node may announce in all its VRFs are the entries of the prefix sets of its import policy: each once, sorted
// by VRF id, an IPv4 prefix apart from an IPv6 one, and exactly their length.
func TestPeerPrefixes(t *testing.T) {
	p := peerConfig{vrfs: map[uint32][]netip.Prefix{
		102: {netip.MustParsePrefix("192.168.10.0/24"), netip.MustParsePrefix("fd00::2/128")},
		101: {netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("192.168.10.0/24")},
	}}
	text := func(l []*api.Prefix) []string {
		var out []string
		for _, e := range l {
			out = append(out, fmt.Sprintf("%s %d..%d", e.IpPrefix, e.MaskLengthMin, e.MaskLengthMax))
		}
		return out
	}
	v4, v6 := peerPrefixes(p)
	if got, want := text(v4), []string{"10.0.0.2/32 32..32", "192.168.10.0/24 24..24"}; !slices.Equal(got, want) {
		t.Errorf("IPv4 entries %v, want %v", got, want)
	}
	if got, want := text(v6), []string{"fd00::2/128 128..128"}; !slices.Equal(got, want) {
		t.Errorf("IPv6 entries %v, want %v", got, want)
	}
	if v4, v6 := peerPrefixes(peerConfig{}); len(v4) != 0 || len(v6) != 0 {
		t.Errorf("a node with no VRFs has %d and %d entries, want none", len(v4), len(v6))
	}
}

// The routes that a read of the table changed go to the node by VRF, then address, then length.
func TestCompareKeys(t *testing.T) {
	key := func(vrf uint32, prefix string) routeKey {
		return routeKey{vrf: vrf, prefix: netip.MustParsePrefix(prefix)}
	}
	keys := []routeKey{key(102, "10.0.0.0/8"), key(101, "fd00::/64"), key(101, "192.168.1.0/25"), key(101, "10.0.0.0/8"), key(101, "192.168.1.0/24")}
	slices.SortFunc(keys, compareKeys)
	want := []routeKey{key(101, "10.0.0.0/8"), key(101, "192.168.1.0/24"), key(101, "192.168.1.0/25"), key(101, "fd00::/64"), key(102, "10.0.0.0/8")}
	if !slices.Equal(keys, want) {
		t.Errorf("order %v, want %v", keys, want)
	}
}
