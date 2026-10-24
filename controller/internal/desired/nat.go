package desired

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// 1:1 NAT and 4via6 (SDN-6 #182, ADR-0025 decisions 4 and 5): a node gets the rules that it
// applies (NodeConfig.nat), its 4via6 among them, and the outside prefix of each rule of one
// family of a peer, in the VRFs that the two share, as a route that leads to that peer
// (Peer.routes). The 4via6 of a node leads nowhere: its outside, 0.0.0.0/0, is the whole IPv4 of
// the VRF as its host sees it, never a route.

// natRules returns the 1:1 NAT rules of every Node of in as the control protocol carries them,
// by Node name, ordered by VRF id, then inside prefix.
func natRules(in intent.Intent, vrfs map[string]*controlpb.Vrf) map[string][]*controlpb.Nat {
	out := map[string][]*controlpb.Nat{}
	for node, rules := range in.NATRules() {
		var list []*controlpb.Nat
		for _, r := range rules {
			list = append(list, &controlpb.Nat{VrfId: vrfs[r.VRF].GetId(), Inside: prefix(r.Inside), Outside: prefix(r.Outside)})
		}
		slices.SortStableFunc(list, func(a, b *controlpb.Nat) int {
			return cmp.Or(cmp.Compare(a.GetVrfId(), b.GetVrfId()), bytes.Compare(a.GetInside().GetAddress(), b.GetInside().GetAddress()),
				cmp.Compare(a.GetInside().GetLength(), b.GetInside().GetLength()))
		})
		out[node] = list
	}
	return out
}

// peerRoutes returns the routes that lead to a peer whose 1:1 NAT rules are rules, in the VRFs of
// the ids shared: the outside prefix of each of its rules of one family, ordered by VRF id, then
// prefix.
func peerRoutes(rules []*controlpb.Nat, shared []uint32) []*controlpb.Route {
	var out []*controlpb.Route
	for _, r := range rules {
		if slices.Contains(shared, r.GetVrfId()) && len(r.GetInside().GetAddress()) == len(r.GetOutside().GetAddress()) {
			out = append(out, &controlpb.Route{VrfId: r.GetVrfId(), Prefix: r.GetOutside()})
		}
	}
	slices.SortStableFunc(out, func(a, b *controlpb.Route) int {
		return cmp.Or(cmp.Compare(a.GetVrfId(), b.GetVrfId()), bytes.Compare(a.GetPrefix().GetAddress(), b.GetPrefix().GetAddress()),
			cmp.Compare(a.GetPrefix().GetLength(), b.GetPrefix().GetLength()))
	})
	return out
}
