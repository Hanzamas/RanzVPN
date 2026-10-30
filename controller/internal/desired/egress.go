package desired

import (
	"net/netip"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The internet exit of a VRF (SDN-12 #188, intent/egress.go). The NodeConfig of the exit carries the
// ids of the VRFs whose exit it is (NodeConfig.egress_vrf_ids): in each of them the node routes the
// addresses outside the VRF to its host, which takes their traffic to the internet with the Egress
// tier of the node. The Peer object of the exit in the state of every other Node of such a VRF
// carries the default route 0.0.0.0/0 of the VRF, so that Node sends the traffic of the VRF to the
// addresses outside it to the exit. A change of the exit of a VRF is one Generation of each Node of
// the VRF: their NodeConfig or the Peer objects of the old and the new exit change.

// egressVRFIDs returns the ids of the VRFs of vrfs whose internet exit the Node node is, ascending,
// nil for none.
func egressVRFIDs(in intent.Intent, node string, vrfs map[string]*controlpb.Vrf) []uint32 {
	var out []uint32
	for _, v := range in.EgressVRFs(node) {
		out = append(out, vrfs[v].GetId())
	}
	slices.Sort(out)
	return out
}

// withEgress returns the routes of the peer other with the default route of each VRF of shared
// whose internet exit the peer is, ordered as withLeaks orders them.
func withEgress(routes []*controlpb.Route, in intent.Intent, other string, shared map[string]bool, vrfs map[string]*controlpb.Vrf) []*controlpb.Route {
	var exits []*controlpb.Route
	for _, v := range in.EgressVRFs(other) {
		if shared[v] {
			exits = append(exits, &controlpb.Route{VrfId: vrfs[v].GetId(), Prefix: prefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))})
		}
	}
	return withLeaks(routes, exits)
}
