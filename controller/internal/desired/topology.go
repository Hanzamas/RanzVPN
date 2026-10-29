package desired

import (
	"bytes"
	"cmp"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The topology of the VRFs and their gateways (SDN-19 #195, intent/topology.go). The Vrf object of a
// VRF of topology hub-and-spoke names its hub, and the Vrf object of a VRF with ECMP says so. The
// NodeConfig of a gateway holds the LAN subnets behind it, which lead to its host; the Peer object of
// a gateway holds the LAN subnets that it advertises in the VRFs that the two share, and the Peer
// object of a hub also the prefixes of the VRF that a spoke reaches through it, as routes that lead to
// it (intent.GatewayRoutes). Two spokes of a VRF of topology hub-and-spoke do not share it, so they are
// no peers through it. The Controller marks the Peer object of a gateway down from its health data
// (controller/gateways.go).
//
// The hub is the place where the policy of the VRF decides the traffic between two spokes (SDN-19-R2
// #508): a spoke sees the hub as the other end of that traffic, and the hub sees both real ends. The hub
// judges each packet that it sends on from one spoke to another by the rules of the VRF, with the Peer
// that sent it and the Peer of its next hop as its ends, so it gets every rule of the VRF (hubHolds),
// the rules between two spokes among them, which name no tag of its own.

// withTopology puts the hub of the VRF v of topology hub-and-spoke and its ECMP into its Vrf object
// vrf.
func withTopology(vrf *controlpb.Vrf, v intent.VRF) {
	if v.HubAndSpoke() {
		vrf.Hub = v.Hub
	}
	vrf.Ecmp = v.ECMP
}

// hubHolds reports whether the Node node is the hub of the VRF of the rule r, a VRF of topology
// hub-and-spoke. The hub judges the flows that it sends on between any two spokes of the VRF by their
// real ends, so any rule of the VRF can match a flow there, and it gets them all (nodeRules).
func hubHolds(in intent.Intent, node string, r intent.Rule) bool {
	v := in.VRFs[r.VRF]
	return v.HubAndSpoke() && v.Hub == node
}

// lanSubnets returns the LAN subnets of each Node of in as its NodeConfig carries them, by Node name,
// ordered by VRF id, then prefix, with the ids of vrfs. A Node without one has no entry.
func lanSubnets(in intent.Intent, vrfs map[string]*controlpb.Vrf) map[string][]*controlpb.Route {
	out := map[string][]*controlpb.Route{}
	for _, r := range in.Routes() {
		out[r.Via] = append(out[r.Via], &controlpb.Route{VrfId: vrfs[r.VRF].GetId(), Prefix: prefix(r.Prefix)})
	}
	for _, list := range out {
		sortRoutes(list)
	}
	return out
}

// withGateways returns the routes of a peer with the routes that lead the node to it as a gateway or
// a hub, gateway, with the ids of vrfs, ordered by VRF id, then prefix, each once.
func withGateways(routes []*controlpb.Route, gateway []intent.Route, vrfs map[string]*controlpb.Vrf) []*controlpb.Route {
	if len(gateway) == 0 {
		return routes
	}
	out := slices.Clone(routes)
	for _, r := range gateway {
		route := &controlpb.Route{VrfId: vrfs[r.VRF].GetId(), Prefix: prefix(r.Prefix)}
		if !slices.ContainsFunc(out, func(o *controlpb.Route) bool { return proto.Equal(o, route) }) {
			out = append(out, route)
		}
	}
	sortRoutes(out)
	return out
}

// sortRoutes orders routes by VRF id, then prefix, as peerRoutes does.
func sortRoutes(routes []*controlpb.Route) {
	slices.SortStableFunc(routes, func(a, b *controlpb.Route) int {
		return cmp.Or(cmp.Compare(a.GetVrfId(), b.GetVrfId()), bytes.Compare(a.GetPrefix().GetAddress(), b.GetPrefix().GetAddress()),
			cmp.Compare(a.GetPrefix().GetLength(), b.GetPrefix().GetLength()))
	})
}
