package desired

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// Route leaking (SDN-7 #183, ADR-0025 decisions 7 to 9): each VRF of a node that imports a route
// target that another VRF exports gets the routes of that VRF which lead to its other members
// (intent.LeakedRoutes), as routes of the Peer of each member with the id of the exporting VRF
// (Route.peer_vrf_id): the node sends a packet on such a route into that VRF of the peer, and the
// peer delivers it there only when that VRF routes the source back to the node, so traffic follows
// a leak both ways only. The members of the two VRFs of a leak are peers whether or not they share
// a VRF, so either can open the Noise session to the other, whatever the order of their keys.

// leaks is what the leaks of an intent give the nodes, by node name, then peer name: the peers
// that a leak joins and the routes that it moves.
type leaks struct {
	joined map[string]map[string]bool
	routes map[string]map[string][]*controlpb.Route
}

// leakRoutes returns the peers and the routes that the leaks of in give each node, with the ids of
// vrfs.
func leakRoutes(in intent.Intent, vrfs map[string]*controlpb.Vrf) leaks {
	out := leaks{joined: map[string]map[string]bool{}, routes: map[string]map[string][]*controlpb.Route{}}
	members := map[string][]string{} // by VRF name
	for name, n := range in.Nodes {
		for _, v := range n.VRFs {
			members[v] = append(members[v], name)
		}
	}
	join := func(a, b string) {
		if out.joined[a] == nil {
			out.joined[a] = map[string]bool{}
		}
		out.joined[a][b] = true
	}
	for _, l := range in.Leaks() {
		for _, a := range members[l.To] {
			for _, b := range members[l.From] {
				if a != b {
					join(a, b)
					join(b, a)
				}
			}
		}
	}
	for _, r := range in.LeakedRoutes() {
		route := &controlpb.Route{VrfId: vrfs[r.VRF].GetId(), Prefix: prefix(r.Prefix), PeerVrfId: vrfs[r.From].GetId()}
		for _, node := range members[r.VRF] {
			// A route that an Endpoint puts into the tables of some Nodes (publish.go; SDN-24) is held by those alone, and joins
			// each of them to the Node that it leads to, with no other member of that Node's VRF
			if node == r.Via || !r.HeldBy(node) {
				continue
			}
			if len(r.Nodes) != 0 {
				join(node, r.Via)
				join(r.Via, node)
			}
			if out.routes[node] == nil {
				out.routes[node] = map[string][]*controlpb.Route{}
			}
			out.routes[node][r.Via] = append(out.routes[node][r.Via], route)
		}
	}
	return out
}

// withLeaks returns the routes of a peer with the routes that leaks add, ordered by VRF id, then
// prefix, then the VRF of the peer.
func withLeaks(routes, leaked []*controlpb.Route) []*controlpb.Route {
	if len(leaked) == 0 {
		return routes
	}
	out := append(slices.Clone(routes), leaked...)
	slices.SortStableFunc(out, func(a, b *controlpb.Route) int {
		return cmp.Or(cmp.Compare(a.GetVrfId(), b.GetVrfId()), bytes.Compare(a.GetPrefix().GetAddress(), b.GetPrefix().GetAddress()),
			cmp.Compare(a.GetPrefix().GetLength(), b.GetPrefix().GetLength()), cmp.Compare(a.GetPeerVrfId(), b.GetPeerVrfId()))
	})
	return out
}
