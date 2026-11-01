package intent

import (
	"fmt"
	"slices"
)

// The route reflectors of the peering of the standard mode (SDN-79 #359). A VRF that peers by BGP may
// name one or two of its Nodes as its route reflectors (Peering.Reflectors): every other Node of the VRF
// is then a client of each of them. A client has a BGP session with each reflector of the VRF and with no
// other client, and a reflector passes on the routes of each client to the other clients and its own and
// theirs to each client, so a VRF of many Nodes needs no full mesh of sessions; with two reflectors the
// clients keep their routes while one of them stops. The two reflectors of a VRF peer with each other.
// The links of the VRF stay a full mesh: a route that a reflector passes on leads to the client that
// announced it, never through the reflector. The Controller gives each Node, in the Peer object of each
// Node that shares such a VRF with it, the role of that Node there (PeeringRole, desired/reflector.go),
// and a Node of the VRF needs the Capability bgpReflection. A reflector is a point of trust: it decides
// what the clients of its VRF learn (SM-7 of the threat model).

// MaxReflectors is the most route reflectors of a VRF.
const MaxReflectors = 2

// The roles of a Node for another in a VRF that peers by BGP (PeeringRole). They are not the Roles of a
// Node (ADR-0011, stretch.go), which say what the Node does.
const (
	// PeeringMesh is the role in a VRF without route reflectors: the two peer directly.
	PeeringMesh = ""
	// PeeringReflector: the Node is a route reflector of the VRF.
	PeeringReflector = "reflector"
	// PeeringClient: the Node is a client of the other, a reflector of the VRF.
	PeeringClient = "client"
	// PeeringReflected: both are clients, and the routes of the Node come to the other through the reflectors.
	PeeringReflected = "reflected"
)

// completeReflectors returns the reflectors of a peering in name order, nil for none.
func completeReflectors(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := slices.Clone(names)
	slices.Sort(out)
	return out
}

// PeeringRole returns the role of the Node peer for the Node node in the VRF vrf, which peers by BGP and
// of which both are members: PeeringReflector when peer is a reflector of the VRF, PeeringClient when node
// is one and peer is not, PeeringReflected when neither is, and PeeringMesh in a VRF without reflectors.
func (in Intent) PeeringRole(node, peer, vrf string) string {
	reflectors := in.VRFs[vrf].Peering.Reflectors
	switch {
	case len(reflectors) == 0:
		return PeeringMesh
	case slices.Contains(reflectors, peer):
		return PeeringReflector
	case slices.Contains(reflectors, node):
		return PeeringClient
	}
	return PeeringReflected
}

// PeeringSession reports whether the Nodes node and peer have a BGP session: they share a VRF that peers by
// BGP in which they are not both clients of its reflectors.
func (in Intent) PeeringSession(node, peer string) bool {
	if node == peer {
		return false
	}
	other := in.Nodes[peer]
	for _, vrf := range in.PeeringVRFs(in.Nodes[node]) {
		if slices.Contains(other.VRFs, vrf) && in.PeeringRole(node, peer, vrf) != PeeringReflected {
			return true
		}
	}
	return false
}

// validateReflectors checks the route reflectors of a completed intent: a VRF names them only with the
// peering protocol bgp, at most MaxReflectors, each once, and each a Node that is a member of the VRF. A
// problem names the VRF and the reflector.
func (in Intent) validateReflectors() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		p := in.VRFs[name].Peering
		if len(p.Reflectors) == 0 {
			continue
		}
		if p.Protocol != PeeringBGP {
			problems = append(problems, fmt.Errorf("VRF %q: the peering reflectors need the peering protocol %s", name, PeeringBGP))
			continue
		}
		if len(p.Reflectors) > MaxReflectors {
			problems = append(problems, fmt.Errorf("VRF %q: the peering names %d reflectors, and a VRF has %d at most", name, len(p.Reflectors), MaxReflectors))
		}
		for i, r := range p.Reflectors {
			n, ok := in.Nodes[r]
			switch {
			case i > 0 && p.Reflectors[i-1] == r:
				problems = append(problems, fmt.Errorf("VRF %q: the peering names the reflector %q twice", name, r))
			case !ok:
				problems = append(problems, fmt.Errorf("VRF %q: the peering reflector %q is no Node", name, r))
			case !slices.Contains(n.VRFs, name):
				problems = append(problems, fmt.Errorf("VRF %q: the peering reflector %q is not a member of the VRF", name, r))
			}
		}
	}
	return problems
}
