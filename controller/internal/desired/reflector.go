package desired

import (
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The route reflectors of the peering of the standard mode (SDN-79 #359, intent/reflector.go). The Vrf object
// of a VRF of route reflectors names them. In the Peer object of each Node that shares such a VRF with a Node,
// the BGP peering gives the role of that peer there: the VRFs in which it is a reflector, those in which it is
// a client of the Node, and those in which both are clients. The Node's sidecar has no session with a peer all
// of whose VRFs are of the last kind, and still holds what that peer may announce, to check the routes that
// the reflectors pass on.

// vrfReflectors returns the route reflectors of the VRF v for its Vrf object, in name order: none while it
// does not peer by BGP.
func vrfReflectors(v intent.VRF) []string {
	if v.Peering.Protocol != intent.PeeringBGP {
		return nil
	}
	return slices.Clone(v.Peering.Reflectors)
}

// withReflection gives the BGP peering p of the Peer object of other at the Node node the role of other in
// each VRF of p whose Intent names route reflectors; p may be nil, for a peer that shares no VRF that peers
// by BGP.
func withReflection(in intent.Intent, node, other string, p *controlpb.PeerPeering, vrfs map[string]*controlpb.Vrf) {
	if p == nil {
		return
	}
	for _, name := range in.PeeringVRFs(in.Nodes[other]) {
		v, ok := vrfs[name]
		if !ok || !slices.Contains(p.VrfIds, v.GetId()) {
			continue
		}
		switch in.PeeringRole(node, other, name) {
		case intent.PeeringReflector:
			p.ReflectorVrfIds = append(p.ReflectorVrfIds, v.GetId())
		case intent.PeeringClient:
			p.ClientVrfIds = append(p.ClientVrfIds, v.GetId())
		case intent.PeeringReflected:
			p.ReflectedVrfIds = append(p.ReflectedVrfIds, v.GetId())
		}
	}
	slices.Sort(p.ReflectorVrfIds)
	slices.Sort(p.ClientVrfIds)
	slices.Sort(p.ReflectedVrfIds)
}
