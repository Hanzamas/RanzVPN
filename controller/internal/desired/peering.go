package desired

import (
	"net/netip"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The BGP peering of the standard mode (SDN-77 #357, intent/peering.go). The Vrf object of a VRF whose
// Nodes peer by BGP carries its peering; the NodeConfig of each of its Nodes the settings of its
// sidecar (the AS, its router id and its address on the network that the operator trusts, the address
// of its tunnel endpoint) and the LAN subnets that it announces there; and the Peer object of each Node
// that shares such a VRF with it the address of that Node's sidecar, the hold time of their session,
// the VRFs of the session and what that Node may announce in them: its addresses, each as a host route,
// and its LAN subnets there. The Controller writes nothing else: the routes go by BGP. A VRF that does
// not peer compiles as before the peering existed.

// vrfPeering returns the peering of the VRF v as the control protocol carries it.
func vrfPeering(v intent.VRF) controlpb.Peering {
	if v.Peering.Protocol == intent.PeeringBGP {
		return controlpb.Peering_PEERING_BGP
	}
	return controlpb.Peering_PEERING_UNSPECIFIED
}

// nodePeering returns the BGP peering of the Node n for its own NodeConfig, nil when no VRF of the Node
// peers by BGP.
func nodePeering(in intent.Intent, n intent.Node, vrfs map[string]*controlpb.Vrf) *controlpb.NodePeering {
	names := in.PeeringVRFs(n)
	a, err := intent.ParseVTEPAddress(n.VTEP.Address)
	if len(names) == 0 || err != nil {
		return nil
	}
	return &controlpb.NodePeering{
		Asn:      intent.PeeringASN,
		RouterId: intent.RouterID(a).AsSlice(),
		Address:  a.AsSlice(),
		Announce: lanRoutes(n, names, vrfs),
	}
}

// peerPeering returns the BGP peering with the Node other, o, for the Peer object of a Node with which
// it shares the VRFs shared: nil when none of them peers by BGP. The hold time is the shortest of those
// VRFs, and a VRF that names none has the default one (SDN-77-R2): VRFs of the hold times default and
// 120 give 90 s, not 120.
func peerPeering(in intent.Intent, other string, o intent.Node, shared map[string]bool, vrfs map[string]*controlpb.Vrf) *controlpb.PeerPeering {
	var names []string
	var hold uint32
	member := map[string]bool{}
	for _, v := range in.PeeringVRFs(o) {
		if !shared[v] {
			continue
		}
		names = append(names, v)
		member[v] = true
		if h := in.VRFs[v].Peering.Hold(); hold == 0 || h < hold {
			hold = h
		}
	}
	a, err := intent.ParseVTEPAddress(o.VTEP.Address)
	if len(names) == 0 || err != nil {
		return nil
	}
	p := &controlpb.PeerPeering{Address: a.AsSlice(), HoldTime: hold}
	for _, v := range names {
		p.VrfIds = append(p.VrfIds, vrfs[v].GetId())
	}
	slices.Sort(p.VrfIds)
	for _, addr := range addresses(in, other, vrfs, member) {
		host := addr.GetPrefix().GetAddress()
		p.Accept = append(p.Accept, &controlpb.Route{VrfId: addr.GetVrfId(), Prefix: &controlpb.Prefix{Address: host, Length: uint32(len(host) * 8)}})
	}
	p.Accept = append(p.Accept, lanRoutes(o, names, vrfs)...)
	sortRoutes(p.Accept)
	return p
}

// lanRoutes returns the LAN subnets of the Node n in the VRFs names as routes, ordered by VRF id, then
// prefix.
func lanRoutes(n intent.Node, names []string, vrfs map[string]*controlpb.Vrf) []*controlpb.Route {
	var out []*controlpb.Route
	for _, v := range names {
		for _, s := range n.LANSubnets[v] {
			if p, err := netip.ParsePrefix(s); err == nil {
				out = append(out, &controlpb.Route{VrfId: vrfs[v].GetId(), Prefix: prefix(p.Masked())})
			}
		}
	}
	sortRoutes(out)
	return out
}
