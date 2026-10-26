package desired

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The links of kind vxlan and geneve (SDN-76 #356, intent/link.go). The Vrf object of a VRF carries the
// kind of its links and its VNI; the NodeConfig of a Node of such a VRF the ports of its own tunnel
// endpoint, which it listens on; and the Peer object of every Node that shares such a VRF with it the
// tunnel endpoint of the peer, the only address that it takes the datagrams of those links from, and
// to which it sends them. The tunnel endpoints of the peers of a VRF are its flood list. A change of
// the kind of a VRF is one Generation of each of its Nodes: their Vrf object changes, and with it the
// Peer objects of the peers whose tunnel endpoint they gain or lose.

// linkKind returns the kind of a link as the control protocol carries it. A link of kind noise is left
// unspecified, which the Nodes take as noise, so the Vrf object of such a VRF is what it was before the
// kinds of links existed, and no Node gets a new Generation for it.
func linkKind(kind string) controlpb.LinkKind {
	switch kind {
	case intent.LinkVXLAN:
		return controlpb.LinkKind_LINK_KIND_VXLAN
	case intent.LinkGeneve:
		return controlpb.LinkKind_LINK_KIND_GENEVE
	}
	return controlpb.LinkKind_LINK_KIND_UNSPECIFIED
}

// withLink puts the kind of the links of the VRF v and its VNI into its Vrf object vrf: none for a VRF of
// kind noise.
func withLink(vrf *controlpb.Vrf, v intent.VRF) {
	vrf.Link = linkKind(v.Link)
	if intent.Plain(v.Link) {
		vrf.Vni = v.VNI
	}
}

// ownVtep returns the tunnel endpoint of the Node n for its own NodeConfig: the ports that it listens on,
// nil when no VRF of the Node has a link of kind vxlan or geneve.
func ownVtep(in intent.Intent, n intent.Node) *controlpb.Vtep {
	if len(in.PlainVRFs(n)) == 0 {
		return nil
	}
	return &controlpb.Vtep{VxlanPort: intent.VXLANPort(n.VTEP), GenevePort: intent.GenevePort(n.VTEP)}
}

// peerVtep returns the tunnel endpoint of the Node o for the Peer object of a Node that shares the VRFs
// shared with it: nil when none of them has a link of kind vxlan or geneve, or o has no tunnel endpoint.
func peerVtep(in intent.Intent, o intent.Node, shared map[string]bool) *controlpb.Vtep {
	plain := false
	for v := range shared {
		plain = plain || intent.Plain(in.VRFs[v].Link)
	}
	a, err := intent.ParseVTEPAddress(o.VTEP.Address)
	if !plain || err != nil {
		return nil
	}
	return &controlpb.Vtep{Address: a.AsSlice(), VxlanPort: intent.VXLANPort(o.VTEP), GenevePort: intent.GenevePort(o.VTEP)}
}
