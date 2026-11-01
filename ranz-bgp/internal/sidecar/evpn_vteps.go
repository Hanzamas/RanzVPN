package sidecar

// The VTEPs that an EVPN gateway knows for a VRF (SDN-25-R3 #571): the node takes a frame of the fabric only from the
// address of a VTEP that it knows for the VRF of its VNI (SDN-25-R1 #549). The node has one route for each prefix of a VRF
// (reportEVPN), so the next hop of that route alone would leave out a leaf that announces a shared prefix and whose route
// lost, and that has no prefix of its own in the VRF: every frame of that leaf would be dropped. So the learned message of a
// prefix names the next hops of all the routes that the peers offer for it, which the node knows as VTEPs of the VRF, and
// the check of the outer source stays as strict as it was.

import (
	"net/netip"
	"slices"
)

// maxEVPNVTEPs is the most next hops that the vteps of a learned message name: the VTEPs of the leaves that offer one prefix
// of a VRF, the next hop of the route of the message among them. The node takes as many (NODE_EVPN_MAX_OFFERS of
// src/Cedar/NodeEvpn.h); the frames of a further leaf, which also announces no prefix of its own, it drops as the frames of
// an unknown VTEP, which it counts and logs.
const maxEVPNVTEPs = 16

// offerVTEPs are the vteps of the learned message of a prefix of a VRF: the next hop of every route that the peers offer for
// it, offers by their NLRI, each once and in order, maxEVPNVTEPs at most, with next, the next hop of the route of the
// message, always among them; nil for no offer.
func offerVTEPs(offers map[string]evpnRoute, next netip.Addr) []netip.Addr {
	if len(offers) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(offers))
	for _, r := range offers {
		out = append(out, r.nextHop)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	out = slices.Compact(out)
	if len(out) > maxEVPNVTEPs {
		// The next hop of the route stays, and the lowest of the others fill the rest
		out = append(slices.DeleteFunc(out, func(a netip.Addr) bool { return a == next })[:maxEVPNVTEPs-1], next)
		slices.SortFunc(out, netip.Addr.Compare)
	}
	return out
}

// vtepTexts are the addresses of vteps as a message names them.
func vtepTexts(vteps []netip.Addr) []string {
	var out []string
	for _, a := range vteps {
		out = append(out, a.String())
	}
	return out
}
