package sidecar

// The EVPN of the peering of the standard mode (SDN-78 #358): in a VRF whose Nodes peer by EVPN, two Ranz nodes exchange the MAC
// addresses, the IP addresses and the prefixes of the VRF as two leaves of a fabric do, with the machinery of the EVPN of a
// gateway (evpn.go, stretch.go): IP prefix routes (type 5) with the L3 VNI of the VRF, and the MAC/IP advertisement routes (type
// 2) and the inclusive multicast Ethernet tag routes (type 3) of its stretched L2 Networks, each on its L2 VNI, with MAC mobility
// (mobility.go). The data goes between the nodes in plain VXLAN, from VTEP to VTEP.
//
// A start of the peering (with an address, peering.go) may so name an evpn object too: its vtep is the address of the node, its
// vrfs are the VRFs of the node that peer by EVPN and its stretches their L2 Networks. The peers are the Ranz nodes of the peering,
// which the Controller names, and no router of a fabric: each gets the L2VPN EVPN family besides its VPN families, and the import
// policy of the peering keeps taking their EVPN routes when the peers change (importPolicies). An IP prefix route of a peer goes
// into a VRF only when it is exactly a prefix that the peer may announce there (evpnTakes), as a VPN route does, so the vrfs of
// such an evpn object name no accept list. A prefix that the node announces in a VRF that peers by EVPN goes as an IP prefix
// route, and one of a VRF that peers by BGP as a VPN route (evpnRoute).

import (
	"errors"
	"net/netip"

	"github.com/osrg/gobgp/v4/api"
)

// peeringEVPN checks the evpn object e of a start whose address is address: nil for a start of a gateway, whose evpn object
// names the routers of a fabric as its peers, or for one without an evpn object. In the peering of the standard mode, the VTEP of
// the node is its address, and the peers announce what their accept lists hold (evpnTakes), so the vrfs name no accept list.
func peeringEVPN(e *evpnState, address netip.Addr) error {
	if e == nil || !address.IsValid() {
		return nil
	}
	if e.vtep != address {
		return errors.New("start: evpn: with an address the VTEP of the node is that address, where its sidecar listens")
	}
	for _, v := range e.vrfs {
		if len(v.accept) != 0 {
			return errors.New("start: evpn: with an address each peer announces the prefixes of its accept list, so a vrf names no accept list")
		}
	}
	return nil
}

// evpnRoute reports whether an announce or a withdraw with the VRF vrf is an IP prefix route of an EVPN VRF (evpn.go): any vrf of
// a gateway, all of whose VRFs are those of its EVPN, and in the peering of the standard mode a VRF that peers by EVPN, while the
// prefix of a VRF that peers by BGP goes as a VPN route (vpnPath, peering.go).
func (s *session) evpnRoute(vrf uint32) bool {
	if vrf == 0 || s.evpn == nil {
		return false
	}
	return !s.address.IsValid() || s.evpn.has(vrf)
}

// evpnTakes reports whether the IP prefix route of prefix that peer offers goes into the EVPN VRF v: in the peering of the
// standard mode when the peer may announce exactly that prefix in that VRF (accepts, peering.go), as it takes a VPN route; at a
// gateway when the accept list of the VRF covers it.
func (s *session) evpnTakes(v *evpnVRF, peer netip.Addr, prefix netip.Prefix) bool {
	if s.address.IsValid() {
		return s.accepts(peer, routeKey{vrf: v.id, prefix: prefix})
	}
	return v.accepts(prefix)
}

// importPolicies is the import policy of the peering of the name policy (setImport, peerfilter.go), followed by the one that takes
// the EVPN routes of the peers while the session has EVPN (startEVPN, evpn.go), so that a new import policy of the peering keeps
// them.
func (s *session) importPolicies(policy string) []*api.Policy {
	policies := []*api.Policy{{Name: policy}}
	if s.evpn != nil {
		policies = append(policies, &api.Policy{Name: evpnImportPolicy})
	}
	return policies
}
