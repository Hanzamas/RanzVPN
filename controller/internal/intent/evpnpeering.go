package intent

import (
	"fmt"
	"slices"
)

// The EVPN peering of the standard mode (SDN-78 #358) is the Peering of a VRF whose links are of kind
// vxlan, with the protocol evpn: its Nodes exchange their MAC addresses, IP addresses and prefixes by
// EVPN, as two leaves of a fabric do, with the machinery of the EVPN edge toward a fabric (SDN-25,
// SDN-64) in the sidecar of the peering (peering.go): IP prefix routes (type 5) with the VNI of the VRF
// as its L3 VNI, and the MAC/IP advertisement routes (type 2, with MAC mobility) and the inclusive
// multicast Ethernet tag routes (type 3, which fill the flood list) of each L2 Network of the VRF on its
// L2 VNI, the VNI of the Network. The data goes between the Nodes in plain VXLAN, from tunnel endpoint
// to tunnel endpoint, on the VXLAN port that the Nodes of the VRF share. The peer of a Node is another
// Node that the Intent names, and the Controller writes only the configuration of the peers
// (desired/peering.go): the sessions, their hold time and the accept lists, as for bgp, and the L2 VNI
// of each L2 Network. It gives no route of a peer in such a VRF and no tunnel endpoint of a peer for it,
// so the VRF does not also use the routes and the flood list that the Controller fills for a link of
// kind vxlan (link.go). What only the Controller can route in a VRF has so no place in such a VRF, and
// is refused: a 1:1 NAT rule, a leak, an internet exit, a WireGuard Device, an Endpoint and a Stretch.
// The VTEP of the EVPN of a Node holds the VXLAN port of its tunnel endpoint, so a Node of such a VRF
// is a member of no VRF with a link of kind vxlan that does not peer by EVPN.

// PeeringEVPN is the protocol of a VRF whose Nodes peer by EVPN.
const PeeringEVPN = "evpn"

// Peers reports whether the Nodes of a VRF with the peering p peer with the sidecar of the peering: by
// BGP or by EVPN.
func (p Peering) Peers() bool {
	return p.Protocol == PeeringBGP || p.Protocol == PeeringEVPN
}

// peeringBy names the protocol of the peering p in a message: BGP or EVPN.
func peeringBy(p Peering) string {
	if p.Protocol == PeeringEVPN {
		return "EVPN"
	}
	return "BGP"
}

// EVPNVRFs returns the VRFs of the Node n whose Nodes peer by EVPN.
func (in Intent) EVPNVRFs(n Node) []string {
	var out []string
	for _, v := range n.VRFs {
		if in.VRFs[v].Peering.Protocol == PeeringEVPN {
			out = append(out, v)
		}
	}
	return out
}

// validateEVPNPeering checks the EVPN peering of a completed intent: the Nodes of a VRF that peers by
// EVPN share one VXLAN port and are members of no VRF with a link of kind vxlan that does not peer by
// EVPN; such a VRF has no 1:1 NAT rule, leak, internet exit, WireGuard Device, Endpoint or Stretch, whose
// routes only the Controller gives; each of its L2 Networks has an L2 VNI from 1 to MaxVNI that no VRF
// of a link of kind vxlan or geneve and no other Network has, and no other Network has a VNI. A problem
// names the VRF, the Network or the Node and what is wrong. The protocol, the link and the topology of
// the VRF are validatePeering's.
func (in Intent) validateEVPNPeering() []error {
	var problems []error
	evpn := func(vrf string) bool { return in.VRFs[vrf].Peering.Protocol == PeeringEVPN }

	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		if !evpn(name) {
			continue
		}
		if len(v.ImportTargets) > 0 || len(v.ExportTargets) > 0 {
			problems = append(problems, fmt.Errorf("VRF %q: it peers by EVPN, and a leak needs the routes that the Controller gives: leave out its importTargets and exportTargets", name))
		}
		if v.Egress != "" {
			problems = append(problems, fmt.Errorf("VRF %q: it peers by EVPN, and its internet exit %q needs the default route that the Controller gives: leave out egress", name, v.Egress))
		}
		// One VXLAN port: the EVPN of a Node sends to the VTEPs of its peers on the port of its own
		first, firstPort := "", uint32(0)
		for _, node := range sortedNames(in.Nodes) {
			n := in.Nodes[node]
			if !slices.Contains(n.VRFs, name) || n.VTEP == (VTEP{}) {
				continue
			}
			port, _ := n.VTEP.Ports()
			if first == "" {
				first, firstPort = node, port
			} else if port != firstPort {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q peers by EVPN, and the vtep vxlanPort %d is not the %d of Node %q: the EVPN of a Node sends to its peers on its own port", node, name, port, firstPort, first))
			}
		}
	}

	// What only the Controller routes
	for _, name := range sortedNames(in.NATs) {
		if r := in.NATs[name]; evpn(r.VRF) {
			problems = append(problems, fmt.Errorf("NAT %q: VRF %q peers by EVPN, and a 1:1 NAT rule needs the routes that the Controller gives", name, r.VRF))
		}
	}
	for _, name := range sortedNames(in.Devices) {
		if vrf := in.Networks[in.Devices[name].Network].VRF; evpn(vrf) {
			problems = append(problems, fmt.Errorf("Device %q: VRF %q of its Network peers by EVPN, and a WireGuard Device needs the routes that the Controller gives", name, vrf))
		}
	}
	for _, name := range sortedNames(in.Endpoints) {
		e := in.Endpoints[name]
		for _, vrf := range []string{e.VRF, e.Consumer} {
			if evpn(vrf) {
				problems = append(problems, fmt.Errorf("Endpoint %q: VRF %q peers by EVPN, and an Endpoint needs the routes that the Controller gives", name, vrf))
			}
		}
	}
	for _, name := range sortedNames(in.Stretches) {
		if vrf := in.Networks[in.Stretches[name].Network].VRF; evpn(vrf) {
			problems = append(problems, fmt.Errorf("Stretch %q: VRF %q of its Network peers by EVPN, and a Node runs one EVPN, of the peering or toward a fabric", name, vrf))
		}
	}

	// The L2 VNIs: of each L2 Network of a VRF that peers by EVPN, and of no other Network, each once among the VNIs of the VRFs
	vnis := map[uint32]string{}
	for _, name := range sortedNames(in.VRFs) {
		if v := in.VRFs[name]; Plain(v.Link) && v.VNI != 0 {
			vnis[v.VNI] = fmt.Sprintf("VRF %q", name)
		}
	}
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		l2 := n.Mode == ModeL2 && evpn(n.VRF)
		switch {
		case l2 && n.VNI == 0:
			problems = append(problems, fmt.Errorf("Network %q: an L2 Network of VRF %q, which peers by EVPN, needs a vni: the L2 VNI of its routes and frames between the Nodes", name, n.VRF))
		case n.VNI == 0:
		case !l2:
			problems = append(problems, fmt.Errorf("Network %q: vni %d needs an L2 Network of a VRF that peers by EVPN", name, n.VNI))
		case n.VNI > MaxVNI:
			problems = append(problems, fmt.Errorf("Network %q: vni %d is not from 1 to %d", name, n.VNI, MaxVNI))
		default:
			if other, ok := vnis[n.VNI]; ok {
				problems = append(problems, fmt.Errorf("Network %q: vni %d is already the vni of %s", name, n.VNI, other))
			} else {
				vnis[n.VNI] = fmt.Sprintf("Network %q", name)
			}
		}
	}

	// The VXLAN port of a Node of a VRF that peers by EVPN is its EVPN's
	for _, node := range sortedNames(in.Nodes) {
		n := in.Nodes[node]
		mine := in.EVPNVRFs(n)
		if len(mine) == 0 {
			continue
		}
		for _, v := range n.VRFs {
			if in.VRFs[v].Link == LinkVXLAN && !evpn(v) {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q peers by EVPN and VRF %q has a link of kind vxlan without it: the VTEP of the EVPN of the Node holds its VXLAN port", node, mine[0], v))
			}
		}
	}
	return problems
}
