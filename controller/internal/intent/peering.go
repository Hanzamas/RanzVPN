package intent

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// The peering of the standard mode (SDN-77 #357) is the Peering of a VRF whose links are of kind
// vxlan or geneve (link.go): with the protocol bgp, the Nodes of the VRF exchange their routes by BGP,
// as routers do, in a full mesh. Each Node runs the sidecar ranz bgp (GoBGP) on its tunnel endpoint,
// so the sessions run on the network that the operator trusts, as the links do, and plain. The
// Controller gives each Node the settings of its sidecar and, for each peer, its address and what it
// may announce: its addresses and its LAN subnets in the VRFs that the two share (desired/peering.go).
// It writes nothing else: the routes go between the Nodes, which announce their LAN subnets and their
// addresses there and install what they learn. All the Nodes are in one AS (PeeringASN), so the
// sessions are internal BGP: a Node passes on nothing that it learned, which a route reflector will
// do (SDN-79). The router id of a Node comes from its tunnel endpoint (RouterID). BGP is an Enterprise
// feature (licence.FeatureEVPN), which the controller checks before the intent.

const (
	// PeeringBGP is the protocol of a VRF whose Nodes peer by BGP.
	PeeringBGP = "bgp"
	// PeeringASN is the AS of the Nodes of the overlay in the BGP peering, one for all of them: a
	// private AS of four bytes (RFC 6996).
	PeeringASN = 4200000000
	// DefaultHoldTime is the BGP hold time in seconds of a VRF that names none, and MinHoldTime and
	// MaxHoldTime the shortest and the longest (RFC 4271 section 4.2).
	DefaultHoldTime = 90
	MinHoldTime     = 3
	MaxHoldTime     = 65535
	// MaxPeeringAnnounce is the most LAN subnets that a Node announces in its VRFs that peer by BGP,
	// which are some of its LAN subnets (MaxLANSubnets, topology.go). What the peers of the Node take
	// from it is those and its addresses, at most MaxAddresses: MaxPeeringAccept.
	MaxPeeringAnnounce = MaxLANSubnets
	MaxPeeringAccept   = MaxPeeringAnnounce + MaxAddresses
)

// Peering is how the Nodes of a VRF exchange their routes (VRF.Peering).
type Peering struct {
	// Protocol is bgp: the Nodes of the VRF peer by BGP in a full mesh. Left out, the Controller gives
	// each Node the routes of its peers.
	Protocol string `json:"protocol,omitempty"`
	// HoldTime is the BGP hold time of the sessions in seconds, from MinHoldTime to MaxHoldTime: a Node
	// that stops answering loses its routes at its peers after it. Left out, it is DefaultHoldTime.
	// Two Nodes that share several VRFs that peer by BGP take the shortest of them.
	HoldTime uint32 `json:"holdTime,omitempty"`
}

// PeeringVRFs returns the VRFs of the Node n whose Nodes peer by BGP.
func (in Intent) PeeringVRFs(n Node) []string {
	var out []string
	for _, v := range n.VRFs {
		if in.VRFs[v].Peering.Protocol == PeeringBGP {
			out = append(out, v)
		}
	}
	return out
}

// RouterID returns the BGP router id of a Node whose tunnel endpoint has the address vtep: that
// address when it is an IPv4 one, else the first 4 bytes of its SHA-256 (RFC 6286 takes any 4 bytes
// that are unique in the AS).
func RouterID(vtep netip.Addr) netip.Addr {
	if vtep.Is4() {
		return vtep
	}
	sum := sha256.Sum256(vtep.AsSlice())
	return netip.AddrFrom4([4]byte(sum[:4]))
}

// completePeering gives the peering of each VRF its one form: the protocol in lower case.
func (in Intent) completePeering() {
	for name, v := range in.VRFs {
		v.Peering.Protocol = strings.ToLower(v.Peering.Protocol)
		in.VRFs[name] = v
	}
}

// validatePeering checks the peering of a completed intent: the protocol of each VRF is bgp or none,
// a VRF that peers by BGP has a link of kind vxlan or geneve, is a full mesh, since its Nodes pass on
// nothing that they learned (topology.go), and has a hold time from MinHoldTime to MaxHoldTime or
// none, and a VRF that does not names no hold time. The Nodes of a VRF that peers by BGP have tunnel
// endpoints of one family (link.go checks that they have them), and each Node that peers has a router
// id of its own. A problem names the VRF or the Node and what is wrong.
func (in Intent) validatePeering() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		p := v.Peering
		switch {
		case p.Protocol == "":
			if p.HoldTime != 0 {
				problems = append(problems, fmt.Errorf("VRF %q: the peering holdTime %d needs the peering protocol %s", name, p.HoldTime, PeeringBGP))
			}
		case p.Protocol != PeeringBGP:
			problems = append(problems, fmt.Errorf("VRF %q: the peering protocol must be %s, not %q", name, PeeringBGP, p.Protocol))
		case !Plain(v.Link):
			problems = append(problems, fmt.Errorf("VRF %q: BGP peering needs a link of kind %s or %s, and the link is %s: the sessions run on the network that the operator trusts", name, LinkVXLAN, LinkGeneve, cmp.Or(v.Link, LinkNoise)))
		case v.HubAndSpoke():
			problems = append(problems, fmt.Errorf("VRF %q: BGP peering is a full mesh, and the topology is %s: a spoke would learn no route of another, since the hub passes on nothing that it learned", name, TopologyHubAndSpoke))
		case p.HoldTime != 0 && (p.HoldTime < MinHoldTime || p.HoldTime > MaxHoldTime):
			problems = append(problems, fmt.Errorf("VRF %q: the peering holdTime %d is not from %d to %d", name, p.HoldTime, MinHoldTime, MaxHoldTime))
		}
	}

	// One family of tunnel endpoints in each VRF that peers by BGP
	for _, vrf := range sortedNames(in.VRFs) {
		if in.VRFs[vrf].Peering.Protocol != PeeringBGP {
			continue
		}
		first := ""
		var first4 bool
		for _, name := range sortedNames(in.Nodes) {
			n := in.Nodes[name]
			a, err := ParseVTEPAddress(n.VTEP.Address)
			if err != nil || !slices.Contains(n.VRFs, vrf) {
				continue
			}
			if first == "" {
				first, first4 = name, a.Is4()
			} else if a.Is4() != first4 {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q peers by BGP, and the vtep address %s is not of the family of the one of Node %q", name, vrf, a, first))
			}
		}
	}

	ids := map[netip.Addr]string{}
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		vrfs := in.PeeringVRFs(n)
		a, err := ParseVTEPAddress(n.VTEP.Address)
		if len(vrfs) == 0 || err != nil {
			continue
		}
		id := RouterID(a)
		if other, ok := ids[id]; ok {
			problems = append(problems, fmt.Errorf("Node %q: its BGP router id %s, from its vtep address, is already the one of Node %q", name, id, other))
		} else {
			ids[id] = name
		}
	}
	return problems
}
