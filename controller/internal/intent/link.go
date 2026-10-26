package intent

import (
	"fmt"
	"net/netip"
	"strings"
)

// The kind of the links between the Nodes of a VRF (SDN-76 #356) is the Link of the VRF. A link of
// kind noise is the Noise session over QUIC or TLS 443, for any underlay. A link of kind vxlan or
// geneve carries the packets of the VRF in plain VXLAN (RFC 7348) or Geneve (RFC 8926) between the
// tunnel endpoints of two Nodes that reach each other on a network that the operator trusts: a LAN,
// an intranet, a data center or a private WAN. Such a link is plain by decision of the maintainer
// (2026-10-24), with no Noise and no IPsec of the product; the operator may put IPsec or MACsec under
// it. The only guard is configuration: a Node takes the datagrams of such a link only from the tunnel
// endpoint of a Node of the VRF that the Controller named, and only on the VNI of the VRF, so every
// Node of the VRF needs a tunnel endpoint (Node.vtep), no two of them share an address, and no two
// such VRFs share a VNI. The Controller gives each Node its peers, the VNI of each VRF and the flood
// list, as it gives the Noise peers (desired/link.go); the policy, the forwarding tables and the VRF
// adapters of the Node see no difference.

// The kinds of a link.
const (
	LinkNoise  = "noise"
	LinkVXLAN  = "vxlan"
	LinkGeneve = "geneve"
)

// GenevePort is the UDP port of Geneve (RFC 8926 section 3.3), as VXLANPort is that of VXLAN (mirror.go).
const GenevePort = 6081

// VTEP is the tunnel endpoint of a Node for the links of kind vxlan and geneve.
type VTEP struct {
	// Address is the IP address of the Node on the network that the operator trusts, under which the
	// other Nodes of its VRFs reach it.
	Address string `json:"address"`
	// VXLANPort and GenevePort are the UDP ports that the Node listens on for each encapsulation.
	// Left out, they are 4789 and 6081 (IANA).
	VXLANPort  uint32 `json:"vxlanPort,omitempty"`
	GenevePort uint32 `json:"genevePort,omitempty"`
}

// Plain reports whether kind is a link of kind vxlan or geneve, which no Noise session carries.
func Plain(kind string) bool {
	return kind == LinkVXLAN || kind == LinkGeneve
}

// ParseVTEPAddress parses the address of a tunnel endpoint: an IP address of one Node, without a zone
// and not the unspecified or a multicast address. An IPv4-mapped IPv6 address is taken as the IPv4
// address.
func ParseVTEPAddress(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("vtep address %q is not an IP address", s)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("vtep address %q has a zone, which only its own host can use", s)
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("vtep address %q is not the address of one Node", s)
	}
	return a, nil
}

// completeLinks gives the links their one form: the kind in lower case, the VNI of a link of kind
// vxlan or geneve that names none the id of its VRF, and the address of a tunnel endpoint in the
// form of netip.Addr.String. A kind or an address that does not parse stays as it is, for
// validateLinks to refuse.
func (in Intent) completeLinks() {
	for name, v := range in.VRFs {
		v.Link = strings.ToLower(v.Link)
		if Plain(v.Link) && v.VNI == 0 {
			v.VNI = v.ID
		}
		in.VRFs[name] = v
	}
	for name, n := range in.Nodes {
		if a, err := ParseVTEPAddress(n.VTEP.Address); err == nil {
			n.VTEP.Address = a.String()
			in.Nodes[name] = n
		}
	}
}

// PlainVRFs returns the VRFs of the Node n whose link is of kind vxlan or geneve.
func (in Intent) PlainVRFs(n Node) []string {
	var out []string
	for _, v := range n.VRFs {
		if Plain(in.VRFs[v].Link) {
			out = append(out, v)
		}
	}
	return out
}

// validateLinks checks the links of a completed intent: the kind of each VRF is noise, vxlan or
// geneve; a VRF of kind vxlan or geneve has a VNI from 1 to MaxVNI that no other such VRF has, and a
// VRF of kind noise names none; every Node of a VRF of kind vxlan or geneve has a tunnel endpoint; and
// a tunnel endpoint has an address that ParseVTEPAddress takes and that no other Node has, and two
// ports from 1 to 65535 that are not the same. A problem names the VRF or the Node and what is wrong.
func (in Intent) validateLinks() []error {
	var problems []error
	vnis := map[uint32]string{}
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		switch {
		case v.Link == "" || v.Link == LinkNoise:
			if v.VNI != 0 {
				problems = append(problems, fmt.Errorf("VRF %q: vni %d needs a link of kind %s or %s, and the link is %s", name, v.VNI, LinkVXLAN, LinkGeneve, LinkNoise))
			}
		case Plain(v.Link):
			if v.VNI == 0 || v.VNI > MaxVNI {
				problems = append(problems, fmt.Errorf("VRF %q: vni %d is not from 1 to %d: give the VRF a vni, since its id does not fit 24 bits", name, v.VNI, MaxVNI))
			} else if other, ok := vnis[v.VNI]; ok {
				problems = append(problems, fmt.Errorf("VRF %q: vni %d is already the vni of VRF %q", name, v.VNI, other))
			} else {
				vnis[v.VNI] = name
			}
		default:
			problems = append(problems, fmt.Errorf("VRF %q: the link must be %s, %s or %s, not %q", name, LinkNoise, LinkVXLAN, LinkGeneve, v.Link))
		}
	}
	addresses := map[netip.Addr]string{}
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		t := n.VTEP
		if t == (VTEP{}) {
			if plain := in.PlainVRFs(n); len(plain) > 0 {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q has a link of kind %s, and the Node has no vtep: give it its address on the network that the operator trusts", name, plain[0], in.VRFs[plain[0]].Link))
			}
			continue
		}
		if a, err := ParseVTEPAddress(t.Address); err != nil {
			problems = append(problems, fmt.Errorf("Node %q: %w", name, err))
		} else if other, ok := addresses[a]; ok {
			problems = append(problems, fmt.Errorf("Node %q: vtep address %s is already the vtep address of Node %q", name, a, other))
		} else {
			addresses[a] = name
		}
		if vxlan, geneve := t.Ports(); t.VXLANPort > 65535 || t.GenevePort > 65535 {
			problems = append(problems, fmt.Errorf("Node %q: the vtep ports %d and %d must be from 1 to 65535 (0 for the default)", name, t.VXLANPort, t.GenevePort))
		} else if vxlan == geneve {
			problems = append(problems, fmt.Errorf("Node %q: the vtep has the port %d for both VXLAN and Geneve", name, vxlan))
		}
	}
	return problems
}

// Ports returns the UDP ports of VXLAN and of Geneve of the tunnel endpoint t: VXLANPort and GenevePort
// for the ones that it names none of.
func (t VTEP) Ports() (vxlan, geneve uint32) {
	vxlan, geneve = t.VXLANPort, t.GenevePort
	if vxlan == 0 {
		vxlan = VXLANPort
	}
	if geneve == 0 {
		geneve = GenevePort
	}
	return vxlan, geneve
}
