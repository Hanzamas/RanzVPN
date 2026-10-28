package intent

import (
	"fmt"
	"slices"
	"strconv"
)

// The security of an L2 Network (SDN-41 #234, ADR-0019 decision 1): the protections of the fork
// that #224 gives an L2 Network, which the switch of the Network applies to the frames of its
// clients on every Node of its VRF (src/Core/SwitchSecurity.h). The clients are every member of the
// Network but its gateways: the Nodes that Gateways names, behind which the real gateway of the
// Network is (its router, and the DHCP server of its LAN), and the Node that answers DHCP for the
// Network (dhcp.go). No protection holds for what a gateway sends, and under a check an address
// that a gateway sends from is its own before a client's, so no client can take it or keep it from
// the gateway. An L3 Network has none: it carries IP packets, which the policy of its VRF judges.

const (
	// DefaultSecurityMACs and DefaultSecurityIPs are the MAC and the IP addresses that a client
	// owns under checkMac and checkIp when the Network sets no limit: those of the node
	// (POLICY_DEFAULT_MACS and POLICY_DEFAULT_IPS of src/Core/Policy.h).
	DefaultSecurityMACs = 1
	DefaultSecurityIPs  = 8
	// MaxSecurityAddresses is the most addresses of each kind that a client owns (POLICY_MAX_BOUND).
	MaxSecurityAddresses = 64
	// MaxSecurityGateways is the most gateways of a Network, the Node that answers DHCP for it among
	// them: the L2Security message of the C node holds that many (control.options).
	MaxSecurityGateways = 8
)

// Security is the security of an L2 Network (Network.Security). A protection that is left out is
// off.
type Security struct {
	// CheckMAC: a client sends from MAC addresses of its own only, the first ones that it sends
	// from, up to MaxMACs, which no other member of the Network may send from (CheckMac of the fork).
	CheckMAC bool `json:"checkMac,omitempty"`
	// CheckIP: a client sends from IP addresses of its own only, as CheckMAC for MAC addresses, up to
	// MaxIPs; an ARP frame counts its sender (CheckIP). The unspecified address of DHCP and of
	// duplicate address detection is no one's.
	CheckIP bool `json:"checkIp,omitempty"`
	// MaxMACs is the most MAC addresses that a client owns under CheckMAC, from 1 to
	// MaxSecurityAddresses. Left out, it is DefaultSecurityMACs.
	MaxMACs uint32 `json:"maxMacs,omitempty"`
	// MaxIPs is the most IP addresses that a client owns under CheckIP, from 1 to
	// MaxSecurityAddresses. Left out, it is DefaultSecurityIPs.
	MaxIPs uint32 `json:"maxIps,omitempty"`
	// ARPDHCPOnly: the frames that a client sends to a group address, and those that it gets from
	// one, are ARP, DHCP, DHCPv6 and IPv6 neighbour discovery only, so other broadcasts stay out of
	// the overlay (ArpDhcpOnly).
	ARPDHCPOnly bool `json:"arpDhcpOnly,omitempty"`
	// DHCPGuard: a client sends no DHCP or DHCPv6 server message, so a rogue DHCP server is blocked
	// (DHCPNoServer).
	DHCPGuard bool `json:"dhcpGuard,omitempty"`
	// RAGuard: a client sends no IPv6 router advertisement, and still gets those of the gateways
	// (RAFilter).
	RAGuard bool `json:"raGuard,omitempty"`
	// Gateways are the Nodes of the VRF of the Network behind which its real gateway is, at most
	// MaxSecurityGateways with the Node that answers DHCP for it. Left out, that Node is the only one.
	Gateways []string `json:"gateways,omitempty"`
}

// On reports whether s turns a protection on.
func (s *Security) On() bool {
	return s != nil && (s.CheckMAC || s.CheckIP || s.ARPDHCPOnly || s.DHCPGuard || s.RAGuard)
}

// clone returns a copy of s that shares nothing with it.
func (s *Security) clone() *Security {
	if s == nil {
		return nil
	}
	c := *s
	c.Gateways = slices.Clone(s.Gateways)
	return &c
}

// SecurityGateways returns the gateways of the Network network in name order: the Nodes that its
// security names, and the Node that answers DHCP for it while its responder is on.
func (in Intent) SecurityGateways(network string) []string {
	n := in.Networks[network]
	var out []string
	if n.Security != nil {
		out = slices.Clone(n.Security.Gateways)
	}
	if d := n.DHCP; d != nil && d.Mode == DHCPPool && d.Node != "" && !slices.Contains(out, d.Node) {
		out = append(out, d.Node)
	}
	slices.Sort(out)
	return out
}

// completeSecurity fills in what the security of each Network leaves out: the limit of a check
// that is on, and the order of its gateways.
func (in Intent) completeSecurity() {
	for name, n := range in.Networks {
		s := n.Security
		if s == nil {
			continue
		}
		if s.CheckMAC && s.MaxMACs == 0 {
			s.MaxMACs = DefaultSecurityMACs
		}
		if s.CheckIP && s.MaxIPs == 0 {
			s.MaxIPs = DefaultSecurityIPs
		}
		slices.Sort(s.Gateways)
		in.Networks[name] = n
	}
}

// securityUsers returns the Networks of in whose security names the Node node as a gateway, each
// as Network "name": a Node that is a gateway of a Network cannot be deleted.
func (in Intent) securityUsers(node string) []string {
	var out []string
	for _, name := range sortedNames(in.Networks) {
		if s := in.Networks[name].Security; s != nil && slices.Contains(s.Gateways, node) {
			out = append(out, KindNetwork+" "+strconv.Quote(name))
		}
	}
	return out
}

// validateSecurity checks the security of each Network of a completed intent: it belongs to an
// L2 Network, each limit is within its bounds and of a check that is on, and its gateways are
// Nodes of the VRF of the Network, MaxSecurityGateways at most with the Node that answers DHCP.
func (in Intent) validateSecurity() []error {
	var problems []error
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		s := n.Security
		if s == nil {
			continue
		}
		bad := func(format string, args ...any) {
			problems = append(problems, fmt.Errorf("Network %q: security: %s", name, fmt.Sprintf(format, args...)))
		}
		if n.Mode != ModeL2 {
			bad("only an L2 Network has security: an L3 Network carries IP packets, which the policy of its VRF judges")
		}
		limit := func(field string, value uint32, check bool, flag string) {
			switch {
			case value != 0 && !check:
				bad("%s limits the addresses that a client owns under %s, which is off", field, flag)
			case value > MaxSecurityAddresses:
				bad("%s %d is not between 1 and %d", field, value, MaxSecurityAddresses)
			}
		}
		limit("maxMacs", s.MaxMACs, s.CheckMAC, "checkMac")
		limit("maxIps", s.MaxIPs, s.CheckIP, "checkIp")
		for i, g := range s.Gateways {
			node, ok := in.Nodes[g]
			switch {
			case !ok:
				bad("gateway %q is not a Node: a gateway is a Node of VRF %q", g, n.VRF)
			case !slices.Contains(node.VRFs, n.VRF):
				bad("gateway %q is not in VRF %q of the Network", g, n.VRF)
			}
			if i > 0 && s.Gateways[i-1] == g {
				bad("gateway %q is listed twice", g)
			}
		}
		if gateways := in.SecurityGateways(name); len(gateways) > MaxSecurityGateways {
			bad("%d gateways with the Node that answers DHCP, and a Network has at most %d", len(gateways), MaxSecurityGateways)
		}
	}
	return problems
}
