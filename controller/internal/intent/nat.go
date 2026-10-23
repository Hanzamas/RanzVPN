package intent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// 1:1 NAT and 4via6 (ADR-0025 decisions 4 and 5, SDN-6 #182). A NAT resource is one 1:1 NAT rule
// of a VRF, a first-class rule as a Policy is: the Node that applies it presents the inside
// prefix, the addresses that its host holds or the LAN behind it, in the VRF as the outside
// prefix of the same length, address for address. The node rewrites the addresses both ways in
// its data plane, the ones that an ICMP error quotes too, and the other nodes of the VRF route
// the outside prefix to it. 4via6 is the same rule between the two families, which the
// controller makes itself: a Node in two VRFs whose IPv4 ranges overlap reaches each of them
// through the 4via6 /64 of the ULA of that VRF (FourViaSix), the IPv4 address in the last 32
// bits (FourViaSixAddr), so 10.0.0.5 in one VRF and 10.0.0.5 in the other are two IPv6
// addresses on its host.

// KindNAT is the kind of a 1:1 NAT rule.
const KindNAT = "NAT"

// MaxNATRules is the most 1:1 NAT rules that one Node applies, its 4via6 rules among them: the
// NodeConfig message of the control protocol carries 16 (proto/ranz/control/v1/control.options).
const MaxNATRules = 16

// NAT is one 1:1 NAT rule of a VRF (ADR-0025 decision 5).
type NAT struct {
	VRF string `json:"vrf"`
	// Node is the Node that applies the rule, a member of the VRF: its host, or the LAN behind
	// it, holds the addresses of Inside.
	Node string `json:"node"`
	// Inside is the prefix as the host of the Node sees it.
	Inside string `json:"inside"`
	// Outside is the prefix as the VRF sees it, of the family and the length of Inside. No pool,
	// LAN subnet or other outside prefix of the VRF overlaps it.
	Outside string `json:"outside"`
}

// NATRule is a 1:1 NAT rule as a Node applies it (NATRules): a NAT resource that names the Node,
// or the 4via6 of one of its VRFs, from the 4via6 /96 of the VRF inside to 0.0.0.0/0 outside.
type NATRule struct {
	VRF     string
	Inside  netip.Prefix
	Outside netip.Prefix
}

// FourViaSixPrefix returns the /96 at the start of the 4via6 /64 of the ULA /48 ula (FourViaSix):
// an IPv4 address of the VRF fills its last 32 bits (ADR-0025 decision 4). It is the zero Prefix
// for anything but a /48 of IPv6.
func FourViaSixPrefix(ula netip.Prefix) netip.Prefix {
	p := FourViaSix(ula)
	if !p.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(p.Addr(), 96)
}

// FourViaSixAddr returns the 4via6 address of the IPv4 address a in the VRF of the ULA /48 ula:
// the /96 of FourViaSixPrefix with a in its last 32 bits. It is the zero Addr when ula is no /48
// of IPv6 or a is no IPv4 address.
func FourViaSixAddr(ula netip.Prefix, a netip.Addr) netip.Addr {
	p := FourViaSixPrefix(ula)
	if !p.IsValid() || !a.Is4() {
		return netip.Addr{}
	}
	b := p.Addr().As16()
	v4 := a.As4()
	copy(b[12:], v4[:])
	return netip.AddrFrom16(b)
}

// NATRules returns the 1:1 NAT rules that each Node of in applies, by Node name: the NAT resources
// that name it, and the 4via6 of each of its VRFs whose IPv4 ranges overlap those of another of
// its VRFs. The rules of a Node are ordered by VRF name, then inside prefix; a Node without one
// has no entry. A rule whose prefixes do not parse is left out: in is an intent that Apply
// returned.
func (in Intent) NATRules() map[string][]NATRule {
	out := map[string][]NATRule{}
	for _, name := range sortedNames(in.NATs) {
		r := in.NATs[name]
		inside, err := parseNATPrefix(r.Inside)
		outside, err2 := parseNATPrefix(r.Outside)
		if _, ok := in.Nodes[r.Node]; ok && err == nil && err2 == nil {
			out[r.Node] = append(out[r.Node], NATRule{VRF: r.VRF, Inside: inside, Outside: outside})
		}
	}
	for node, vrfs := range in.fourViaSixVRFs() {
		for _, vrf := range vrfs {
			if ula, err := ParseULA(in.VRFs[vrf].ULA); err == nil {
				out[node] = append(out[node], NATRule{VRF: vrf, Inside: FourViaSixPrefix(ula), Outside: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
			}
		}
	}
	for _, rules := range out {
		slices.SortFunc(rules, func(a, b NATRule) int {
			return cmp.Or(cmp.Compare(a.VRF, b.VRF), a.Inside.Addr().Compare(b.Inside.Addr()), cmp.Compare(a.Inside.Bits(), b.Inside.Bits()))
		})
	}
	return out
}

// fourViaSixVRFs returns, by Node name, the VRFs of each Node whose IPv4 ranges overlap the IPv4
// ranges of another of its VRFs, in name order: the host of the Node reaches them through 4via6.
// A Node without one has no entry.
func (in Intent) fourViaSixVRFs() map[string][]string {
	ranges := in.ipv4Ranges()
	out := map[string][]string{}
	for _, node := range sortedNames(in.Nodes) {
		vrfs := in.Nodes[node].VRFs
		for _, v := range vrfs {
			overlaps := slices.ContainsFunc(vrfs, func(w string) bool { return w != v && overlapping(ranges[v], ranges[w]) })
			if overlaps && !slices.Contains(out[node], v) {
				out[node] = append(out[node], v)
			}
		}
		slices.Sort(out[node])
	}
	return out
}

// ipv4Ranges returns the IPv4 ranges of each VRF, by VRF name: the IPv4 pools of its Networks, the
// LAN subnets that Nodes advertise in it and the outside prefixes of its 1:1 NAT rules.
func (in Intent) ipv4Ranges() map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		if p, err := ParsePool(n.IPv4Pool, 4); err == nil {
			out[n.VRF] = append(out[n.VRF], p)
		}
	}
	for _, r := range in.Routes() {
		if r.Prefix.Addr().Is4() {
			out[r.VRF] = append(out[r.VRF], r.Prefix)
		}
	}
	for _, name := range sortedNames(in.NATs) {
		r := in.NATs[name]
		if p, err := parseNATPrefix(r.Outside); err == nil && p.Addr().Is4() {
			out[r.VRF] = append(out[r.VRF], p)
		}
	}
	return out
}

// overlapping reports whether a prefix of a overlaps a prefix of b.
func overlapping(a, b []netip.Prefix) bool {
	for _, p := range a {
		if slices.ContainsFunc(b, p.Overlaps) {
			return true
		}
	}
	return false
}

// parseNATPrefix parses the inside or the outside prefix of a 1:1 NAT rule: an IPv4 or an IPv6
// prefix with no host bits set, which is not the default route.
func parseNATPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	switch {
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix", s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("%q has host bits set, the prefix is %s", s, p.Masked())
	case p.Bits() == 0:
		return netip.Prefix{}, fmt.Errorf("%q is the default route: a 1:1 NAT rule maps a prefix of the VRF", s)
	}
	return p, nil
}

// completeNAT writes the prefixes of each 1:1 NAT rule of in in their one form. A prefix that does
// not parse stays as it is, for validate to refuse.
func (in Intent) completeNAT() {
	for name, r := range in.NATs {
		if p, err := netip.ParsePrefix(r.Inside); err == nil {
			r.Inside = p.String()
		}
		if p, err := netip.ParsePrefix(r.Outside); err == nil {
			r.Outside = p.String()
		}
		in.NATs[name] = r
	}
}

// natUsers returns the 1:1 NAT rules of in that the VRF vrf or the Node node is used by, each as
// its kind and quoted name, in name order. An empty vrf or node matches no rule.
func (in Intent) natUsers(vrf, node string) []string {
	var out []string
	for _, name := range sortedNames(in.NATs) {
		r := in.NATs[name]
		if (vrf != "" && r.VRF == vrf) || (node != "" && r.Node == node) {
			out = append(out, KindNAT+" "+strconv.Quote(name))
		}
	}
	return out
}

// natPrefixes is a 1:1 NAT rule whose prefixes parse (validateNAT).
type natPrefixes struct {
	name            string
	node            string
	inside, outside netip.Prefix
}

// validateNAT checks the 1:1 NAT rules of a completed intent: each names a VRF and a Node that is
// a member of it and maps two prefixes of one family and length, its outside prefix overlaps no
// pool, LAN subnet, 4via6 /64 or outside prefix of another rule of the VRF, and the prefixes of
// two rules of one Node in one VRF do not overlap. No Node applies more than MaxNATRules rules
// with its 4via6.
func (in Intent) validateNAT() []error {
	var problems []error
	routes := in.Routes()
	byVRF := map[string][]natPrefixes{}
	for _, name := range sortedNames(in.NATs) {
		r := in.NATs[name]
		v, vrfOK := in.VRFs[r.VRF]
		if !vrfOK {
			problems = append(problems, fmt.Errorf("NAT %q: VRF %q does not exist", name, r.VRF))
		}
		if n, ok := in.Nodes[r.Node]; !ok {
			problems = append(problems, fmt.Errorf("NAT %q: Node %q does not exist", name, r.Node))
		} else if vrfOK && !slices.Contains(n.VRFs, r.VRF) {
			problems = append(problems, fmt.Errorf("NAT %q: Node %q is not a member of VRF %q", name, r.Node, r.VRF))
		}
		inside, err := parseNATPrefix(r.Inside)
		if err != nil {
			problems = append(problems, fmt.Errorf("NAT %q: inside: %w", name, err))
		}
		outside, err2 := parseNATPrefix(r.Outside)
		if err2 != nil {
			problems = append(problems, fmt.Errorf("NAT %q: outside: %w", name, err2))
		}
		if err != nil || err2 != nil {
			continue
		}
		if inside.Addr().Is4() != outside.Addr().Is4() || inside.Bits() != outside.Bits() {
			problems = append(problems, fmt.Errorf("NAT %q: the inside %s and the outside %s are not of one family and length: a 1:1 NAT rule maps one address to one", name, inside, outside))
			continue
		}
		if inside == outside {
			problems = append(problems, fmt.Errorf("NAT %q: the inside and the outside are the same prefix %s", name, inside))
			continue
		}
		for _, network := range sortedNames(in.Networks) {
			if in.Networks[network].VRF != r.VRF {
				continue
			}
			for _, p := range in.poolsOf(network) {
				if p.Overlaps(outside) {
					problems = append(problems, fmt.Errorf("NAT %q: the outside %s overlaps the pool %s of Network %q: an address names one holder in a VRF", name, outside, p, network))
				}
			}
		}
		for _, rt := range routes {
			if rt.VRF == r.VRF && rt.Prefix.Overlaps(outside) {
				problems = append(problems, fmt.Errorf("NAT %q: the outside %s overlaps the LAN subnet %s that Node %q advertises in VRF %q", name, outside, rt.Prefix, rt.Via, r.VRF))
			}
		}
		if ula, err := ParseULA(v.ULA); vrfOK && err == nil && outside.Overlaps(FourViaSix(ula)) {
			problems = append(problems, fmt.Errorf("NAT %q: the outside %s overlaps %s, the /64 of the ULA of VRF %q that 4via6 reserves", name, outside, FourViaSix(ula), r.VRF))
		}
		byVRF[r.VRF] = append(byVRF[r.VRF], natPrefixes{name: name, node: r.Node, inside: inside, outside: outside})
	}
	for _, vrf := range sortedNames(byVRF) {
		rules := byVRF[vrf]
		for i, a := range rules {
			for _, b := range rules[i+1:] {
				switch {
				case a.outside.Overlaps(b.outside):
					problems = append(problems, fmt.Errorf("NAT %q: the outside %s overlaps the outside %s of NAT %q in VRF %q: an address names one holder in a VRF", a.name, a.outside, b.outside, b.name, vrf))
				case a.node == b.node && a.inside.Overlaps(b.inside):
					problems = append(problems, fmt.Errorf("NAT %q: the inside %s overlaps the inside %s of NAT %q, a rule of Node %q in VRF %q too", a.name, a.inside, b.inside, b.name, a.node, vrf))
				case a.node == b.node && (a.inside.Overlaps(b.outside) || a.outside.Overlaps(b.inside)):
					problems = append(problems, fmt.Errorf("NAT %q: its prefixes %s and %s overlap the prefixes %s and %s of NAT %q, a rule of Node %q in VRF %q too", a.name, a.inside, a.outside, b.inside, b.outside, b.name, a.node, vrf))
				}
			}
		}
	}
	all := in.NATRules()
	for _, node := range sortedNames(all) {
		if got := len(all[node]); got > MaxNATRules {
			problems = append(problems, fmt.Errorf("Node %q: %d 1:1 NAT rules with the 4via6 of its VRFs, and the control protocol carries at most %d", node, got, MaxNATRules))
		}
	}
	return problems
}
