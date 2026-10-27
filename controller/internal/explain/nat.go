package explain

import (
	"net/netip"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// 1:1 NAT and 4via6 as the data plane of a Node applies them (src/Cedar/NodeNat.c). A rule of a VRF maps each address
// of its inside prefix to the address of its outside prefix with the same host bits: out of the host into the overlay
// from inside to outside, in from the overlay to the host the other way. The 4via6 of a VRF is the rule between the
// families, an IPv6 /96 inside and the IPv4 0.0.0.0/0 outside. On the way out the 4via6 goes first and the rules of
// one family after it, on the way in the other way round; of each kind the first rule in the order of the state that
// holds the address maps it.

// natRule is a 1:1 NAT rule that a Node applies.
type natRule struct {
	vrf     uint32
	family  bool // the 4via6 of the VRF: IPv6 inside, IPv4 outside
	inside  netip.Prefix
	outside netip.Prefix
}

// natRules returns the rules of a NodeConfig that the Node applies: a rule whose prefixes are not of as many host
// bits is left out, and so is one of two families but for IPv6 inside and IPv4 outside (NodeNatRule).
func natRules(list []*controlpb.Nat) []natRule {
	var out []natRule
	for _, c := range list {
		in, ok := prefixOf(c.GetInside())
		o, ok2 := prefixOf(c.GetOutside())
		if !ok || !ok2 || in.Addr().BitLen()-in.Bits() != o.Addr().BitLen()-o.Bits() {
			continue
		}
		family := in.Addr().BitLen() != o.Addr().BitLen()
		if family && in.Addr().BitLen() != 128 {
			continue
		}
		out = append(out, natRule{vrf: c.GetVrfId(), family: family, inside: in, outside: o})
	}
	return out
}

// apply returns the address a of the prefix that r maps from, out of the host or in to it, as the other side sees it:
// the prefix of that side with the host bits of a.
func (r natRule) apply(a netip.Addr, out bool) netip.Addr {
	from, to := r.outside, r.inside
	if out {
		from, to = r.inside, r.outside
	}
	host := from.Addr().BitLen() - from.Bits()
	src := a.AsSlice()
	dst := to.Masked().Addr().AsSlice()
	for i := 0; i < host/8; i++ {
		dst[len(dst)-1-i] = src[len(src)-1-i]
	}
	if bits := host % 8; bits != 0 {
		k := host / 8
		dst[len(dst)-1-k] |= src[len(src)-1-k] & byte(1<<bits-1)
	}
	b, _ := netip.AddrFromSlice(dst)
	return b
}

// holds reports whether r maps the address a, out of the host or in to it.
func (r natRule) holds(a netip.Addr, out bool) bool {
	from := r.outside
	if out {
		from = r.inside
	}
	return from.Addr().BitLen() == a.BitLen() && from.Contains(a)
}

// mapAddr returns the address a of a packet of the VRF vrf of n as the other side sees it, out of the host or in to
// it, through the stage of the 4via6 and the stage of the rules of one family, and the rules that mapped it, in order.
func (n *node) mapAddr(vrf uint32, a netip.Addr, out bool) (netip.Addr, []natRule) {
	var used []natRule
	// Out: the 4via6 first; in: the rules of one family first
	for _, family := range []bool{out, !out} {
		for _, r := range n.nat {
			if r.vrf == vrf && r.family == family && r.holds(a, out) {
				a = r.apply(a, out)
				used = append(used, r)
				break
			}
		}
	}
	return a, used
}
