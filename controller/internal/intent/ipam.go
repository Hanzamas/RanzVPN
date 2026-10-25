package intent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// IPAM (ADR-0028, SDN-10 #186): the rules that the pools, the reservations and the LAN subnets of
// the intent obey, how full a pool is, and the routes. address.go allocates the addresses of the
// Nodes by them.
//
// The controller alone owns the addresses of the overlay, and no DHCP runs inside it. A Network
// has an IPv4 pool and an IPv6 pool. The IPv6 pool lies in the ULA /48 of its VRF, so IPv6 inside a
// VRF is unique by construction, and outside the /64 that 4via6 reserves (FourViaSix). The pools
// of one VRF do not overlap, so an address names one holder in a VRF; two VRFs may use the same
// range. A Network reserves addresses (Network.Reserved) that no Node is given. The LAN subnets
// behind a gateway Node (Node.LANSubnets) are routes that the gateway advertises in a VRF, never
// allocations: no pool of that VRF may cover one, so the existing LANs keep their addresses.

const (
	// DefaultPoolThreshold is the percentage of a pool in use at which the controller raises the
	// pool event, for a Network that sets no PoolThreshold (ADR-0030 decision 5).
	DefaultPoolThreshold = 80
	// MaxAddresses is the most addresses that one Node holds in all its Networks together: the
	// NodeConfig and Peer messages of the control protocol carry 16
	// (proto/ranz/control/v1/control.options).
	MaxAddresses = 16
	// MaxPoolSize is the largest size that PoolUse reports. A pool of more addresses reports this
	// size, which JSON holds exactly; no fleet comes near it.
	MaxPoolSize = 1 << 53
)

// Route is a prefix that a gateway Node advertises in a VRF: a LAN subnet behind the Node
// (Node.LANSubnets). The routes are made from the Nodes, and nothing is allocated from one.
type Route struct {
	// VRF is the VRF that the route is in.
	VRF string `json:"vrf"`
	// Prefix is the LAN subnet.
	Prefix netip.Prefix `json:"prefix"`
	// Via is the gateway Node that advertises it.
	Via string `json:"via"`
}

// PoolUse is how full one pool of a Network is. An address of the pool is in use when a Node holds
// it or the Network reserves it.
type PoolUse struct {
	// Network is the Network that has the pool.
	Network string `json:"network"`
	// VRF is the VRF of the Network.
	VRF string `json:"vrf"`
	// Pool is the pool, an IPv4 or an IPv6 prefix.
	Pool netip.Prefix `json:"pool"`
	// Size is the number of host addresses of the pool, at most MaxPoolSize.
	Size uint64 `json:"size"`
	// Allocated is the number of them that Nodes hold.
	Allocated uint64 `json:"allocated"`
	// Reserved is the number of them that the Network reserves.
	Reserved uint64 `json:"reserved"`
	// Free is the number of them that are neither.
	Free uint64 `json:"free"`
	// Percent is the share of the pool that is in use, rounded down.
	Percent uint64 `json:"percent"`
	// Threshold is the percentage of the pool in use at which the pool event fires.
	Threshold uint32 `json:"threshold"`
	// NearExhaustion says that the pool is in use at or above its Threshold.
	NearExhaustion bool `json:"nearExhaustion"`
}

// FourViaSix returns the /64 of the ULA /48 ula that 4via6 reserves (ADR-0025 decision 4): the
// last one, so the pools that an operator carves from the start of the ULA never meet it. It is
// the zero Prefix for anything but a /48 of IPv6.
func FourViaSix(ula netip.Prefix) netip.Prefix {
	if !ula.IsValid() || !ula.Addr().Is6() || ula.Addr().Is4In6() || ula.Bits() != 48 {
		return netip.Prefix{}
	}
	a := ula.Masked().Addr().As16()
	a[6], a[7] = 0xff, 0xff
	return netip.PrefixFrom(netip.AddrFrom16(a), 64)
}

// Routes returns the routes that the LAN subnets of the Nodes make, ordered by VRF, prefix and
// gateway Node. Two gateways that advertise the same prefix make two routes (ADR-0025 decision
// 12).
func (in Intent) Routes() []Route {
	out := []Route{}
	for _, name := range sortedNames(in.Nodes) {
		lans := in.Nodes[name].LANSubnets
		for _, vrf := range sortedNames(lans) {
			for _, s := range lans[vrf] {
				if p, err := parseLAN(s); err == nil {
					out = append(out, Route{VRF: vrf, Prefix: p, Via: name})
				}
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Route) int {
		return cmp.Or(cmp.Compare(a.VRF, b.VRF), a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()),
			cmp.Compare(a.Via, b.Via))
	})
	return out
}

// Pools returns how full each pool of each Network is, the Networks in name order, each with its
// IPv4 pool and then its IPv6 pool.
func (in Intent) Pools() []PoolUse {
	out := []PoolUse{}
	index := map[string]int{} // the place in out of a pool, by Network name and family
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		for _, p := range in.poolsOf(name) {
			u := PoolUse{Network: name, VRF: n.VRF, Pool: p, Size: hostsIn(p, p), Threshold: cmp.Or(n.PoolThreshold, DefaultPoolThreshold)}
			u.Reserved = reservedCount(p, in.reservedIn(name, p))
			index[name+" "+familyOf(p).String()] = len(out)
			out = append(out, u)
		}
	}
	for _, n := range in.Nodes {
		for _, f := range []addrFamily{family4, family6} {
			for network, s := range f.held(n) {
				i, ok := index[network+" "+f.String()]
				a, err := netip.ParseAddr(s)
				if ok && err == nil && slices.Contains(n.VRFs, out[i].VRF) && hostAddress(out[i].Pool, a) {
					out[i].Allocated++
				}
			}
		}
	}
	// A Device holds its addresses as a Node does (device.go)
	in.countDevices(out, index)
	for i := range out {
		u := &out[i]
		used := min(u.Allocated+u.Reserved, u.Size)
		u.Free = u.Size - used
		// The size of a pool is at least 1, so these divide by more than 0
		u.Percent = used * 100 / u.Size
		u.NearExhaustion = used*100 >= uint64(u.Threshold)*u.Size
	}
	return out
}

// poolsOf returns the pools of the Network name that parse: its IPv4 pool, then its IPv6 pool,
// each left out when the Network has none.
func (in Intent) poolsOf(name string) []netip.Prefix {
	n := in.Networks[name]
	var out []netip.Prefix
	if p, err := ParsePool(n.IPv4Pool, 4); err == nil {
		out = append(out, p)
	}
	if p, err := ParsePool(n.IPv6Pool, 6); err == nil {
		out = append(out, p)
	}
	return out
}

// reservedIn returns the reservations of the Network name that parse and lie in pool.
func (in Intent) reservedIn(name string, pool netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range in.Networks[name].Reserved {
		if p, err := parseReserved(s); err == nil && inside(pool, p) {
			out = append(out, p)
		}
	}
	return out
}

// hostsIn returns the number of host addresses of pool that lie in p, a prefix of pool, at most
// MaxPoolSize. The addresses that are no host's (nonHost) do not count.
func hostsIn(pool, p netip.Prefix) uint64 {
	h := p.Addr().BitLen() - p.Bits()
	if h >= 53 {
		return MaxPoolSize
	}
	n := uint64(1) << h
	for _, a := range nonHost(pool) {
		if p.Contains(a) {
			n--
		}
	}
	return n
}

// reservedCount returns the number of host addresses of pool that the prefixes reserved cover, at
// most MaxPoolSize. A prefix inside another counts once, and so does a prefix that is listed twice.
func reservedCount(pool netip.Prefix, reserved []netip.Prefix) uint64 {
	var n uint64
	for i, p := range reserved {
		covered := false
		for j, o := range reserved {
			if i != j && inside(o, p) && (o != p || j < i) {
				covered = true
			}
		}
		if !covered {
			n = min(n+hostsIn(pool, p), MaxPoolSize)
		}
	}
	return n
}

// nonHost returns the addresses of pool that no Node is given because they are no host's: for
// IPv4 the first and the last, which name the network and its broadcast; for IPv6 the first, the
// Subnet-Router anycast address (RFC 4291). A pool of no more than two addresses has none.
func nonHost(pool netip.Prefix) []netip.Addr {
	switch {
	case pool.Addr().Is4() && pool.Bits() < 31:
		return []netip.Addr{pool.Addr(), lastAddr(pool)}
	case pool.Addr().Is6() && pool.Bits() < 127:
		return []netip.Addr{pool.Addr()}
	}
	return nil
}

// lastAddr returns the last address of the prefix p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		bits := p.Bits() - 8*i
		switch {
		case bits <= 0:
			b[i] = 0xff
		case bits < 8:
			b[i] |= 0xff >> bits
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// inside reports whether the prefix p lies inside the prefix outer.
func inside(outer, p netip.Prefix) bool {
	return p.Bits() >= outer.Bits() && outer.Contains(p.Addr())
}

// within reports whether the address a lies in one of prefixes.
func within(prefixes []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
}

// after returns the address that follows a, past the reserved prefix that holds a: the allocation
// steps over a reservation in one move, whatever its size.
func after(reserved []netip.Prefix, a netip.Addr) netip.Addr {
	for _, p := range reserved {
		if p.Contains(a) {
			return lastAddr(p).Next()
		}
	}
	return a.Next()
}

// parseLAN parses a LAN subnet of a Node: an IPv4 or an IPv6 prefix with no host bits set, which
// is not the default route.
func parseLAN(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("LAN subnet: %w", err)
	}
	switch {
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("LAN subnet %q is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix", s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("LAN subnet %q has host bits set, the prefix is %s", s, p.Masked())
	case p.Bits() == 0:
		return netip.Prefix{}, fmt.Errorf("LAN subnet %q is the default route, which is no LAN", s)
	}
	return p, nil
}

// parseReserved parses an entry of Network.Reserved: a prefix with no host bits set, or one
// address, which is the prefix of all its bits.
func parseReserved(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("reserved: %w", err)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("reserved: %w", err)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("reserved %q has host bits set, the prefix is %s", s, p.Masked())
	}
	return p, nil
}

// canonicalReserved returns the reservations rs in their one form: each as a prefix, in order. An
// entry that does not parse stays as it is, for validate to refuse.
func canonicalReserved(rs []string) []string {
	if len(rs) == 0 {
		return nil
	}
	out := make([]string, len(rs))
	for i, s := range rs {
		if p, err := parseReserved(s); err == nil {
			s = p.String()
		}
		out[i] = s
	}
	slices.Sort(out)
	return out
}

// canonicalLANs returns the LAN subnets lans of a Node in their one form: each as a prefix, in
// order, and no VRF without one. An entry that does not parse stays as it is, for validate to
// refuse.
func canonicalLANs(lans map[string][]string) map[string][]string {
	var out map[string][]string
	for vrf, ss := range lans {
		if len(ss) == 0 {
			continue
		}
		list := make([]string, len(ss))
		for i, s := range ss {
			if p, err := parseLAN(s); err == nil {
				s = p.String()
			}
			list[i] = s
		}
		slices.Sort(list)
		if out == nil {
			out = map[string][]string{}
		}
		out[vrf] = list
	}
	return out
}

// cloneLANs returns a copy of lans that shares nothing with it.
func cloneLANs(lans map[string][]string) map[string][]string {
	if lans == nil {
		return nil
	}
	out := make(map[string][]string, len(lans))
	for vrf, ss := range lans {
		out[vrf] = slices.Clone(ss)
	}
	return out
}

// validateIPAM checks the pools, the reservations and the LAN subnets of a completed intent, and
// the number of addresses of each Node.
func (in Intent) validateIPAM() []error {
	var problems []error
	type poolOf struct {
		network string
		pool    netip.Prefix
	}
	pools := map[string][]poolOf{} // the pools of the Networks of each VRF
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		mine := in.poolsOf(name)
		for _, p := range mine {
			pools[n.VRF] = append(pools[n.VRF], poolOf{name, p})
		}
		if n.PoolThreshold > 100 {
			problems = append(problems, fmt.Errorf("Network %q: poolThreshold %d is not between 1 and 100 (0 is the default, %d)", name, n.PoolThreshold, DefaultPoolThreshold))
		}
		for i, s := range n.Reserved {
			p, err := parseReserved(s)
			switch {
			case err != nil:
				problems = append(problems, fmt.Errorf("Network %q: %w", name, err))
			case !slices.ContainsFunc(mine, func(pool netip.Prefix) bool { return inside(pool, p) }):
				problems = append(problems, fmt.Errorf("Network %q: reserved %s is inside none of the pools of the Network", name, p))
			case i > 0 && n.Reserved[i-1] == s:
				problems = append(problems, fmt.Errorf("Network %q: reserved %s is listed twice", name, p))
			}
		}
		v, ok := in.VRFs[n.VRF]
		if !ok {
			continue
		}
		ula, err := ParseULA(v.ULA)
		if err != nil {
			continue
		}
		for _, p := range mine {
			if !p.Addr().Is6() {
				continue
			}
			switch {
			case !inside(ula, p):
				problems = append(problems, fmt.Errorf("Network %q: ipv6Pool %s is not inside the ULA %s of VRF %q: the IPv6 addresses of a VRF are in its ULA", name, p, ula, n.VRF))
			case p.Overlaps(FourViaSix(ula)):
				problems = append(problems, fmt.Errorf("Network %q: ipv6Pool %s overlaps %s, the /64 of the ULA of VRF %q that 4via6 reserves", name, p, FourViaSix(ula), n.VRF))
			}
		}
	}
	for _, vrf := range sortedNames(pools) {
		refs := pools[vrf]
		for i, a := range refs {
			for _, b := range refs[i+1:] {
				if a.pool.Overlaps(b.pool) {
					problems = append(problems, fmt.Errorf("Network %q: the pool %s overlaps the pool %s of Network %q in VRF %q: an address names one holder in a VRF, so its pools do not overlap", a.network, a.pool, b.pool, b.network, vrf))
				}
			}
		}
	}
	for _, r := range in.Routes() {
		for _, ref := range pools[r.VRF] {
			if ref.pool.Overlaps(r.Prefix) {
				problems = append(problems, fmt.Errorf("Network %q: the pool %s overlaps the LAN subnet %s that Node %q advertises in VRF %q: a LAN subnet is a route and never an allocation, so no pool covers one", ref.network, ref.pool, r.Prefix, r.Via, r.VRF))
			}
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		for _, vrf := range sortedNames(n.LANSubnets) {
			if !slices.Contains(n.VRFs, vrf) {
				problems = append(problems, fmt.Errorf("Node %q: lanSubnets: VRF %q is not a VRF of the node", name, vrf))
			}
			for i, s := range n.LANSubnets[vrf] {
				if p, err := parseLAN(s); err != nil {
					problems = append(problems, fmt.Errorf("Node %q: lanSubnets of VRF %q: %w", name, vrf, err))
				} else if i > 0 && n.LANSubnets[vrf][i-1] == s {
					problems = append(problems, fmt.Errorf("Node %q: LAN subnet %s of VRF %q is listed twice", name, p, vrf))
				}
			}
		}
		if got := len(n.Addresses) + len(n.IPv6Addresses); got > MaxAddresses {
			problems = append(problems, fmt.Errorf("Node %q: %d addresses in its Networks, and the control protocol carries at most %d", name, got, MaxAddresses))
		}
	}
	return problems
}
