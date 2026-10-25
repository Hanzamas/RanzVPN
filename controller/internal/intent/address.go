package intent

import (
	"fmt"
	"net/netip"
	"slices"
)

// The addresses of the Nodes (ADR-0028, SDN-3 #179, SDN-10 #186). The controller alone allocates
// them, from the IPv4 pool and the IPv6 pool of each L3 Network: a Node holds one address of each
// family in every such Network of its VRFs, and no DHCP runs inside the overlay. The address of a
// Node in a Network is the one the Node declares (a reservation), else the one it held before,
// else the lowest free host address of the pool, and it stays the Node's while the Node is in that
// Network. An address that the Network reserves is never allocated (ipam.go), and neither is any
// address of a LAN subnet behind a gateway: no pool covers one.

// addrFamily is the address family of a pool and of the addresses held in it: the one thing that
// the allocation of IPv4 addresses and the allocation of IPv6 addresses do not share.
type addrFamily bool

const (
	family4 addrFamily = false
	family6 addrFamily = true
)

// familyOf returns the family of the prefix p.
func familyOf(p netip.Prefix) addrFamily {
	return addrFamily(p.Addr().Is6())
}

// String returns the name of the family as the messages write it.
func (f addrFamily) String() string {
	if f == family6 {
		return "IPv6"
	}
	return "IPv4"
}

// number returns 4 or 6, the family argument of ParsePool.
func (f addrFamily) number() int {
	if f == family6 {
		return 6
	}
	return 4
}

// pool returns the pool of the family that n declares, "" for none.
func (f addrFamily) pool(n Network) string {
	if f == family6 {
		return n.IPv6Pool
	}
	return n.IPv4Pool
}

// held returns the addresses of the family that n holds, by Network name.
func (f addrFamily) held(n Node) map[string]string {
	if f == family6 {
		return n.IPv6Addresses
	}
	return n.Addresses
}

// store sets the addresses of the family that n holds.
func (f addrFamily) store(n *Node, addresses map[string]string) {
	if f == family6 {
		n.IPv6Addresses = addresses
	} else {
		n.Addresses = addresses
	}
}

// contains reports whether a is an address of the family.
func (f addrFamily) contains(a netip.Addr) bool {
	if f == family6 {
		return a.Is6() && !a.Is4In6()
	}
	return a.Is4()
}

// NodeAddress returns the IPv4 address of the Node node in the Network network, with the prefix
// length of the pool: false when the Node holds none there, or holds one that is no host address of
// the IPv4 pool of an L3 Network of its VRFs.
func (in Intent) NodeAddress(node, network string) (netip.Prefix, bool) {
	return in.nodeAddress(node, network, family4)
}

// NodeAddress6 is NodeAddress for the IPv6 address of the Node.
func (in Intent) NodeAddress6(node, network string) (netip.Prefix, bool) {
	return in.nodeAddress(node, network, family6)
}

func (in Intent) nodeAddress(node, network string, f addrFamily) (netip.Prefix, bool) {
	n, ok := in.Nodes[node]
	if !ok {
		return netip.Prefix{}, false
	}
	pool, ok := in.pool(network, f)
	if !ok || !slices.Contains(n.VRFs, in.Networks[network].VRF) {
		return netip.Prefix{}, false
	}
	a, err := netip.ParseAddr(f.held(n)[network])
	if err != nil || !hostAddress(pool, a) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, pool.Bits()), true
}

// pool returns the pool of family f of the Network network when it is an L3 Network that has one.
func (in Intent) pool(network string, f addrFamily) (netip.Prefix, bool) {
	n, ok := in.Networks[network]
	if !ok || n.Mode != ModeL3 || f.pool(n) == "" {
		return netip.Prefix{}, false
	}
	p, err := ParsePool(f.pool(n), f.number())
	return p, err == nil
}

// allocate fills in the addresses of every Node of in, which complete completed, for both
// families, and of every Device: a Device keeps the addresses it held before any Node is given one,
// and gets the ones it lacks after the Nodes (device.go).
func (in Intent) allocate(prev Intent, declared map[string]bool) []error {
	var problems []error
	want := in.keepDevices(prev, declared)
	for _, f := range []addrFamily{family4, family6} {
		problems = append(problems, in.allocateFamily(prev, declared, f)...)
	}
	if len(problems) > 0 {
		return problems
	}
	return in.allocateDevices(want)
}

// allocateFamily fills in the addresses of family f of every Node of in: one address in each L3
// Network with a pool of f of the Node's VRFs, and none elsewhere. An address that a Node of the
// document declares must be a free host address of the pool that the Network does not reserve;
// the address that a Node held before stays its own while it is one; every other Node gets the
// lowest free host address, Nodes in name order and their Networks in name order. declared holds
// kind/name of the resources of the document; prev is the intent before it.
func (in Intent) allocateFamily(prev Intent, declared map[string]bool, f addrFamily) []error {
	var problems []error
	pools := map[string]netip.Prefix{}
	reserved := map[string][]netip.Prefix{}
	for _, name := range sortedNames(in.Networks) {
		if p, ok := in.pool(name, f); ok {
			pools[name] = p
			reserved[name] = in.reservedIn(name, p)
		}
	}
	names := sortedNames(in.Nodes)
	// The Networks of each Node, and what each Node holds so far
	member := map[string][]string{}
	got := map[string]map[string]string{}
	for _, name := range names {
		for _, network := range sortedNames(pools) {
			if slices.Contains(in.Nodes[name].VRFs, in.Networks[network].VRF) {
				member[name] = append(member[name], network)
			}
		}
		got[name] = map[string]string{}
	}
	holder := map[string]map[netip.Addr]string{}
	for network := range pools {
		holder[network] = map[netip.Addr]string{}
	}
	// The addresses that the Devices kept are theirs (device.go)
	in.deviceHolders(holder, f)
	take := func(name, network string, a netip.Addr) {
		holder[network][a] = name
		got[name][network] = a.String()
	}
	// free reports whether a is a host address of the pool of network that no Node holds and the
	// Network does not reserve.
	free := func(network string, a netip.Addr) bool {
		return hostAddress(pools[network], a) && holder[network][a] == "" && !within(reserved[network], a)
	}
	// keep takes the address s that the Node name held in network, when it is still free.
	keep := func(name, network, s string) {
		a, err := netip.ParseAddr(s)
		if _, done := got[name][network]; done || err != nil || !free(network, a) {
			return
		}
		take(name, network, a)
	}

	// The addresses the Nodes outside the document hold, then the reservations of the document
	for _, name := range names {
		if declared[KindNode+"/"+name] {
			continue
		}
		for _, network := range member[name] {
			keep(name, network, f.held(in.Nodes[name])[network])
		}
	}
	for _, name := range names {
		if !declared[KindNode+"/"+name] {
			continue
		}
		want := f.held(in.Nodes[name])
		for _, network := range sortedNames(want) {
			s := want[network]
			a, err := netip.ParseAddr(s)
			switch {
			case !slices.Contains(member[name], network):
				problems = append(problems, fmt.Errorf("Node %q: address %q: %q is not an L3 Network with an %s pool in a VRF of the node", name, s, network, f))
			case err != nil || !f.contains(a):
				problems = append(problems, fmt.Errorf("Node %q: address %q of Network %q is not an %s address", name, s, network, f))
			case !hostAddress(pools[network], a):
				problems = append(problems, fmt.Errorf("Node %q: address %s is not a host address of the pool %s of Network %q", name, a, pools[network], network))
			case within(reserved[network], a):
				problems = append(problems, fmt.Errorf("Node %q: address %s of Network %q is reserved by the Network", name, a, network))
			case holder[network][a] != "":
				problems = append(problems, fmt.Errorf("Node %q: address %s of Network %q is already the address of %s", name, a, network, holderName(holder[network][a])))
			default:
				take(name, network, a)
			}
		}
	}
	if len(problems) > 0 {
		return problems
	}
	// The Nodes of the document keep the addresses they held before
	for _, name := range names {
		if !declared[KindNode+"/"+name] {
			continue
		}
		for _, network := range member[name] {
			keep(name, network, f.held(prev.Nodes[name])[network])
		}
	}

	// The lowest free host address for the rest
	cursor := map[string]netip.Addr{}
	for _, name := range names {
		for _, network := range member[name] {
			if _, done := got[name][network]; done {
				continue
			}
			a, ok := cursor[network]
			if !ok {
				a = pools[network].Addr()
			}
			for a.IsValid() && pools[network].Contains(a) && !free(network, a) {
				a = after(reserved[network], a)
			}
			if !a.IsValid() || !pools[network].Contains(a) {
				problems = append(problems, fmt.Errorf("Network %q: the %s pool %s has no free address for Node %q", network, f, pools[network], name))
				cursor[network] = a
				continue
			}
			take(name, network, a)
			cursor[network] = a.Next()
		}
	}
	for _, name := range names {
		n := in.Nodes[name]
		var addresses map[string]string
		if len(got[name]) > 0 {
			addresses = got[name]
		}
		f.store(&n, addresses)
		in.Nodes[name] = n
	}
	return problems
}

// release takes the addresses in the Network network from every Node of in.
func (in Intent) release(network string) {
	for name, n := range in.Nodes {
		_, v4 := n.Addresses[network]
		_, v6 := n.IPv6Addresses[network]
		if !v4 && !v6 {
			continue
		}
		delete(n.Addresses, network)
		if len(n.Addresses) == 0 {
			n.Addresses = nil
		}
		delete(n.IPv6Addresses, network)
		if len(n.IPv6Addresses) == 0 {
			n.IPv6Addresses = nil
		}
		in.Nodes[name] = n
	}
}

// hostAddress reports whether a may be the address of a Node in the pool p: an address of the
// pool other than the ones that are no host's (nonHost).
func hostAddress(p netip.Prefix, a netip.Addr) bool {
	return p.Contains(a) && !slices.Contains(nonHost(p), a)
}
