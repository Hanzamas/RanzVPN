package intent

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
)

// The addresses of the Nodes (ADR-0028, SDN-3 #179). The controller alone allocates them, from the
// IPv4 pool of each L3 Network: a Node holds one address in every such Network of its VRFs, and
// no DHCP runs inside the overlay. The address of a Node in a Network is the one the Node declares
// (a reservation), else the one it held before, else the lowest free host address of the pool,
// and it stays the Node's while the Node is in that Network. SDN-10 (#186) adds the IPv6 pools,
// the gateway LAN subnets as routes and the event before a pool runs out.

// NodeAddress returns the address of the Node node in the Network network, with the prefix length
// of the pool: false when the Node holds none there, or holds one that is no host address of the
// IPv4 pool of an L3 Network of its VRFs.
func (in Intent) NodeAddress(node, network string) (netip.Prefix, bool) {
	n, ok := in.Nodes[node]
	if !ok {
		return netip.Prefix{}, false
	}
	pool, ok := in.pool(network)
	if !ok || !slices.Contains(n.VRFs, in.Networks[network].VRF) {
		return netip.Prefix{}, false
	}
	a, err := netip.ParseAddr(n.Addresses[network])
	if err != nil || !hostAddress(pool, a) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, pool.Bits()), true
}

// pool returns the IPv4 pool of the Network network when it is an L3 Network that has one.
func (in Intent) pool(network string) (netip.Prefix, bool) {
	n, ok := in.Networks[network]
	if !ok || n.Mode != ModeL3 || n.IPv4Pool == "" {
		return netip.Prefix{}, false
	}
	p, err := ParsePool(n.IPv4Pool, 4)
	return p, err == nil
}

// allocate fills in the Addresses of every Node of in, which complete completed: one address in
// each L3 Network with an IPv4 pool of the Node's VRFs, and none elsewhere. An address that a Node
// of the document declares must be a free host address of the pool; the address that a Node held
// before stays its own while it is one; every other Node gets the lowest free host address, Nodes
// in name order and their Networks in name order. declared holds kind/name of the resources of
// the document; prev is the intent before it.
func (in Intent) allocate(prev Intent, declared map[string]bool) []error {
	var problems []error
	pools := map[string]netip.Prefix{}
	for _, name := range sortedNames(in.Networks) {
		if p, ok := in.pool(name); ok {
			pools[name] = p
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
	held := map[string]map[netip.Addr]string{}
	for network := range pools {
		held[network] = map[netip.Addr]string{}
	}
	take := func(name, network string, a netip.Addr) {
		held[network][a] = name
		got[name][network] = a.String()
	}
	// keep takes the address s that the Node name held in network, when it is still a free host
	// address of the pool.
	keep := func(name, network, s string) {
		a, err := netip.ParseAddr(s)
		if _, done := got[name][network]; done || err != nil || !hostAddress(pools[network], a) || held[network][a] != "" {
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
			keep(name, network, in.Nodes[name].Addresses[network])
		}
	}
	for _, name := range names {
		if !declared[KindNode+"/"+name] {
			continue
		}
		n := in.Nodes[name]
		for _, network := range sortedNames(n.Addresses) {
			s := n.Addresses[network]
			a, err := netip.ParseAddr(s)
			switch {
			case !slices.Contains(member[name], network):
				problems = append(problems, fmt.Errorf("Node %q: address %q: %q is not an L3 Network with an IPv4 pool in a VRF of the node", name, s, network))
			case err != nil || !a.Is4():
				problems = append(problems, fmt.Errorf("Node %q: address %q of Network %q is not an IPv4 address", name, s, network))
			case !hostAddress(pools[network], a):
				problems = append(problems, fmt.Errorf("Node %q: address %s is not a host address of the pool %s of Network %q", name, a, pools[network], network))
			case held[network][a] != "":
				problems = append(problems, fmt.Errorf("Node %q: address %s of Network %q is already the address of Node %q", name, a, network, held[network][a]))
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
			keep(name, network, prev.Nodes[name].Addresses[network])
		}
	}

	// The lowest free host address for the rest
	next := map[string]netip.Addr{}
	for _, name := range names {
		for _, network := range member[name] {
			if _, done := got[name][network]; done {
				continue
			}
			a, ok := next[network]
			if !ok {
				a = pools[network].Addr()
			}
			for !hostAddress(pools[network], a) || held[network][a] != "" {
				if !pools[network].Contains(a) {
					break
				}
				a = a.Next()
			}
			if !pools[network].Contains(a) {
				problems = append(problems, fmt.Errorf("Network %q: the IPv4 pool %s has no free address for Node %q", network, pools[network], name))
				next[network] = a
				continue
			}
			take(name, network, a)
			next[network] = a.Next()
		}
	}
	for _, name := range names {
		n := in.Nodes[name]
		n.Addresses = nil
		if len(got[name]) > 0 {
			n.Addresses = got[name]
		}
		in.Nodes[name] = n
	}
	return problems
}

// release takes the addresses in the Network network from every Node of in.
func (in Intent) release(network string) {
	for name, n := range in.Nodes {
		if _, ok := n.Addresses[network]; !ok {
			continue
		}
		delete(n.Addresses, network)
		if len(n.Addresses) == 0 {
			n.Addresses = nil
		}
		in.Nodes[name] = n
	}
}

// hostAddress reports whether a may be the address of a Node in the IPv4 pool p: an address of
// the pool other than its first and its last, which name the network and its broadcast, unless
// the pool holds no more than two addresses.
func hostAddress(p netip.Prefix, a netip.Addr) bool {
	if !p.Contains(a) {
		return false
	}
	if p.Bits() >= 31 {
		return true
	}
	b := p.Addr().As4()
	last := binary.BigEndian.Uint32(b[:]) | (1<<(32-p.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], last)
	return a != p.Addr() && a != netip.AddrFrom4(b)
}
