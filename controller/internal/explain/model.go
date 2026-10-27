package explain

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The desired state of a Node as its data plane reads it (src/Core/Control.c and the Node module of Cedar): the
// objects of the state, the peers and the rules in name order, and the forwarding tables of its VRFs, built as
// NodeOverlayTables builds them. Next hop i of the tables is the peer peers[i]; each route that a VRF of a peer leaks
// into a VRF of the Node has a next hop of its own after the peers, in the order of the peers and of their routes
// (NodeLeak.c); the addresses of the Node itself, the outside prefixes of its 1:1 NAT rules of one family and the
// addresses of the WireGuard Devices that it terminates lead to its host.

// local is the next hop of an address of the Node itself, its host (NODE_VRF_LOCAL of src/Cedar/Node.h). It is
// greater than any next hop of a peer, so of two routes of one prefix the route to the host wins, as in the
// forwarding tables of the Node, where the route of the greater next hop goes in last.
const local = 0x3FFFFFFF

// The IP protocols that a packet of a query can be.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// The kinds of a link, as Link names them.
const (
	linkNoise  = "noise"
	linkVXLAN  = "vxlan"
	linkGeneve = "geneve"
)

// node is the desired state of one Node.
type node struct {
	name    string
	self    *controlpb.NodeConfig
	vrfs    map[uint32]*controlpb.Vrf // by id, the first of a repeated id in name order
	peers   []*controlpb.Peer         // in name order
	rules   []*controlpb.Rule         // in name order
	devices []*controlpb.Device       // in name order
	nat     []natRule                 // the 1:1 NAT rules that it applies, in the order of the state
	hops    []hop                     // the next hops of its forwarding tables
	routes  []route                   // the routes of the forwarding tables of its VRFs
}

// hop is a next hop of the forwarding tables of a Node: a peer, or a route that a VRF of a peer leaks, which leads to
// that peer and into that VRF.
type hop struct {
	peer int    // the peer, an index of peers
	vrf  uint32 // the VRF of the peer that a packet on a leaked route goes into, 0 for the peer itself
}

// route is a route of the forwarding table of a VRF.
type route struct {
	vrf    uint32
	prefix netip.Prefix // its host bits zero
	hop    uint32       // an index of hops, or local
	what   string       // what it is, for a step
}

// newNode returns the Node name of the desired state s.
func newNode(name string, s desired.State) *node {
	n := &node{name: name, vrfs: map[uint32]*controlpb.Vrf{}}
	for _, o := range s.Objects() {
		switch k := o.GetKind().(type) {
		case *controlpb.Object_Node:
			n.self = k.Node
		case *controlpb.Object_Vrf:
			if _, ok := n.vrfs[k.Vrf.GetId()]; !ok {
				n.vrfs[k.Vrf.GetId()] = k.Vrf
			}
		case *controlpb.Object_Peer:
			// The client leaves out a Peer whose static key is no key (Control.c)
			if len(k.Peer.GetPublicKey()) == intent.KeySize {
				n.peers = append(n.peers, k.Peer)
			}
		case *controlpb.Object_Rule:
			n.rules = append(n.rules, k.Rule)
		case *controlpb.Object_Device:
			n.devices = append(n.devices, k.Device)
		}
	}
	if n.self == nil {
		n.self = &controlpb.NodeConfig{Name: name}
	}
	n.nat = natRules(n.self.GetNat())
	n.build()
	return n
}

// build makes the forwarding tables of n, as NodeOverlayTables does with NodeNatRoutes, NodeLeakRoutes and
// NodeDeviceRoutes.
func (n *node) build() {
	for i := range n.peers {
		n.hops = append(n.hops, hop{peer: i})
	}
	// A host route to each address of the Node, which leads to its host, and to each address of a peer
	for _, a := range n.self.GetAddresses() {
		if p, ok := hostPrefix(a.GetPrefix()); ok {
			n.add(a.GetVrfId(), p, local, fmt.Sprintf("the address %s of %s in Network %s", p.Addr(), n.name, a.GetNetwork()))
		}
	}
	for i, peer := range n.peers {
		for _, a := range peer.GetAddresses() {
			if p, ok := hostPrefix(a.GetPrefix()); ok {
				n.add(a.GetVrfId(), p, uint32(i), fmt.Sprintf("the address %s of %s in Network %s", p.Addr(), peer.GetName(), a.GetNetwork()))
			}
		}
	}
	// 1:1 NAT: the outside prefix of each rule of one family of the Node leads to its host, each route of a peer that
	// no VRF leaks to the peer
	for _, r := range n.nat {
		if !r.family {
			n.add(r.vrf, r.outside, local, fmt.Sprintf("the outside %s of a 1:1 NAT rule of %s", r.outside, n.name))
		}
	}
	for i, peer := range n.peers {
		for _, rt := range peer.GetRoutes() {
			if p, ok := prefixOf(rt.GetPrefix()); ok && !leaked(rt) {
				n.add(rt.GetVrfId(), p, uint32(i), fmt.Sprintf("the outside %s of a 1:1 NAT rule of %s", p, peer.GetName()))
			}
		}
	}
	// Route leaking: each route that a VRF of a peer leaks has a next hop of its own, after the peers
	for i, peer := range n.peers {
		for _, rt := range peer.GetRoutes() {
			if p, ok := prefixOf(rt.GetPrefix()); ok && leaked(rt) {
				n.hops = append(n.hops, hop{peer: i, vrf: rt.GetPeerVrfId()})
				n.add(rt.GetVrfId(), p, uint32(len(n.hops)-1), fmt.Sprintf("a route to %s, the address or the outside prefix of a 1:1 NAT rule of %s", p, peer.GetName()))
			}
		}
	}
	// The WireGuard Devices: the addresses of a Device lead to its gateway, and to the host at the gateway itself
	for _, d := range n.devices {
		next := uint32(0)
		found := false
		if len(d.GetPublicKey()) != 0 && d.GetGateway() == n.name {
			next, found = local, true
		}
		for i, peer := range n.peers {
			if !found && peer.GetName() == d.GetGateway() {
				next, found = uint32(i), true
			}
		}
		if !found {
			continue
		}
		for _, a := range d.GetAddresses() {
			if p, ok := hostPrefix(a.GetPrefix()); ok {
				n.add(d.GetVrfId(), p, next, fmt.Sprintf("the address %s of the WireGuard Device %s, whose gateway is %s", p.Addr(), d.GetName(), d.GetGateway()))
			}
		}
	}
}

// add adds the route of the prefix p in the VRF vrf to the next hop next.
func (n *node) add(vrf uint32, p netip.Prefix, next uint32, what string) {
	n.routes = append(n.routes, route{vrf: vrf, prefix: p.Masked(), hop: next, what: what})
}

// hasTable reports whether n has a forwarding table of the VRF vrf: a route of it (NodeNewVrfTables makes one table
// for the routes of each VRF).
func (n *node) hasTable(vrf uint32) bool {
	return slices.ContainsFunc(n.routes, func(r route) bool { return r.vrf == vrf })
}

// lookup returns the route of the forwarding table of the VRF vrf of n that holds a, as NodeVrfLookup finds it: the
// longest prefix, and of two routes of one prefix the one of the greater next hop. False when no route holds a.
func (n *node) lookup(vrf uint32, a netip.Addr) (route, bool) {
	var best route
	found := false
	for _, r := range n.routes {
		if r.vrf != vrf || !r.prefix.Contains(a) {
			continue
		}
		if !found || r.prefix.Bits() > best.prefix.Bits() || (r.prefix.Bits() == best.prefix.Bits() && r.hop > best.hop) {
			best, found = r, true
		}
	}
	return best, found
}

// vrfIDs returns the ids of the VRFs of n, ordered by the names of the VRFs.
func (n *node) vrfIDs() []uint32 {
	var out []uint32
	for id := range n.vrfs {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b uint32) int { return cmp.Compare(n.vrfs[a].GetName(), n.vrfs[b].GetName()) })
	return out
}

// holds reports whether the host of n holds the address a in the VRF vrf, any VRF when vrf is 0: an address of n, an
// address of the inside of one of its 1:1 NAT rules of one family, or an address of a WireGuard Device that it
// terminates. It returns the VRF.
func (n *node) holds(a netip.Addr, vrf uint32) (uint32, bool) {
	for _, x := range n.self.GetAddresses() {
		if p, ok := hostPrefix(x.GetPrefix()); ok && p.Addr() == a && (vrf == 0 || x.GetVrfId() == vrf) {
			return x.GetVrfId(), true
		}
	}
	for _, r := range n.nat {
		if !r.family && r.inside.Contains(a) && (vrf == 0 || r.vrf == vrf) {
			return r.vrf, true
		}
	}
	for _, d := range n.devices {
		if d.GetGateway() != n.name || len(d.GetPublicKey()) == 0 || (vrf != 0 && d.GetVrfId() != vrf) {
			continue
		}
		for _, x := range d.GetAddresses() {
			if p, ok := hostPrefix(x.GetPrefix()); ok && p.Addr() == a {
				return d.GetVrfId(), true
			}
		}
	}
	return 0, false
}

// reachable returns the addresses under which the other Nodes may reach the host of n, IPv4 first: each address of n,
// and the address that its 1:1 NAT rules of the VRF of the address show to the VRF, which is the one that a leak of
// an address held by a rule moves.
func (n *node) reachable() []netip.Addr {
	var out []netip.Addr
	for _, x := range n.self.GetAddresses() {
		p, ok := hostPrefix(x.GetPrefix())
		if !ok {
			continue
		}
		out = append(out, p.Addr())
		if shown, rules := n.mapAddr(x.GetVrfId(), p.Addr(), true); len(rules) != 0 {
			out = append(out, shown)
		}
	}
	slices.SortStableFunc(out, func(a, b netip.Addr) int {
		return cmp.Compare(a.BitLen(), b.BitLen())
	})
	return out
}

// linkOf returns the kind of the links of the VRF vrf of n, and its VNI: noise for a VRF that n is not a member of,
// as NodeLinkKind finds none.
func (n *node) linkOf(vrf uint32) (string, uint32) {
	v := n.vrfs[vrf]
	switch v.GetLink() {
	case controlpb.LinkKind_LINK_KIND_VXLAN:
		return linkVXLAN, v.GetVni()
	case controlpb.LinkKind_LINK_KIND_GENEVE:
		return linkGeneve, v.GetVni()
	}
	return linkNoise, 0
}

// leaked reports whether a route of a peer is one that a VRF of the peer leaks into a VRF of the Node.
func leaked(r *controlpb.Route) bool {
	return r.GetPeerVrfId() != 0 && r.GetPeerVrfId() != r.GetVrfId()
}

// prefixOf returns the prefix p of the control protocol, its host bits zero: false for one that is neither IPv4 nor
// IPv6, or longer than its address.
func prefixOf(p *controlpb.Prefix) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(p.GetAddress())
	if !ok || int(p.GetLength()) > a.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, int(p.GetLength())).Masked(), true
}

// hostPrefix returns the host prefix of the address of p: the forwarding tables hold an address as a host route,
// whatever the length of the pool that p carries with it.
func hostPrefix(p *controlpb.Prefix) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(p.GetAddress())
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// packet is the packet of a walk: its protocol, its addresses and the ports of TCP and UDP.
type packet struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
}

// String says the packet as the steps name it: "udp 10.0.0.1:40000 > 10.0.0.2:53".
func (p packet) String() string {
	switch p.proto {
	case protoTCP:
		return fmt.Sprintf("tcp %s > %s (SYN)", netip.AddrPortFrom(p.src, p.sport), netip.AddrPortFrom(p.dst, p.dport))
	case protoUDP:
		return fmt.Sprintf("udp %s > %s", netip.AddrPortFrom(p.src, p.sport), netip.AddrPortFrom(p.dst, p.dport))
	case protoICMP, protoICMPv6:
		return fmt.Sprintf("icmp echo request %s > %s", p.src, p.dst)
	}
	return fmt.Sprintf("protocol %d %s > %s", p.proto, p.src, p.dst)
}
