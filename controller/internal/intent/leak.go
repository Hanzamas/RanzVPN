package intent

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Route leaking with route targets (ADR-0025 decisions 7 to 9, SDN-7 #183). VRFs are isolated
// unless the Intent leaks routes between them. A VRF exports route targets and imports route
// targets, as a VRF of BGP L3VPN and EVPN does, and the routes of a VRF leak into every other VRF
// that imports a route target that it exports (Leaks). There is no route distinguisher: every VRF
// has its own forwarding table on a Node. The routes that a VRF leaks are the routes of its
// forwarding tables that lead to its members (LeakedRoutes): the address of each member Node in
// each L3 Network of the VRF, and the outside prefix of each 1:1 NAT rule that a member applies in
// it. An address that a 1:1 NAT rule of its Node holds as inside leaks as the outside address of
// the rule only, as the Node's host presents it to the VRF.
//
// A leak moves routes one way. Traffic needs the leak both ways, because a Node delivers a packet
// of a peer only when its VRF routes the source back to that peer; the "connect VRF" shortcut
// (Connect) writes the two route-target edits of a two-way leak at once. A shared-services VRF
// that exports to many VRFs and imports from them is reachable from all of them, while they reach
// each other only when they leak into each other too.
//
// A leaked route never makes a route ambiguous (decision 8): a route that overlaps a prefix of the
// importing VRF (a pool of its Networks, a LAN subnet advertised in it, the outside prefix of one
// of its 1:1 NAT rules, or a route that another VRF leaks into it) refuses the apply. An address
// leaks through 1:1 NAT instead: a NAT rule of its Node whose inside holds it presents it to the
// VRF, and every VRF that imports, as an outside prefix that they do not use. The policy of the VRF
// that a leaked route leads into still decides what passes (decision 8, ADR-0029 decision 6): the
// Node of the destination takes leaked traffic in that VRF only, through its forwarding table,
// its 1:1 NAT rules and its policy.

const (
	// MaxRouteTargets is the most route targets that a VRF imports, and the most that it exports.
	MaxRouteTargets = 32
	// MaxPeerRoutes is the most routes that lead to one peer of a Node besides its addresses: the
	// outside prefixes of its 1:1 NAT rules, the routes that leaks add and the default route of
	// each VRF whose internet exit it is (egress.go). The Peer message of the control protocol
	// carries 16 (proto/ranz/control/v1/control.options).
	MaxPeerRoutes = 16
	// DefaultRouteTargetASN is the AS number of the route target that Connect gives a VRF that
	// exports none (DefaultRouteTarget): 64512, the first AS number for private use (RFC 6996).
	DefaultRouteTargetASN = 64512
)

// Leak is the leak of the routes of one VRF into another: To imports a route target that From
// exports.
type Leak struct {
	From string `json:"from"`
	To   string `json:"to"`
	// RouteTargets are the route targets that From exports and To imports, sorted.
	RouteTargets []string `json:"routeTargets"`
}

// LeakedRoute is a route that a leak puts into the forwarding table of a VRF: it leads to the Node
// Via, a member of the VRF From, and a packet on it goes into From.
type LeakedRoute struct {
	// VRF is the importing VRF, whose forwarding tables hold the route.
	VRF string `json:"vrf"`
	// Prefix is the address of Via in a Network of From, as a host prefix, or the outside prefix
	// of a 1:1 NAT rule that Via applies in From.
	Prefix netip.Prefix `json:"prefix"`
	// Via is the Node that the route leads to.
	Via string `json:"via"`
	// From is the exporting VRF.
	From string `json:"from"`
	// Nodes are the Nodes of VRF that hold the route, when only some do: the route that an Endpoint puts into the tables
	// (publish.go; SDN-24). Left out, every member of VRF holds it, as for the routes of route targets.
	Nodes []string `json:"nodes,omitempty"`
}

// ParseRouteTarget parses a route target of a VRF, in the forms of the route target extended
// community of BGP (RFC 4360, RFC 5668): ASN:NUMBER with an AS number up to 65535 and a number up
// to 4294967295, ASN:NUMBER with a larger AS number and a number up to 65535, or IPV4:NUMBER with
// a number up to 65535. It returns the route target in its one form, without leading zeros.
func ParseRouteTarget(s string) (string, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", fmt.Errorf("route target %q is not ASN:NUMBER or IPV4:NUMBER", s)
	}
	admin, number := s[:i], s[i+1:]
	n, err := strconv.ParseUint(number, 10, 32)
	if err != nil {
		return "", fmt.Errorf("route target %q: the number %q is not a number from 0 to 4294967295", s, number)
	}
	if strings.ContainsAny(admin, ".:") {
		a, err := netip.ParseAddr(admin)
		if err != nil || !a.Is4() {
			return "", fmt.Errorf("route target %q: %q is neither an AS number nor an IPv4 address", s, admin)
		}
		if n > 0xFFFF {
			return "", fmt.Errorf("route target %q: after an IPv4 address the number is at most 65535", s)
		}
		return a.String() + ":" + strconv.FormatUint(n, 10), nil
	}
	asn, err := strconv.ParseUint(admin, 10, 32)
	switch {
	case err != nil:
		return "", fmt.Errorf("route target %q: %q is neither an AS number nor an IPv4 address", s, admin)
	case asn == 0:
		return "", fmt.Errorf("route target %q: AS number 0 is reserved (RFC 7607)", s)
	case asn > 0xFFFF && n > 0xFFFF:
		return "", fmt.Errorf("route target %q: after an AS number above 65535 the number is at most 65535", s)
	}
	return strconv.FormatUint(asn, 10) + ":" + strconv.FormatUint(n, 10), nil
}

// DefaultRouteTarget returns the route target that Connect gives the VRF of the id id when it
// exports none: DefaultRouteTargetASN and the id.
func DefaultRouteTarget(id uint32) string {
	return strconv.Itoa(DefaultRouteTargetASN) + ":" + strconv.FormatUint(uint64(id), 10)
}

// Leaks returns the leaks of in, ordered by From, then To. A VRF never leaks into itself.
func (in Intent) Leaks() []Leak {
	var out []Leak
	names := sortedNames(in.VRFs)
	for _, from := range names {
		for _, to := range names {
			if from == to {
				continue
			}
			var rts []string
			for _, rt := range in.VRFs[from].ExportTargets {
				if slices.Contains(in.VRFs[to].ImportTargets, rt) && !slices.Contains(rts, rt) {
					rts = append(rts, rt)
				}
			}
			if len(rts) > 0 {
				slices.Sort(rts)
				out = append(out, Leak{From: from, To: to, RouteTargets: rts})
			}
		}
	}
	return out
}

// LeakedRoutes returns the routes that the leaks of in move, ordered by VRF, then prefix, then
// Via. A route that would make a route of its VRF ambiguous is left out: in is an intent that
// Apply returned, which refuses such a route.
func (in Intent) LeakedRoutes() []LeakedRoute {
	out, _ := in.leakedRoutes()
	return out
}

// Connect returns the resources of the VRFs a and b of in, edited so that the routes of each leak
// into the other (the "connect VRF" shortcut, ADR-0025 decision 9): each imports a route target
// that the other exports. A VRF that exports none first exports DefaultRouteTarget of its id; a
// VRF that already imports a route target of the other keeps its imports. Applying the document
// makes the two route-target edits of a two-way leak one revision. in must be an intent that Apply
// returned.
func (in Intent) Connect(a, b string) (Document, error) {
	if a == b {
		return Document{}, fmt.Errorf("%w: VRF %q cannot be connected to itself", ErrInvalid, a)
	}
	va, ok := in.VRFs[a]
	if !ok {
		return Document{}, fmt.Errorf("%w: VRF %q", ErrNotFound, a)
	}
	vb, ok := in.VRFs[b]
	if !ok {
		return Document{}, fmt.Errorf("%w: VRF %q", ErrNotFound, b)
	}
	for _, v := range []*VRF{&va, &vb} {
		v.ImportTargets = slices.Clone(v.ImportTargets)
		v.ExportTargets = slices.Clone(v.ExportTargets)
		if len(v.ExportTargets) == 0 {
			v.ExportTargets = []string{DefaultRouteTarget(v.ID)}
		}
	}
	for _, p := range [][2]*VRF{{&va, &vb}, {&vb, &va}} {
		to, from := p[0], p[1]
		if !slices.ContainsFunc(from.ExportTargets, func(rt string) bool { return slices.Contains(to.ImportTargets, rt) }) {
			to.ImportTargets = append(to.ImportTargets, from.ExportTargets[0])
			slices.Sort(to.ImportTargets)
		}
	}
	return Document{Resources: []Resource{resource(KindVRF, a, va), resource(KindVRF, b, vb)}}, nil
}

// cloneRouteTargets gives each VRF of vrfs route targets of its own, so a clone of an intent
// shares none with the intent (Clone).
func cloneRouteTargets(vrfs map[string]VRF) {
	for name, v := range vrfs {
		v.ImportTargets = slices.Clone(v.ImportTargets)
		v.ExportTargets = slices.Clone(v.ExportTargets)
		vrfs[name] = v
	}
}

// completeLeaks writes the route targets of each VRF of in in their one form, sorted. A route
// target that does not parse stays as it is, for validate to refuse.
func (in Intent) completeLeaks() {
	for name, v := range in.VRFs {
		v.ImportTargets = canonicalRouteTargets(v.ImportTargets)
		v.ExportTargets = canonicalRouteTargets(v.ExportTargets)
		in.VRFs[name] = v
	}
}

// canonicalRouteTargets returns a sorted copy of list with each route target that parses in its
// one form.
func canonicalRouteTargets(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, len(list))
	for i, rt := range list {
		out[i] = rt
		if canonical, err := ParseRouteTarget(rt); err == nil {
			out[i] = canonical
		}
	}
	slices.Sort(out)
	return out
}

// validateLeaks checks the route targets and the leaks of a completed intent: each route target
// parses and is listed once, a VRF has at most MaxRouteTargets of each kind, no leaked route
// overlaps a prefix of the VRF that it leaks into, and no Node has more than MaxPeerRoutes routes
// to one peer.
func (in Intent) validateLeaks() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		for _, list := range []struct {
			field string
			rts   []string
		}{{"importTargets", v.ImportTargets}, {"exportTargets", v.ExportTargets}} {
			if len(list.rts) > MaxRouteTargets {
				problems = append(problems, fmt.Errorf("VRF %q: %s holds %d route targets, at most %d", name, list.field, len(list.rts), MaxRouteTargets))
			}
			for i, rt := range list.rts {
				if _, err := ParseRouteTarget(rt); err != nil {
					problems = append(problems, fmt.Errorf("VRF %q: %s: %w", name, list.field, err))
				} else if i > 0 && list.rts[i-1] == rt {
					problems = append(problems, fmt.Errorf("VRF %q: %s lists the route target %s twice", name, list.field, rt))
				}
			}
		}
	}
	routes, overlaps := in.leakedRoutes()
	problems = append(problems, overlaps...)
	return append(problems, in.validatePeerRoutes(routes)...)
}

// exportedRoute is a route of the forwarding tables of a VRF that leads to one of its members, as a
// leak moves it: the address of the member in a Network of the VRF, or the outside prefix of a 1:1
// NAT rule that it applies in the VRF.
type exportedRoute struct {
	prefix netip.Prefix
	node   string
	nat    string // the NAT resource of an outside prefix, empty for an address
}

// what names the route in a message, after "the".
func (r exportedRoute) what() string {
	if r.nat != "" {
		return fmt.Sprintf("outside %s of NAT %q", r.prefix, r.nat)
	}
	return fmt.Sprintf("address %s of Node %q", r.prefix.Addr(), r.node)
}

// exportedRoutes returns the routes that the VRF vrf leaks, ordered by Node, then Network, the
// addresses of a Node before the outside prefixes of its NAT rules: the address of each member in
// each L3 Network of the VRF that no 1:1 NAT rule of the member holds as inside, as a host prefix,
// and the outside prefix of each 1:1 NAT rule of a member in the VRF.
func (in Intent) exportedRoutes(vrf string) []exportedRoute {
	var out []exportedRoute
	for _, node := range sortedNames(in.Nodes) {
		if !slices.Contains(in.Nodes[node].VRFs, vrf) {
			continue
		}
		var insides []netip.Prefix
		var outsides []exportedRoute
		for _, name := range sortedNames(in.NATs) {
			r := in.NATs[name]
			inside, err := parseNATPrefix(r.Inside)
			outside, err2 := parseNATPrefix(r.Outside)
			if r.VRF == vrf && r.Node == node && err == nil && err2 == nil {
				insides = append(insides, inside)
				outsides = append(outsides, exportedRoute{prefix: outside, node: node, nat: name})
			}
		}
		for _, network := range sortedNames(in.Networks) {
			if in.Networks[network].VRF != vrf {
				continue
			}
			for _, address := range []func(node, network string) (netip.Prefix, bool){in.NodeAddress, in.NodeAddress6} {
				p, ok := address(node, network)
				if ok && !slices.ContainsFunc(insides, func(i netip.Prefix) bool { return i.Contains(p.Addr()) }) {
					out = append(out, exportedRoute{prefix: netip.PrefixFrom(p.Addr(), p.Addr().BitLen()), node: node})
				}
			}
		}
		out = append(out, outsides...)
	}
	return out
}

// namedPrefix is a prefix of a VRF with what it is, for a message, after "the".
type namedPrefix struct {
	prefix netip.Prefix
	what   string
}

// ownPrefixes returns the prefixes of the VRF vrf that a route leaked into it must not overlap:
// the pools of its Networks, the LAN subnets advertised in it and the outside prefixes of its 1:1
// NAT rules.
func (in Intent) ownPrefixes(vrf string) []namedPrefix {
	var out []namedPrefix
	for _, network := range sortedNames(in.Networks) {
		if in.Networks[network].VRF != vrf {
			continue
		}
		for _, p := range in.poolsOf(network) {
			out = append(out, namedPrefix{p, fmt.Sprintf("pool %s of Network %q", p, network)})
		}
	}
	for _, r := range in.Routes() {
		if r.VRF == vrf {
			out = append(out, namedPrefix{r.Prefix, fmt.Sprintf("LAN subnet %s that Node %q advertises", r.Prefix, r.Via)})
		}
	}
	for _, name := range sortedNames(in.NATs) {
		r := in.NATs[name]
		if p, err := parseNATPrefix(r.Outside); r.VRF == vrf && err == nil {
			out = append(out, namedPrefix{p, fmt.Sprintf("outside %s of NAT %q", p, name)})
		}
	}
	return out
}

// leakedRoutes returns the routes that the leaks of in move, ordered by VRF, then prefix, then
// Via, and a problem for each route that overlaps a prefix of the VRF that it leaks into, or a
// route that another VRF leaks into it; such a route is left out.
func (in Intent) leakedRoutes() ([]LeakedRoute, []error) {
	var out []LeakedRoute
	var problems []error
	byTo := map[string][]Leak{}
	for _, l := range in.Leaks() {
		byTo[l.To] = append(byTo[l.To], l)
	}
	for _, to := range sortedNames(byTo) {
		taken := in.ownPrefixes(to)
		for _, l := range byTo[to] {
			for _, r := range in.exportedRoutes(l.From) {
				i := slices.IndexFunc(taken, func(t namedPrefix) bool { return t.prefix.Overlaps(r.prefix) })
				if i < 0 {
					out = append(out, LeakedRoute{VRF: to, Prefix: r.prefix, Via: r.node, From: l.From})
					taken = append(taken, namedPrefix{r.prefix, fmt.Sprintf("%s, which VRF %q leaks into it", r.what(), l.From)})
					continue
				}
				fix := fmt.Sprintf("give Node %q a 1:1 NAT rule in VRF %q whose inside holds %s, and the address leaks as the outside of the rule", r.node, l.From, r.prefix.Addr())
				if r.nat != "" {
					fix = fmt.Sprintf("give NAT %q an outside prefix that VRF %q does not use", r.nat, to)
				}
				problems = append(problems, fmt.Errorf("VRF %q imports the route target %s of VRF %q, which leaks the %s into it, but VRF %q holds the overlapping %s: a leaked overlapping prefix needs 1:1 NAT (ADR-0025 decision 8), so %s",
					to, l.RouteTargets[0], l.From, r.what(), to, taken[i].what, fix))
			}
		}
	}
	// The routes that the Endpoints put into the tables of some Nodes (publish.go; SDN-24)
	published, overlaps := in.publishedLeaks(out)
	out = append(out, published...)
	problems = append(problems, overlaps...)
	slices.SortStableFunc(out, func(a, b LeakedRoute) int {
		return cmp.Or(cmp.Compare(a.VRF, b.VRF), a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), cmp.Compare(a.Via, b.Via))
	})
	return out, problems
}

// validatePeerRoutes checks that no Node has more than MaxPeerRoutes routes to one peer besides
// its addresses: the outside prefixes of the 1:1 NAT rules of the peer in the VRFs that the two
// share, the routes leaked into the VRFs of the Node that lead to the peer, the LAN subnets of the
// peer and the prefixes of the VRFs whose hub it is (topology.go), and the default route of each
// VRF of the two whose internet exit the peer is (egress.go). The LAN subnets of the peer in a VRF
// that peers by BGP count too: the Controller gives no route of them, but the Node learns them and
// puts each one among the routes of the peer, in one of the same slots (peering.go; SDN-77-R2).
func (in Intent) validatePeerRoutes(leaked []LeakedRoute) []error {
	count := map[[2]string]int{} // by Node and peer
	for _, name := range sortedNames(in.Nodes) {
		vrfs := in.Nodes[name].VRFs
		for _, r := range leaked {
			if r.Via != name && slices.Contains(vrfs, r.VRF) && r.HeldBy(name) {
				count[[2]string{name, r.Via}]++
			}
		}
		for _, n := range sortedNames(in.NATs) {
			r := in.NATs[n]
			// Two spokes of a VRF of topology hub-and-spoke do not share it (SDN-19, topology.go)
			if peer, ok := in.Nodes[r.Node]; ok && r.Node != name && slices.Contains(vrfs, r.VRF) && slices.Contains(peer.VRFs, r.VRF) && !in.Spokes(r.VRF, name, r.Node) {
				count[[2]string{name, r.Node}]++
			}
		}
		// The default routes of the internet exits (egress.go; SDN-12)
		in.egressRoutes(name, count)
	}
	// The LAN subnets of the gateways and the prefixes that lead to a hub (SDN-19, topology.go), and the LAN
	// subnets that a Node learns from its peers by BGP (SDN-77-R2, peering.go)
	in.gatewayRouteCounts(count)
	var problems []error
	for _, k := range slices.SortedFunc(maps.Keys(count), func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) }) {
		if count[k] > MaxPeerRoutes {
			problems = append(problems, fmt.Errorf("Node %q: %d routes lead to its peer %q, the outside prefixes of the 1:1 NAT rules of the peer with the routes that leaks add, the LAN subnets and hub prefixes of the peer and the default routes of the VRFs whose internet exit it is, and the control protocol carries at most %d",
				k[0], count[k], k[1], MaxPeerRoutes))
		}
	}
	return problems
}
