package intent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The Endpoints (SDN-24 #200, ADR-0025 decision 10). An Endpoint publishes one IP address and port of a source VRF into a
// consumer VRF, so that a vendor or another department reaches only that service, even where their ranges overlap. The
// Controller adds no code to the data plane for it: it compiles an Endpoint into primitives that the Nodes have already, by
// WithPublished and publishedRoutes, which the compile of the desired state and the checks of the Intent both use.
//
//   - a 1:1 NAT rule of the Node that serves the service (nat.go), from the address of the service as its host sees it to the
//     published address, one that neither VRF uses, so the overlap of the two ranges never makes a route ambiguous;
//   - a route to that one address, which leaks into the consumer VRF and leads to that Node (leak.go), and, since a Node takes
//     a packet of a peer only from a source that its VRF routes back to that peer, the routes of the consumers back to that
//     Node: their addresses as the source VRF sees them, which a consumer whose range overlaps the source VRF presents
//     through a 1:1 NAT rule of its own, as for any leak (ADR-0025 decision 8). Only the Nodes that a route concerns hold it:
//     the consumers hold the route to the service, and the Node that serves it the routes back, so no other Node of the
//     source VRF is a peer of a consumer, and no other address of the source VRF leaks;
//   - a rule of the policy of each of the two VRFs that lets that port of that protocol through to that address and nothing
//     else (policy.go), the rule of the consumer VRF from the consumers (their tags) and the rule of the source VRF from any
//     source outside the VRF, which only the routes back let through;
//   - a name in the zone of the consumer VRF (dns.go), which answers the published address.
//
// None of these is a resource of the Intent: the stored Intent holds the Endpoint alone, and the revisions, the export and the
// rollback carry it. Their names end in a suffix that no name of a resource can have, so they never meet one of the
// administrator (publishedNATSuffix and the others), and the name of an Endpoint is short enough (MaxEndpointName) for the
// longest of them to fit the name of a rule of the control protocol.
//
// The Go type is PublishedEndpoint: Endpoint is the address under which the other Nodes reach a Node (endpoint.go, SDN-93).

// KindEndpoint is the kind of an Endpoint.
const KindEndpoint = "Endpoint"

// MaxEndpointName is the most characters in the name of an Endpoint. The rules of policy that it compiles to are named after
// it, with a suffix of up to nine characters, and the name of a rule has 63 (proto/ranz/control/v1/control.options).
const MaxEndpointName = 54

// The suffixes of the names of what an Endpoint compiles to. A name of a resource is a DNS label, so none holds a dot.
const (
	publishedNATSuffix      = ".nat"
	publishedSourceSuffix   = ".source"
	publishedConsumerSuffix = ".consumer"
	publishedDNSSuffix      = ".dns"
)

// PublishedEndpoint is the spec of an Endpoint: one service of the source VRF, and where it is published.
type PublishedEndpoint struct {
	// VRF is the source VRF: the service is in it.
	VRF string `json:"vrf"`
	// Node is the Node of the source VRF that serves it: its host, or the LAN behind it, holds Address.
	Node string `json:"node"`
	// Address is the IP address of the service as the host of Node sees it.
	Address string `json:"address"`
	// Port is the port of the service, a TCP or a UDP port by Protocol.
	Port uint16 `json:"port"`
	// Protocol is tcp, the default, or udp.
	Protocol string `json:"protocol,omitempty"`
	// Consumer is the VRF that the service is published into, which has overlay DNS on.
	Consumer string `json:"consumer"`
	// As is the address that the service has in the overlay, of the family of Address: the outside prefix of the 1:1 NAT rule
	// of Node, which the consumers reach it at. No pool, LAN subnet, 1:1 NAT rule or leak of either VRF holds it.
	As string `json:"as"`
	// Name is the name of the service in the zone of Consumer, relative to its suffix: DNS labels separated by dots. Left out,
	// it is the name of the resource.
	Name string `json:"name,omitempty"`
	// ConsumerTags select the consumers: the Nodes of Consumer that have one of the tags, which the Groups of their owner give
	// them too. Left out, every Node of Consumer is one.
	ConsumerTags []string `json:"consumerTags,omitempty"`
}

// HeldBy reports whether the Node node holds the route r: the Nodes that it names, or every member of its VRF when it names
// none, as the routes that a leak of route targets moves are held.
func (r LeakedRoute) HeldBy(node string) bool {
	return len(r.Nodes) == 0 || slices.Contains(r.Nodes, node)
}

// hostPrefix returns the prefix of the whole length of the address a.
func hostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// publishedAddress parses an address of an Endpoint: an IP address that a host of the overlay can hold, so no zone, no
// IPv4-mapped IPv6 address, and neither the unspecified, a loopback, a multicast nor a link-local address.
func publishedAddress(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	switch {
	case err != nil:
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	case a.Zone() != "":
		return netip.Addr{}, fmt.Errorf("%q has a zone: an address of the overlay is the same on every host", s)
	case a.Is4In6():
		return netip.Addr{}, fmt.Errorf("%q is an IPv4-mapped IPv6 address: write it as an IPv4 address", s)
	case a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast():
		return netip.Addr{}, fmt.Errorf("%q is no address of a host of the overlay: it is unspecified, a loopback, a multicast or a link-local address", s)
	}
	return a, nil
}

// values parses the address and the published address of the Endpoint e, and its protocol, which is tcp or udp (6 or 17). The
// two addresses are of one family and differ, as the inside and the outside of a 1:1 NAT rule do.
func (e PublishedEndpoint) values() (netip.Addr, netip.Addr, uint8, error) {
	address, err := publishedAddress(e.Address)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("address: %w", err)
	}
	as, err := publishedAddress(e.As)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("as: %w", err)
	}
	if address.Is4() != as.Is4() {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("the address %s and the published address %s are of two families: a 1:1 NAT rule maps one address to one of its family", address, as)
	}
	if address == as {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("the address and the published address are the same %s: publish the service at an address that it does not have", address)
	}
	protocol, err := ParseProtocol(e.Protocol)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, err
	}
	if protocol != 6 && protocol != 17 {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("protocol %q must be tcp or udp: an Endpoint publishes one port", e.Protocol)
	}
	if e.Port == 0 {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("port 0 is no port of a service, which is a port from 1 to 65535")
	}
	return address, as, protocol, nil
}

// publication is an Endpoint of an intent with its values parsed, for the compilation.
type publication struct {
	spec     PublishedEndpoint
	address  netip.Addr // of the service as the host of its Node sees it
	as       netip.Addr // as the overlay sees it
	protocol uint8      // 6 or 17
}

// publicationOf returns the Endpoint name of in with its values parsed, and false when it compiles to nothing: its values do
// not parse, or its VRFs or its Node are not there, as when a licence leaves its Node out (Capped).
func (in Intent) publicationOf(name string) (publication, bool) {
	e := in.Endpoints[name]
	address, as, protocol, err := e.values()
	if err != nil {
		return publication{}, false
	}
	_, source := in.VRFs[e.VRF]
	_, consumer := in.VRFs[e.Consumer]
	n, node := in.Nodes[e.Node]
	if !source || !consumer || !node || !slices.Contains(n.VRFs, e.VRF) {
		return publication{}, false
	}
	return publication{spec: e, address: address, as: as, protocol: protocol}, true
}

// nat returns the 1:1 NAT rule of p: the Node presents the address of the service in the source VRF as the published address.
func (p publication) nat() NAT {
	return NAT{VRF: p.spec.VRF, Node: p.spec.Node, Inside: hostPrefix(p.address).String(), Outside: hostPrefix(p.as).String()}
}

// rules returns the rule of the policy of the source VRF and the rule of the policy of the consumer VRF that let the port of
// the service through to the published address, and nothing else: from any source outside the VRF in the first, from the
// consumers in the second.
func (p publication) rules() (source, consumer Policy) {
	port := strconv.Itoa(int(p.spec.Port))
	source = Policy{VRF: p.spec.VRF, Action: PolicyAllow, To: PolicyEnd{Addresses: []string{p.as.String()}}, Protocol: policyProtocolName(p.protocol),
		Ports: []PolicyValue{PolicyValue(port)}}
	consumer = Policy{VRF: p.spec.Consumer, Action: PolicyAllow, From: PolicyEnd{Tags: slices.Clone(p.spec.ConsumerTags)},
		To: PolicyEnd{Addresses: []string{p.as.String()}}, Protocol: policyProtocolName(p.protocol), Ports: []PolicyValue{PolicyValue(port)}}
	return source, consumer
}

// record returns the name of p in the zone of the consumer VRF, which answers the published address.
func (p publication) record() DNSRecord {
	return DNSRecord{VRF: p.spec.Consumer, Name: p.spec.Name, Addresses: []string{p.as.String()}}
}

// WithPublished returns in with what its Endpoints compile to besides: for each, the 1:1 NAT rule, the two rules of policy and
// the DnsRecord described at the head of this file, as the resources of their kinds, which the checks and the compile of the
// desired state read as any other. The routes that an Endpoint adds are no resources: LeakedRoutes holds them. An Endpoint that
// compiles to nothing (publicationOf) adds nothing, and two Endpoints that publish two ports of one service at one address
// share one 1:1 NAT rule. in itself is not changed.
func (in Intent) WithPublished() Intent {
	if len(in.Endpoints) == 0 {
		return in
	}
	out := in.Clone()
	rules := map[NAT]bool{}
	for _, name := range sortedNames(in.Endpoints) {
		p, ok := in.publicationOf(name)
		if !ok {
			continue
		}
		if n := p.nat(); !rules[n] {
			rules[n] = true
			out.NATs[name+publishedNATSuffix] = n
		}
		out.Policies[name+publishedSourceSuffix], out.Policies[name+publishedConsumerSuffix] = p.rules()
		out.DNSRecords[name+publishedDNSSuffix] = p.record()
	}
	return out
}

// consumers returns the Nodes that reach the Endpoint p, in name order: the members of the consumer VRF that have one of its
// tags, or all of them when it names none, but the Node that serves it and the members of the source VRF too, which reach the
// service in that VRF itself.
func (in Intent) consumers(p publication) []string {
	var out []string
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		if name == p.spec.Node || !slices.Contains(n.VRFs, p.spec.Consumer) || slices.Contains(n.VRFs, p.spec.VRF) {
			continue
		}
		if len(p.spec.ConsumerTags) > 0 && !(RuleEnd{Tags: p.spec.ConsumerTags}).Holds(in.NodeTags(name)) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// publishedRoute is a route that an Endpoint puts into the forwarding tables of some Nodes (publishedRoutes).
type publishedRoute struct {
	LeakedRoute
	// endpoint is the first Endpoint, in name order, that needs the route.
	endpoint string
	// forward is true for the route to the published address, false for a route back to a consumer.
	forward bool
	// what names the address that the route leads to, after "the" in a message, and nat the NAT resource whose outside prefix
	// it is, empty for an address.
	what string
	nat  string
}

// publishedRoutes returns the routes that the Endpoints of in put into the forwarding tables, ordered by VRF, then prefix, then
// Via: for each, the route to its published address into the consumer VRF, which the consumers hold, and the route back to each
// consumer into the source VRF, which only the Node that serves it holds. A consumer is one that has an address of the family
// of the published address, as the addresses of its VRF leak (exportedRoutes): its own address, or the outside prefix of a 1:1
// NAT rule that presents it. Two Endpoints that need one route share it, and an Endpoint that no consumer can use adds none. An
// Endpoint that compiles to nothing (publicationOf) adds none. in is an intent that Apply returned, or the one that
// WithPublished made of it, which holds the 1:1 NAT rules of the Endpoints too.
func (in Intent) publishedRoutes() []publishedRoute {
	if len(in.Endpoints) == 0 {
		return nil
	}
	type key struct {
		vrf    string
		prefix netip.Prefix
		via    string
		from   string
	}
	var out []publishedRoute
	index := map[key]int{}
	add := func(r publishedRoute) {
		k := key{vrf: r.VRF, prefix: r.Prefix, via: r.Via, from: r.From}
		if i, ok := index[k]; ok {
			out[i].Nodes = append(out[i].Nodes, r.Nodes...)
			slices.Sort(out[i].Nodes)
			out[i].Nodes = slices.Compact(out[i].Nodes)
			return
		}
		index[k] = len(out)
		out = append(out, r)
	}
	exported := map[string]map[string][]exportedRoute{} // by consumer VRF, then Node
	for _, name := range sortedNames(in.Endpoints) {
		p, ok := in.publicationOf(name)
		if !ok {
			continue
		}
		byNode, cached := exported[p.spec.Consumer]
		if !cached {
			byNode = map[string][]exportedRoute{}
			for _, r := range in.exportedRoutes(p.spec.Consumer) {
				byNode[r.node] = append(byNode[r.node], r)
			}
			exported[p.spec.Consumer] = byNode
		}
		var reaching []string
		for _, c := range in.consumers(p) {
			back := false
			for _, r := range byNode[c] {
				if r.prefix.Addr().Is4() != p.as.Is4() {
					continue
				}
				back = true
				add(publishedRoute{LeakedRoute: LeakedRoute{VRF: p.spec.VRF, Prefix: r.prefix, Via: c, From: p.spec.Consumer, Nodes: []string{p.spec.Node}},
					endpoint: name, what: r.what(), nat: r.nat})
			}
			if back {
				reaching = append(reaching, c)
			}
		}
		if len(reaching) > 0 {
			add(publishedRoute{LeakedRoute: LeakedRoute{VRF: p.spec.Consumer, Prefix: hostPrefix(p.as), Via: p.spec.Node, From: p.spec.VRF, Nodes: reaching},
				endpoint: name, forward: true, what: fmt.Sprintf("published address %s", p.as)})
		}
	}
	slices.SortStableFunc(out, func(a, b publishedRoute) int {
		return cmp.Or(cmp.Compare(a.VRF, b.VRF), a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), cmp.Compare(a.Via, b.Via))
	})
	return out
}

// overlap is the problem of the route r, which overlaps held, a prefix that the VRF it leaks into holds already.
func (r publishedRoute) overlap(held string) error {
	if r.forward {
		return fmt.Errorf("Endpoint %q: the %s is published into VRF %q, which holds the overlapping %s: choose a published address that the consumer VRF does not use",
			r.endpoint, r.what, r.VRF, held)
	}
	fix := fmt.Sprintf("give Node %q a 1:1 NAT rule in VRF %q whose inside holds %s, and the address leaks as the outside of the rule", r.Via, r.From, r.Prefix.Addr())
	if r.nat != "" {
		fix = fmt.Sprintf("give NAT %q an outside prefix that VRF %q does not use", r.nat, r.VRF)
	}
	return fmt.Errorf("Endpoint %q: the %s must route back in VRF %q, as a Node takes a packet of a peer only from a source that its VRF routes to that peer, but it overlaps the %s of that VRF: a leaked overlapping prefix needs 1:1 NAT (ADR-0025 decision 8), so %s",
		r.endpoint, r.what, r.VRF, held, fix)
}

// publishedLeaks returns the routes that the Endpoints of in add to the routes leaked, which the leaks of route targets move,
// and a problem for each that overlaps a prefix of the VRF that it leaks into, or a route that is leaked into it already; such a
// route is left out. A route that a leak of route targets holds already for every member of its VRF is not added again.
func (in Intent) publishedLeaks(leaked []LeakedRoute) ([]LeakedRoute, []error) {
	var out []LeakedRoute
	var problems []error
	taken := map[string][]namedPrefix{} // by VRF: its own prefixes and the routes leaked into it so far
	for _, r := range in.publishedRoutes() {
		if slices.ContainsFunc(leaked, func(l LeakedRoute) bool {
			return l.VRF == r.VRF && l.Prefix == r.Prefix && l.Via == r.Via && l.From == r.From
		}) {
			continue
		}
		if _, ok := taken[r.VRF]; !ok {
			taken[r.VRF] = in.ownPrefixes(r.VRF)
			for _, l := range leaked {
				if l.VRF == r.VRF {
					taken[r.VRF] = append(taken[r.VRF], namedPrefix{l.Prefix, fmt.Sprintf("route to %s that VRF %q leaks into it", l.Prefix, l.From)})
				}
			}
		}
		if i := slices.IndexFunc(taken[r.VRF], func(t namedPrefix) bool { return t.prefix.Overlaps(r.Prefix) }); i >= 0 {
			problems = append(problems, r.overlap(taken[r.VRF][i].what))
			continue
		}
		taken[r.VRF] = append(taken[r.VRF], namedPrefix{r.Prefix, fmt.Sprintf("%s, which Endpoint %q leaks into it", r.what, r.endpoint)})
		out = append(out, r.LeakedRoute)
	}
	return out, problems
}

// completeEndpoints writes the values of each Endpoint of in in their one form: the addresses as netip writes them, the
// protocol by its name, tcp when it is left out, the name of the resource for a name that is left out, and the consumer tags
// sorted. A value that does not parse stays as it is, for validate to refuse.
func (in Intent) completeEndpoints() {
	for name, e := range in.Endpoints {
		if a, err := netip.ParseAddr(e.Address); err == nil {
			e.Address = a.String()
		}
		if a, err := netip.ParseAddr(e.As); err == nil {
			e.As = a.String()
		}
		e.Protocol = strings.ToLower(e.Protocol)
		if n, err := ParseProtocol(e.Protocol); err == nil {
			e.Protocol = string(policyProtocolName(n))
		}
		if e.Protocol == "" {
			e.Protocol = "tcp"
		}
		if e.Name == "" {
			e.Name = name
		}
		e.ConsumerTags = slices.Sorted(slices.Values(e.ConsumerTags))
		in.Endpoints[name] = e
	}
}

// cloneEndpoints returns a copy of the Endpoints of in that shares nothing with them.
func (in Intent) cloneEndpoints() map[string]PublishedEndpoint {
	out := make(map[string]PublishedEndpoint, len(in.Endpoints))
	for name, e := range in.Endpoints {
		e.ConsumerTags = slices.Clone(e.ConsumerTags)
		out[name] = e
	}
	return out
}

// publishedUsers returns the Endpoints of in that the VRF vrf or the Node node is used by, each as its kind and quoted name, in
// name order. An empty vrf or node matches none.
func (in Intent) publishedUsers(vrf, node string) []string {
	var out []string
	for _, name := range sortedNames(in.Endpoints) {
		e := in.Endpoints[name]
		if (vrf != "" && (e.VRF == vrf || e.Consumer == vrf)) || (node != "" && e.Node == node) {
			out = append(out, KindEndpoint+" "+strconv.Quote(name))
		}
	}
	return out
}

// validatePublishedEndpoint checks the Endpoint name of a completed intent: its two VRFs are VRFs of the intent and not one, and
// the consumer VRF has overlay DNS on; its Node is a member of the source VRF; its values parse; its name is a name of a zone;
// and its consumer tags are tags. What it compiles to is checked by validatePublished.
func (in Intent) validatePublishedEndpoint(name string) []error {
	e := in.Endpoints[name]
	var problems []error
	if len(name) > MaxEndpointName {
		problems = append(problems, fmt.Errorf("Endpoint %q: the name is longer than %d characters: the rules of policy that it compiles to are named after it", name, MaxEndpointName))
	}
	if _, ok := in.VRFs[e.VRF]; !ok {
		problems = append(problems, fmt.Errorf("Endpoint %q: VRF %q does not exist", name, e.VRF))
	}
	consumer, ok := in.VRFs[e.Consumer]
	switch {
	case !ok:
		problems = append(problems, fmt.Errorf("Endpoint %q: the consumer VRF %q does not exist", name, e.Consumer))
	case e.Consumer == e.VRF:
		problems = append(problems, fmt.Errorf("Endpoint %q: the consumer VRF is the source VRF %q: an Endpoint publishes a service into another VRF", name, e.VRF))
	case !consumer.DNS:
		problems = append(problems, fmt.Errorf("Endpoint %q: overlay DNS is off in the consumer VRF %q: turn on its dns, so that its zone answers the name of the Endpoint", name, e.Consumer))
	}
	if n, ok := in.Nodes[e.Node]; !ok {
		problems = append(problems, fmt.Errorf("Endpoint %q: Node %q does not exist", name, e.Node))
	} else if !slices.Contains(n.VRFs, e.VRF) {
		problems = append(problems, fmt.Errorf("Endpoint %q: Node %q is not a member of VRF %q", name, e.Node, e.VRF))
	}
	if _, _, _, err := e.values(); err != nil {
		problems = append(problems, fmt.Errorf("Endpoint %q: %w", name, err))
	}
	if err := checkDNSName(e.Name); err != nil {
		problems = append(problems, fmt.Errorf("Endpoint %q: name: %w", name, err))
	} else if full := e.Name + "." + in.DNSSuffix(e.Consumer); len(full) > maxDNSFull {
		problems = append(problems, fmt.Errorf("Endpoint %q: %s is longer than %d characters", name, full, maxDNSFull))
	}
	if len(e.ConsumerTags) > MaxPolicyValues {
		problems = append(problems, fmt.Errorf("Endpoint %q: %d consumer tags, at most %d", name, len(e.ConsumerTags), MaxPolicyValues))
	}
	for i, t := range e.ConsumerTags {
		if !nameRule.MatchString(t) {
			problems = append(problems, fmt.Errorf("Endpoint %q: consumer tag %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", name, t))
		}
		if i > 0 && e.ConsumerTags[i-1] == t {
			problems = append(problems, fmt.Errorf("Endpoint %q: consumer tag %q is listed twice", name, t))
		}
	}
	return problems
}

// validatePublished checks the Endpoints of a completed intent. Each Endpoint is checked alone (validatePublishedEndpoint). Once the rest
// of the intent is valid, rest, what they compile to is checked as the resources of its kinds are: the 1:1 NAT rule of an
// Endpoint overlaps no pool, LAN subnet or outside prefix of the source VRF and no other rule of its Node, its routes overlap no
// prefix of the VRF that they leak into, no Node has more 1:1 NAT rules, routes to a peer or records in a zone than the control
// protocol carries, and its rules and its record are rules and a record of their VRFs. The checks of the rest of the intent have
// found their own problems by then, so what they find now is the Endpoints'.
func (in Intent) validatePublished(rest bool) []error {
	var problems []error
	for _, name := range sortedNames(in.Endpoints) {
		problems = append(problems, in.validatePublishedEndpoint(name)...)
	}
	if len(problems) > 0 || !rest || len(in.Endpoints) == 0 {
		return problems
	}
	d := in.WithPublished()
	problems = append(problems, d.validatePolicies()...)
	problems = append(problems, d.validateNAT()...)
	problems = append(problems, d.validateLeaks()...)
	return append(problems, d.validateDNS()...)
}
