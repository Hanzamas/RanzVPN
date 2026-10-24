package intent

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The policy of the VRFs (ADR-0029, SDN-8 #184). A Policy is one rule of the policy of its VRF,
// written between the tags of Nodes and the prefixes of addresses, with a protocol and ports, an
// action and a priority. The controller compiles the rules of a VRF into the policy engine of
// each of its Nodes (desired/policy.go): stateful, default deny, one evaluation per flow at each
// end of the flow, with the conntrack quota and the timeouts that the VRF declares (Conntrack).

const (
	// DefaultPriority is the priority of a Policy that declares none.
	DefaultPriority = 1000
	// MaxPriority is the largest priority of a Policy: the rule that a Node judges last.
	MaxPriority = 1000000
	// MaxPolicyValues is the most tags, addresses or ports of one kind that a Policy holds in one
	// place: the Rule message of the control protocol carries 16 of each
	// (proto/ranz/control/v1/control.options).
	MaxPolicyValues = 16
	// MaxFlows is the largest conntrack quota of a VRF: a Node takes the memory of the table of
	// the VRF at once.
	MaxFlows = 1 << 20
	// MaxTimeout is the longest timeout of a flow, in seconds: a week.
	MaxTimeout = 604800
)

// Conntrack is the conntrack table of a VRF on each of its Nodes (ADR-0029 decision 5): its quota
// and the timeouts of its flows. A value of 0 is the default of the Node.
type Conntrack struct {
	// MaxFlows is the most flows that the table holds, from 1 to MaxFlows; 65536 by default. A
	// new flow takes the place of the least recently used one of a full table, so a VRF that fills
	// its table takes no room of another.
	MaxFlows uint32 `json:"maxFlows,omitempty"`
	// Timeouts are the times after which a flow without a packet ends.
	Timeouts Timeouts `json:"timeouts,omitzero"`
}

// Timeouts are the timeouts of the flows of a VRF by protocol and state, in seconds from 1 to
// MaxTimeout; the default of the Node is in brackets.
type Timeouts struct {
	TCPEstablished uint32 `json:"tcpEstablished,omitempty"` // a TCP flow that both ends sent on (3600)
	TCPTransitory  uint32 `json:"tcpTransitory,omitempty"`  // a TCP flow that opens or closes (120)
	UDP            uint32 `json:"udp,omitempty"`            // a UDP flow (60)
	ICMP           uint32 `json:"icmp,omitempty"`           // an ICMP echo (30)
	Other          uint32 `json:"other,omitempty"`          // a flow of another IP protocol (60)
}

// PolicyEnd is an end of the flows of a Policy: a Node with one of the tags, any Node when it
// names none, whose address is in one of the prefixes, any address when it names none.
type PolicyEnd struct {
	Tags []string `json:"tags,omitempty"`
	// Addresses are IPv4 or IPv6 prefixes without host bits, or single addresses.
	Addresses []string `json:"addresses,omitempty"`
}

// PolicyValue is the protocol or a port of a Policy, which a document may give as a number or as
// a string. It holds the string.
type PolicyValue string

// UnmarshalJSON takes a JSON string, or a JSON number as it is written.
func (v *PolicyValue) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = PolicyValue(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("a protocol or a port is a number or a string")
	}
	*v = PolicyValue(n.String())
	return nil
}

// Rule is a Policy as the Nodes of its VRF enforce it (Rules): its values parsed and its priority
// filled in.
type Rule struct {
	Name     string
	VRF      string
	Priority uint32
	Deny     bool
	From, To RuleEnd
	Protocol uint8       // the IP protocol, 0 for any
	Ports    []PortRange // the destination ports, none for any
}

// RuleEnd is an end of the flows of a Rule.
type RuleEnd struct {
	Tags     []string
	Prefixes []netip.Prefix
}

// PortRange is the ports from First to Last.
type PortRange struct {
	First, Last uint16
}

// Holds reports whether a Node with the tags can be the end e: e names no tag, or one of them.
func (e RuleEnd) Holds(tags []string) bool {
	return len(e.Tags) == 0 || slices.ContainsFunc(e.Tags, func(t string) bool { return slices.Contains(tags, t) })
}

// Rules returns the Policies of in as their Nodes enforce them, ordered by VRF, then name. A
// Policy whose values do not parse is left out: in is an intent that Apply returned.
func (in Intent) Rules() []Rule {
	var out []Rule
	for _, name := range sortedNames(in.Policies) {
		if r, err := in.Policies[name].rule(name); err == nil {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b Rule) int { return cmp.Compare(a.VRF, b.VRF) })
	return out
}

// rule parses the Policy p of the name name.
func (p Policy) rule(name string) (Rule, error) {
	r := Rule{Name: name, VRF: p.VRF, Priority: p.Priority, Deny: p.Action != PolicyAllow}
	if r.Priority == 0 {
		r.Priority = DefaultPriority
	}
	var err error
	if r.From, err = p.From.parse("from"); err != nil {
		return Rule{}, err
	}
	if r.To, err = p.To.parse("to"); err != nil {
		return Rule{}, err
	}
	if r.Protocol, err = parsePolicyProtocol(p.Protocol); err != nil {
		return Rule{}, err
	}
	if len(p.Ports) > MaxPolicyValues {
		return Rule{}, fmt.Errorf("%d ports, at most %d", len(p.Ports), MaxPolicyValues)
	}
	for _, v := range p.Ports {
		pr, err := parsePolicyPorts(v)
		if err != nil {
			return Rule{}, err
		}
		r.Ports = append(r.Ports, pr)
	}
	if len(r.Ports) > 0 && r.Protocol != 6 && r.Protocol != 17 {
		return Rule{}, errors.New("ports are for the protocol tcp or udp only")
	}
	return r, nil
}

// parse parses the end e of a Policy, which is its end where (from or to). Its tags are sorted
// (completePolicies).
func (e PolicyEnd) parse(where string) (RuleEnd, error) {
	if len(e.Tags) > MaxPolicyValues || len(e.Addresses) > MaxPolicyValues {
		return RuleEnd{}, fmt.Errorf("%s: %d tags and %d addresses, at most %d of each", where, len(e.Tags), len(e.Addresses), MaxPolicyValues)
	}
	for i, t := range e.Tags {
		if !nameRule.MatchString(t) {
			return RuleEnd{}, fmt.Errorf("%s: tag %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", where, t)
		}
		if i > 0 && e.Tags[i-1] == t {
			return RuleEnd{}, fmt.Errorf("%s: tag %q is listed twice", where, t)
		}
	}
	end := RuleEnd{Tags: slices.Clone(e.Tags)}
	for _, s := range e.Addresses {
		p, err := parsePolicyAddress(s)
		if err != nil {
			return RuleEnd{}, fmt.Errorf("%s: %w", where, err)
		}
		end.Prefixes = append(end.Prefixes, p)
	}
	return end, nil
}

// parsePolicyAddress parses an address of an end of a Policy: an IPv4 or IPv6 prefix without host
// bits, or one address, which is the prefix of its whole length.
func parsePolicyAddress(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if a, aerr := netip.ParseAddr(s); aerr == nil {
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("address %q has a zone", s)
		}
		p, err = netip.PrefixFrom(a, a.BitLen()), nil
	}
	switch {
	case err != nil:
		return netip.Prefix{}, fmt.Errorf("address %q is neither an IP address nor a prefix", s)
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("address %q is an IPv4-mapped IPv6 address: write it as IPv4", s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("address %q has host bits set, the prefix is %s", s, p.Masked())
	}
	return p, nil
}

// policyAddress writes the prefix p of an end of a Policy in its one form: an address alone for
// the prefix of its whole length.
func policyAddress(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// The IP protocols that a Policy names by name
var policyProtocols = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17}

// parsePolicyProtocol parses the protocol of a Policy: tcp, udp, icmp, or the number of an IP
// protocol from 1 to 255. It returns the number, and 0 for none, which takes every protocol.
func parsePolicyProtocol(v PolicyValue) (uint8, error) {
	s := string(v)
	if s == "" {
		return 0, nil
	}
	if n, ok := policyProtocols[s]; ok {
		return n, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil || n == 0 || s != strconv.FormatUint(n, 10) {
		return 0, fmt.Errorf("protocol %q is neither tcp, udp nor icmp, nor a number from 1 to 255", s)
	}
	return uint8(n), nil
}

// policyProtocolName writes the IP protocol n of a Policy in its one form: the name of TCP, UDP
// and ICMP, empty for any, else the number.
func policyProtocolName(n uint8) PolicyValue {
	switch n {
	case 0:
		return ""
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return PolicyValue(strconv.Itoa(int(n)))
}

// parsePolicyPorts parses a port of a Policy, or a range of them "first-last".
func parsePolicyPorts(v PolicyValue) (PortRange, error) {
	first, last, isRange := strings.Cut(string(v), "-")
	a, err := strconv.ParseUint(first, 10, 16)
	b := a
	if err == nil && isRange {
		b, err = strconv.ParseUint(last, 10, 16)
	}
	if err != nil || b < a {
		return PortRange{}, fmt.Errorf("port %q is not a port from 0 to 65535 or a range of them \"first-last\"", v)
	}
	return PortRange{First: uint16(a), Last: uint16(b)}, nil
}

// value writes the ports r in the one form of a port of a Policy.
func (r PortRange) value() PolicyValue {
	if r.First == r.Last {
		return PolicyValue(strconv.Itoa(int(r.First)))
	}
	return PolicyValue(fmt.Sprintf("%d-%d", r.First, r.Last))
}

// canonical returns e in its one form: its tags sorted and its addresses as policyAddress writes
// them. An end that names nothing is the zero end, which a document leaves out.
func (e PolicyEnd) canonical() PolicyEnd {
	var out PolicyEnd
	if len(e.Tags) > 0 {
		out.Tags = slices.Sorted(slices.Values(e.Tags))
	}
	for _, s := range e.Addresses {
		if p, err := parsePolicyAddress(s); err == nil {
			s = policyAddress(p)
		}
		out.Addresses = append(out.Addresses, s)
	}
	return out
}

// completePolicies writes the values of each Policy of in in their one form: its ends as
// canonical makes them, its protocol by name where it has one and its ports as value writes them.
// A value that does not parse stays as it is, for validate to refuse.
func (in Intent) completePolicies() {
	for name, p := range in.Policies {
		p.From = p.From.canonical()
		p.To = p.To.canonical()
		if n, err := parsePolicyProtocol(p.Protocol); err == nil {
			p.Protocol = policyProtocolName(n)
		}
		for i, v := range p.Ports {
			if r, err := parsePolicyPorts(v); err == nil {
				p.Ports[i] = r.value()
			}
		}
		in.Policies[name] = p
	}
}

// clonePolicies gives each Policy of policies slices of its own (Clone).
func clonePolicies(policies map[string]Policy) {
	for name, p := range policies {
		p.From = PolicyEnd{Tags: slices.Clone(p.From.Tags), Addresses: slices.Clone(p.From.Addresses)}
		p.To = PolicyEnd{Tags: slices.Clone(p.To.Tags), Addresses: slices.Clone(p.To.Addresses)}
		p.Ports = slices.Clone(p.Ports)
		policies[name] = p
	}
}

// validatePolicies checks the conntrack of each VRF and the values of each Policy of a completed
// intent. The VRF and the action of a Policy are checked with the other resources (validate).
func (in Intent) validatePolicies() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		c := in.VRFs[name].Conntrack
		if c.MaxFlows > MaxFlows {
			problems = append(problems, fmt.Errorf("VRF %q: conntrack.maxFlows %d is more than %d", name, c.MaxFlows, MaxFlows))
		}
		t := c.Timeouts
		for _, timeout := range []struct {
			key     string
			seconds uint32
		}{{"tcpEstablished", t.TCPEstablished}, {"tcpTransitory", t.TCPTransitory}, {"udp", t.UDP}, {"icmp", t.ICMP}, {"other", t.Other}} {
			if timeout.seconds > MaxTimeout {
				problems = append(problems, fmt.Errorf("VRF %q: conntrack.timeouts.%s %d is more than %d seconds", name, timeout.key, timeout.seconds, MaxTimeout))
			}
		}
	}
	for _, name := range sortedNames(in.Policies) {
		p := in.Policies[name]
		if p.Priority > MaxPriority {
			problems = append(problems, fmt.Errorf("Policy %q: priority %d is more than %d", name, p.Priority, MaxPriority))
		}
		if _, err := p.rule(name); err != nil {
			problems = append(problems, fmt.Errorf("Policy %q: %w", name, err))
		}
	}
	return problems
}
