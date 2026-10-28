package intent

import "encoding/json"

// The intent of a first install (ADR-0034, SDN-3 #179). The first start of a controller creates
// VRF default with overlay DNS on, its Network default with the automatic IPv4 pool, from which
// the controller allocates the addresses of its Nodes, and the explicit starter rule that allows
// all traffic inside VRF default. Its topology is full mesh, the one of every VRF so far, and a
// Node that names no VRF joins it (complete).

const (
	// DefaultVRF is the VRF of a first install.
	DefaultVRF = "default"
	// DefaultNetwork is its Network.
	DefaultNetwork = "default"
	// DefaultPool is the automatic IPv4 pool of that Network: the shared address space of RFC
	// 6598, which LANs do not use.
	DefaultPool = "100.64.0.0/10"
	// StarterRule is the Policy that allows all traffic inside VRF default.
	StarterRule = "default-allow-all"
	// StarterRuleNote says what the starter rule does and how to narrow it, for the log of the first
	// start and for `ranz status` (AUD1-DT-6, #454): the Policies of the operator first, so that the
	// traffic that they allow never stops, and then the delete of the rule.
	StarterRuleNote = "the starter rule " + StarterRule + " allows all traffic inside VRF " + DefaultVRF +
		": narrow it by applying Policies of your own and then deleting it (ranz delete Policy " + StarterRule + "), as docs/first-test.md shows"
	// OpFirstStart is the operation of the revision that the first start made.
	OpFirstStart = "first-start"
)

// FirstInstall returns the document that the first start of a controller applies.
func FirstInstall() Document {
	return Document{Resources: []Resource{
		resource(KindVRF, DefaultVRF, VRF{DNS: true}),
		resource(KindNetwork, DefaultNetwork, Network{VRF: DefaultVRF, IPv4Pool: DefaultPool}),
		resource(KindPolicy, StarterRule, Policy{VRF: DefaultVRF, Action: PolicyAllow}),
	}}
}

// IsStarterRule reports whether r is the starter rule as the first start made it: the Policy
// StarterRule, which allows all traffic inside VRF default. A rule of that name that an operator
// narrowed in place, with an end, a protocol or ports, or turned into a deny rule or into a rule of
// another VRF, no longer allows all, and is not the starter rule. A priority narrows nothing, so it
// does not count (AUD1-DT-6, #454).
func IsStarterRule(r Resource) bool {
	if r.Kind != KindPolicy || r.Name != StarterRule {
		return false
	}
	var p Policy
	if json.Unmarshal(r.Spec, &p) != nil {
		return false
	}
	return p.VRF == DefaultVRF && p.Action == PolicyAllow &&
		len(p.From.Tags) == 0 && len(p.From.Addresses) == 0 && len(p.To.Tags) == 0 && len(p.To.Addresses) == 0 &&
		p.Protocol == "" && len(p.Ports) == 0
}
