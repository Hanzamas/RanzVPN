package desired

import (
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The policy of the VRFs (SDN-8 #184, ADR-0029): every VRF of a node carries its policy, the
// conntrack quota of the VRF and the timeouts of its flows (Vrf.policy), and the node enforces
// the rules of a VRF that has it, default deny. The node gets as Rule objects the rules of its
// VRFs that can match a flow with one end at the node: a rule whose from or to end names no tag
// or a tag of the node. Every flow that a node judges has one end at the node, its host, so a
// rule whose two ends name only tags that the node does not have never matches there. The tags
// of each Peer identify the other end of a flow to the rules.

// vrfPolicy returns the policy of the VRF v as the control protocol carries it with the VRF.
func vrfPolicy(v intent.VRF) *controlpb.VrfPolicy {
	t := v.Conntrack.Timeouts
	return &controlpb.VrfPolicy{MaxFlows: v.Conntrack.MaxFlows, TcpEstablished: t.TCPEstablished, TcpTransitory: t.TCPTransitory,
		Udp: t.UDP, Icmp: t.ICMP, Other: t.Other}
}

// nodeRules returns the rules that each Node of in enforces, by Node name, ordered by VRF name,
// then rule name: the rules of its VRFs whose from or to end can be the Node. A Node without one
// has no entry.
func nodeRules(in intent.Intent, vrfs map[string]*controlpb.Vrf) map[string][]*controlpb.Rule {
	out := map[string][]*controlpb.Rule{}
	for _, r := range in.Rules() {
		rule := &controlpb.Rule{Name: r.Name, VrfId: vrfs[r.VRF].GetId(), Priority: r.Priority, Action: controlpb.RuleAction_RULE_ACTION_ALLOW,
			From: ruleEnd(r.From), To: ruleEnd(r.To), Protocol: uint32(r.Protocol)}
		if r.Deny {
			rule.Action = controlpb.RuleAction_RULE_ACTION_DENY
		}
		for _, p := range r.Ports {
			rule.Ports = append(rule.Ports, &controlpb.PortRange{First: uint32(p.First), Last: uint32(p.Last)})
		}
		for name, n := range in.Nodes {
			// A gateway judges the flows of its Devices too (device.go; SDN-80)
			if slices.Contains(n.VRFs, r.VRF) && (r.From.Holds(n.Tags) || r.To.Holds(n.Tags) || gatewayHolds(in, name, r)) {
				out[name] = append(out[name], rule)
			}
		}
	}
	return out
}

// ruleEnd returns the end e of a rule as the control protocol carries it, nil for an end that
// names nothing: any end.
func ruleEnd(e intent.RuleEnd) *controlpb.RuleEnd {
	if len(e.Tags) == 0 && len(e.Prefixes) == 0 {
		return nil
	}
	out := &controlpb.RuleEnd{Tags: e.Tags}
	for _, p := range e.Prefixes {
		out.Prefixes = append(out.Prefixes, prefix(p))
	}
	return out
}
