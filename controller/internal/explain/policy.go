package explain

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The policy of a VRF as a Node enforces it (src/Cedar/NodePolicy.c on the policy engine of src/Core/Policy*.c). The
// engine runs one Network for each VRF that has its policy, with the rules of that VRF that the Node got, and judges
// the first packet of a flow from one member to another: the first rule by priority, a deny rule before an allow rule
// of one priority, then by name, whose two ends hold the two members and their addresses, and whose protocol and
// ports hold the packet; the default action denies a flow that no rule matches. The members of a VRF at a Node are
// its host with the tags of the Node, each peer that shares the VRF with the tags of its Peer object, the end outside
// the VRF without a tag, which every other next hop is, a route that another VRF leaks among them, and each WireGuard
// Device of the VRF with its tags, found by its address.

// end is an end of a flow as the policy engine sees it: the tags of its member, and what it is, for a step.
type end struct {
	tags []string
	what string
}

// rule is a Rule object as the Node enforces it (ControlCopyRule).
type rule struct {
	name     string
	priority uint32
	allow    bool
	from, to *controlpb.RuleEnd // nil: any end
	protocol uint32             // 0 for any; 1 takes ICMP of either family
	ports    [][2]uint32
}

// policyRules returns the rules of the VRF vrf of n in the order that the engine judges them. An allow rule that the
// Node cannot read whole is left out; a deny rule that it cannot read whole denies every flow of its VRF.
func (n *node) policyRules(vrf uint32) []rule {
	var out []rule
	for _, r := range n.rules {
		if r.GetVrfId() != vrf {
			continue
		}
		x := rule{name: r.GetName(), priority: min(r.GetPriority(), 1000000), allow: r.GetAction() == controlpb.RuleAction_RULE_ACTION_ALLOW,
			from: r.GetFrom(), to: r.GetTo(), protocol: r.GetProtocol()}
		ok := x.protocol <= 255 && (len(r.GetPorts()) == 0 || x.protocol == protoTCP || x.protocol == protoUDP) && readable(x.from) && readable(x.to)
		for _, p := range r.GetPorts() {
			ok = ok && p.GetFirst() <= p.GetLast() && p.GetLast() <= 65535
			x.ports = append(x.ports, [2]uint32{p.GetFirst(), p.GetLast()})
		}
		if !ok {
			if x.allow {
				continue
			}
			x = rule{name: x.name, priority: x.priority}
		}
		out = append(out, x)
	}
	slices.SortStableFunc(out, func(a, b rule) int {
		deny := func(r rule) int {
			if r.allow {
				return 1
			}
			return 0
		}
		return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(deny(a), deny(b)), cmp.Compare(a.name, b.name))
	})
	return out
}

// readable reports whether the Node reads an end of a rule whole: each of its prefixes IPv4 or IPv6, no longer than
// its address.
func readable(e *controlpb.RuleEnd) bool {
	for _, p := range e.GetPrefixes() {
		if _, ok := prefixOf(p); !ok {
			return false
		}
	}
	return true
}

// judge returns the first rule of the VRF vrf of n that matches the flow that the packet p opens from the end from to
// the end to, as the overlay sees it; nil for none, which the default action denies.
func (n *node) judge(vrf uint32, p packet, from, to end) *rule {
	for _, r := range n.policyRules(vrf) {
		if r.matches(p, from, to) {
			return &r
		}
	}
	return nil
}

// matches reports whether r holds the flow that the packet p opens from the end from to the end to (PolicyMatch).
func (r rule) matches(p packet, from, to end) bool {
	icmp := (p.src.Is4() && p.proto == protoICMP) || (p.src.Is6() && p.proto == protoICMPv6)
	switch {
	case r.protocol == 0:
	case r.protocol == protoICMP:
		// ICMP of the family of the packet
		if !icmp {
			return false
		}
	case uint32(p.proto) != r.protocol:
		return false
	}
	if len(r.ports) != 0 {
		if p.proto != protoTCP && p.proto != protoUDP {
			return false
		}
		if !slices.ContainsFunc(r.ports, func(x [2]uint32) bool { return x[0] <= uint32(p.dport) && uint32(p.dport) <= x[1] }) {
			return false
		}
	}
	return holds(r.from, from, p.src) && holds(r.to, to, p.dst)
}

// holds reports whether the end e of a rule holds the end of a flow whose member is who and whose address is a: one of
// its tags is a tag of the member, without case, and one of its prefixes holds the address; an end that names no tag,
// or no prefix, holds any.
func holds(e *controlpb.RuleEnd, who end, a netip.Addr) bool {
	if e == nil {
		return true
	}
	if len(e.GetTags()) != 0 && !slices.ContainsFunc(e.GetTags(), func(t string) bool {
		return slices.ContainsFunc(who.tags, func(u string) bool { return strings.EqualFold(t, u) })
	}) {
		return false
	}
	if len(e.GetPrefixes()) != 0 && !slices.ContainsFunc(e.GetPrefixes(), func(x *controlpb.Prefix) bool {
		p, ok := prefixOf(x)
		return ok && p.Contains(a)
	}) {
		return false
	}
	return true
}

// hostEnd is the host of n as a member of its VRFs: the tags of the Node.
func (n *node) hostEnd(vrf uint32) end {
	return end{tags: n.self.GetTags(), what: "the host of " + n.name}
}

// hopEnd is the next hop hop of the forwarding tables of n as a member of the VRF vrf: the peer with its tags when it
// shares the VRF, else the end outside the VRF, which has no tag, as for every route that another VRF leaks.
func (n *node) hopEnd(vrf uint32, next uint32) end {
	if int(next) < len(n.peers) {
		peer := n.peers[next]
		if slices.Contains(peer.GetVrfIds(), vrf) {
			return end{tags: peer.GetTags(), what: peer.GetName()}
		}
	}
	if int(next) < len(n.hops) {
		return end{what: fmt.Sprintf("the end outside the VRF, which %s is to it", n.peers[n.hops[next].peer].GetName())}
	}
	return end{what: "the end outside the VRF"}
}

// deviceEnds puts the WireGuard Devices of the VRF vrf of n in place of the ends of the packet p that they are
// (NodePolicyDeviceEnds): a Device that n terminates is the end at the host, any other the end at the peer, found by
// the source of a packet out of the host and the destination of one in to it, and the other way round.
func (n *node) deviceEnds(vrf uint32, p packet, out bool, host, peer *end) {
	for _, d := range n.devices {
		if d.GetVrfId() != vrf {
			continue
		}
		localDevice := len(d.GetPublicKey()) != 0 && d.GetGateway() == n.name
		for _, x := range d.GetAddresses() {
			a, ok := hostPrefix(x.GetPrefix())
			if !ok {
				continue
			}
			who := end{tags: d.GetTags(), what: "the WireGuard Device " + d.GetName()}
			atHost, atPeer := p.src, p.dst
			if !out {
				atHost, atPeer = p.dst, p.src
			}
			if localDevice && a.Addr() == atHost {
				*host = who
			} else if !localDevice && a.Addr() == atPeer {
				*peer = who
			}
		}
	}
}
