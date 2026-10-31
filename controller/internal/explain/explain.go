// Package explain answers `ranz explain A B` (ADR-0031 decisions 7 and 8; SDN-15, #191). It walks the
// compiled model of the Controller, the desired state of each Node (internal/desired) as the Controller sends
// it and as the data plane of the Node runs it, for one packet from A to B, and names each step on the way:
// the VRF, the route of the forwarding table that the packet takes (with the VRF that a leaked route comes from
// and the route targets that leak it), the 1:1 NAT rules that rewrite its addresses, the link to the next Node
// with the endpoints that it is dialled at, and the rule of the policy of the VRF that judges it at each end.
//
// The walk follows the data plane of a Node (src/Cedar/NodeOverlay.c with NodeLeak.c, NodeNat.c and
// NodePolicy.c): the same forwarding tables from the same objects of the state, the same order of the checks,
// and the same first rule of the policy engine (src/Core/PolicyRules.c). At the Node that sends the packet:
// its 1:1 NAT rules, the source that must be its own, the route of the destination, the policy of the VRF on
// the way out and the link; at the Node that the route leads to: the VRF that the record names, the route of
// the source back to the sender, the destination that must be its own, the policy of the VRF on the way in and
// its 1:1 NAT rules. The packet is the first of a flow, which the rules judge; the replies of an allowed flow
// pass on the conntrack tables of both ends. The scenarios of tests/explain check that explain cannot drift
// from what forwarding does (scenario.go): each runs through Explain and through the data plane of the vpntest
// harness, and the two must give the same verdict for each packet.
package explain

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The kinds of a Step.
const (
	StepVRF    = "vrf"    // the VRF of the packet at a Node
	StepNAT    = "nat"    // a 1:1 NAT rule of a Node rewrote an address
	StepRoute  = "route"  // a route of the forwarding table of a VRF of a Node
	StepLink   = "link"   // the link from one Node to the next
	StepPolicy = "policy" // the rule of the policy of a VRF that judged the packet at a Node
)

// The reasons of a Verdict that drops the packet.
const (
	DropRoute  = "route"  // no route takes it, or the route of an end is not the one that the data plane needs
	DropNAT    = "nat"    // a 1:1 NAT rule holds an address that it cannot translate
	DropPolicy = "policy" // a rule of the policy of the VRF, or its default action, denies it
	DropLink   = "link"   // the link of kind vxlan or geneve has no tunnel endpoint of the next Node
)

// DefaultDeny names the default action of the policy of a VRF, which denies every flow that no rule allows, as the
// counters of the policy engine name it (src/Core/PolicyRules.c).
const DefaultDeny = "default:deny"

// Query is the packet that `ranz explain A B` asks about.
type Query struct {
	// From is a Node, which sends the packet from its address in the VRF, the name of a WireGuard Device, or an
	// address of a Node, of the inside of one of its 1:1 NAT rules or of a Device.
	From string `json:"from"`
	// To is a Node, then the packet goes to its address as the VRF of From routes it, a Device, or an IP address.
	To string `json:"to"`
	// VRF is the VRF of From that the packet is sent in. Left out, it is the VRF of the address From, the one VRF of
	// the Node From, or the first VRF of From in name order whose forwarding table leads To to another Node.
	VRF string `json:"vrf,omitempty"`
	// Protocol is tcp, udp, icmp or the number of an IP protocol; icmp, an echo request, when it is left out. A
	// packet of TCP is the SYN that opens a flow.
	Protocol string `json:"protocol,omitempty"`
	// SourcePort and Port are the source and the destination port of TCP and UDP.
	SourcePort uint16 `json:"sourcePort,omitempty"`
	Port       uint16 `json:"port,omitempty"`
}

// Packet is the packet that a Result follows, as the host of the Node that sends it sees it.
type Packet struct {
	Node        string     `json:"node"`
	VRF         string     `json:"vrf"`
	VRFID       uint32     `json:"vrfId"`
	Protocol    uint8      `json:"protocol"`
	Source      netip.Addr `json:"source"`
	Destination netip.Addr `json:"destination"`
	SourcePort  uint16     `json:"sourcePort,omitempty"`
	Port        uint16     `json:"port,omitempty"`
}

// String says the packet as the steps name it: "udp 10.0.0.1:40000 > 10.0.0.2:53".
func (p Packet) String() string {
	return packet{proto: p.Protocol, src: p.Source, dst: p.Destination, sport: p.SourcePort, dport: p.Port}.String()
}

// Route is the route of a StepRoute.
type Route struct {
	// Prefix is the prefix of the route that the lookup matched.
	Prefix netip.Prefix `json:"prefix"`
	// Next is the Node that the route leads to; empty for a route to the host of the Node itself.
	Next string `json:"next,omitempty"`
	// Leaked is the VRF of Next that a route that a VRF leaks takes the packet into, with the route targets that it
	// exports and the VRF of the route imports; empty for a route of the VRF itself.
	Leaked       string   `json:"leaked,omitempty"`
	RouteTargets []string `json:"routeTargets,omitempty"`
	// What says what the route is: an address of a Node, the outside prefix of a 1:1 NAT rule, a route that a VRF
	// leaks, or an address of a Device.
	What string `json:"what"`
}

// NAT is the 1:1 NAT rule of a StepNAT, and the address that it rewrote.
type NAT struct {
	// Name is the NAT resource of the rule, or "4via6" for the 4via6 of the VRF.
	Name    string       `json:"name"`
	Inside  netip.Prefix `json:"inside"`
	Outside netip.Prefix `json:"outside"`
	From    netip.Addr   `json:"from"`
	To      netip.Addr   `json:"to"`
}

// Rule is the rule of a StepPolicy.
type Rule struct {
	// Name is the Policy of the rule, or DefaultDeny for the default action of the VRF, or empty when the VRF has no
	// policy at the Node and nothing judges the packet.
	Name     string `json:"name,omitempty"`
	Priority uint32 `json:"priority,omitempty"`
	Allow    bool   `json:"allow"`
	// Out is true for the policy of the Node that sends the packet, on its way out; false on its way in.
	Out bool `json:"out"`
}

// Endpoint is an endpoint of a Node: an address under which the other Nodes reach it, over one transport.
type Endpoint struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
}

// Link is the link of a StepLink.
type Link struct {
	// Peer is the Node that the link leads to.
	Peer string `json:"peer"`
	// Kind is noise, vxlan or geneve, and Encrypted says whether the link encrypts the packet: the Noise session does,
	// a link of kind vxlan or geneve is plain, on a network that the operator trusts (SDN-76).
	Kind      string `json:"kind"`
	Encrypted bool   `json:"encrypted"`
	VNI       uint32 `json:"vni,omitempty"`
	// Endpoints are the endpoints of Peer, which the sending Node dials it at in this order; SourceEndpoints those of
	// the sending Node (SDN-93). A Node without endpoints is dialled by no peer, so it dials them.
	Endpoints       []Endpoint `json:"endpoints,omitempty"`
	SourceEndpoints []Endpoint `json:"sourceEndpoints,omitempty"`
}

// Step is one thing that the packet meets on its way.
type Step struct {
	Node  string `json:"node"`
	Kind  string `json:"kind"`
	VRF   string `json:"vrf,omitempty"`
	Route *Route `json:"route,omitempty"`
	NAT   *NAT   `json:"nat,omitempty"`
	Rule  *Rule  `json:"rule,omitempty"`
	Link  *Link  `json:"link,omitempty"`
	// Profile is the session profile of a StepProfile (profile.go; SDN-40).
	Profile *Profile `json:"profile,omitempty"`
	// Decoy is the decoy of the front door of a StepDecoy (decoy.go; AUD1-DT-4, #452).
	Decoy *Decoy `json:"decoy,omitempty"`
	// Text says the step in a sentence.
	Text string `json:"text"`
}

// Verdict is where the packet ends.
type Verdict struct {
	// Delivered is true when the host of Node takes the packet in VRF, with Source and Destination as it sees them;
	// else Node drops it, for Reason.
	Delivered   bool       `json:"delivered"`
	Node        string     `json:"node"`
	VRF         string     `json:"vrf,omitempty"`
	VRFID       uint32     `json:"vrfId,omitempty"`
	Source      netip.Addr `json:"source,omitzero"`
	Destination netip.Addr `json:"destination,omitzero"`
	Reason      string     `json:"reason,omitempty"`
	Text        string     `json:"text"`
}

// Result is the answer of Explain: the packet, each step on its way, and where it ends.
type Result struct {
	Packet  Packet  `json:"packet"`
	Steps   []Step  `json:"steps"`
	Verdict Verdict `json:"verdict"`
}

// Rules returns the rule that judged the packet at each Node, by Node name: the Policy, or DefaultDeny. A Node whose
// policy did not judge it has no entry.
func (r Result) Rules() map[string]string {
	out := map[string]string{}
	for _, s := range r.Steps {
		if s.Kind == StepPolicy && s.Rule != nil && s.Rule.Name != "" {
			out[s.Node] = s.Rule.Name
		}
	}
	return out
}

// Model is the compiled model that Explain walks: the desired state of each Node that the licence in force covers,
// and the intent that they were compiled from, which names what the states hold by number only: the VRFs of the
// leaked routes, the route targets of the leaks and the NAT resources.
type Model struct {
	in    intent.Intent
	nodes map[string]*node
}

// New returns the model of the desired states of the Nodes, by Node name, which desired.Compile made of in.
func New(in intent.Intent, states map[string]desired.State) *Model {
	m := &Model{in: in, nodes: map[string]*node{}}
	for name, s := range states {
		m.nodes[name] = newNode(name, s)
	}
	return m
}

// Explain walks the model for the packet of q. A query that names no Node, Device or address that the model knows,
// a VRF that the sender is not a member of, or a protocol that is none is ErrInvalid or ErrNotFound of the intent.
func (m *Model) Explain(q Query) (Result, error) {
	proto, err := intent.ParseProtocol(q.Protocol)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", intent.ErrInvalid, err)
	}
	if proto == 0 {
		proto = protoICMP
	}
	s, vrf, src, dst, err := m.ends(q)
	if err != nil {
		return Result{}, err
	}
	if proto == protoICMP && dst.Is6() {
		proto = protoICMPv6
	}
	p := packet{proto: proto, src: src, dst: dst}
	if proto == protoTCP || proto == protoUDP {
		p.sport, p.dport = q.SourcePort, q.Port
	}
	w := &walk{m: m, res: Result{Packet: Packet{Node: s.name, VRF: m.vrfName(vrf), VRFID: vrf, Protocol: proto, Source: src, Destination: dst,
		SourcePort: p.sport, Port: p.dport}}}
	w.send(s, vrf, p)
	return w.res, nil
}

// walk is one packet on its way through the model.
type walk struct {
	m   *Model
	res Result
}

// step adds a step of the Node n of the kind in the VRF vrf (0 for none), with what it holds and its text.
func (w *walk) step(n *node, kind string, vrf uint32, s Step, format string, args ...any) {
	s.Node, s.Kind = n.name, kind
	if vrf != 0 {
		s.VRF = w.m.vrfName(vrf)
	}
	s.Text = fmt.Sprintf(format, args...)
	w.res.Steps = append(w.res.Steps, s)
}

// drop ends the walk: the Node n drops the packet for the reason.
func (w *walk) drop(n *node, reason, format string, args ...any) {
	w.res.Verdict = Verdict{Node: n.name, Reason: reason, Text: fmt.Sprintf(format, args...)}
}

// send is the packet p of the host of the Node s in the VRF vrf, as NodeOverlayInput takes it: through the 1:1 NAT
// rules of s, the forwarding table of the VRF, its policy on the way out and the link of the route.
func (w *walk) send(s *node, vrf uint32, p packet) {
	if !s.hasTable(vrf) {
		w.drop(s, DropRoute, "%s has no forwarding table of VRF %s: no address of the VRF leads anywhere on it", s.name, w.m.vrfName(vrf))
		return
	}
	w.step(s, StepVRF, vrf, Step{}, "the host of %s sends %s in VRF %s (id %d)", s.name, p, w.m.vrfName(vrf), vrf)

	// The overlay sees the packet through the 1:1 NAT rules of the sender (NodeNatEnds)
	out, ok := w.translate(s, vrf, p, true)
	if !ok {
		w.drop(s, DropNAT, "%s cannot translate %s between the families of its 1:1 NAT rules", s.name, p)
		return
	}

	// Only a packet from an address of the sender itself goes, and only to a peer
	if r, ok := s.lookup(vrf, out.src); !ok || r.hop != local {
		w.drop(s, DropRoute, "the source %s is no address of %s in VRF %s: the overlay takes a packet of the host only from its own addresses", out.src, s.name, w.m.vrfName(vrf))
		return
	}
	r, ok := s.lookup(vrf, out.dst)
	if !ok {
		w.drop(s, DropRoute, "no route of VRF %s at %s holds %s", w.m.vrfName(vrf), s.name, out.dst)
		return
	}
	if r.hop == local {
		w.step(s, StepRoute, vrf, Step{Route: &Route{Prefix: r.prefix, What: r.what}}, "%s: %s leads to the host of %s itself", r.prefix, r.what, s.name)
		w.drop(s, DropRoute, "%s is an address of %s itself: the overlay sends a packet of the host only to a peer", out.dst, s.name)
		return
	}
	h := s.hops[r.hop]
	peer := s.peers[h.peer]
	into := vrf
	route := &Route{Prefix: r.prefix, Next: peer.GetName(), What: r.what}
	if h.vrf != 0 {
		// A route that a VRF of the peer leaks takes the packet into that VRF (NodeLeakVrf)
		into = h.vrf
		route.Leaked = w.m.vrfName(h.vrf)
		route.RouteTargets = w.m.routeTargets(h.vrf, vrf)
		w.step(s, StepRoute, vrf, Step{Route: route}, "%s leads to %s: a route that VRF %s leaks into VRF %s through the route targets %s, so the packet goes into VRF %s of %s",
			r.prefix, peer.GetName(), route.Leaked, w.m.vrfName(vrf), strings.Join(route.RouteTargets, ", "), route.Leaked, peer.GetName())
	} else {
		w.step(s, StepRoute, vrf, Step{Route: route}, "%s leads to %s: %s", r.prefix, peer.GetName(), r.what)
	}

	// The session profile of the peer and the one of the sender judge it before the policy (NodeProfileOutbound)
	if !w.profile(s, vrf, out, r.hop, true) {
		return
	}
	// The policy of the VRF judges the packet as the overlay sees it, after the 1:1 NAT rules (NodePolicyOutbound)
	if !w.judge(s, vrf, out, r.hop, true) {
		return
	}

	// The link of the VRF of the record carries it: a link of kind vxlan or geneve in place of the session
	kind, vni := s.linkOf(into)
	link := &Link{Peer: peer.GetName(), Kind: kind, Encrypted: kind == linkNoise, VNI: vni, Endpoints: endpoints(peer.GetEndpoints()), SourceEndpoints: endpoints(s.self.GetEndpoints())}
	if kind != linkNoise && len(peer.GetVtep().GetAddress()) == 0 {
		w.step(s, StepLink, into, Step{Link: link}, "the link to %s in VRF %s is of kind %s, unencrypted, and %s has no tunnel endpoint", peer.GetName(), w.m.vrfName(into), kind, peer.GetName())
		w.drop(s, DropLink, "%s has no tunnel endpoint for the link of kind %s of VRF %s", peer.GetName(), kind, w.m.vrfName(into))
		return
	}
	w.step(s, StepLink, into, Step{Link: link}, "%s", linkText(s, peer, link, w.m.vrfName(into)))

	next, ok := w.m.nodes[peer.GetName()]
	if !ok {
		w.res.Verdict = Verdict{Node: peer.GetName(), Reason: DropRoute, Text: fmt.Sprintf("%s has no desired state: it does not run the VRF", peer.GetName())}
		return
	}
	// The session arrives at the front door of the next Node, where a prober arrives too (decoy.go)
	w.frontDoor(next, link)
	w.receive(s, next, into, out)
}

// receive is the packet p that the Node s sent to the Node n in the VRF vrf, as NodeOverlayDeliver takes it: the
// forwarding table of the VRF must route its source back to s and its destination to the host of n, then the
// policy of the VRF judges it, and the 1:1 NAT rules of n give it to the host.
func (w *walk) receive(s, n *node, vrf uint32, p packet) {
	if !n.hasTable(vrf) {
		w.drop(n, DropRoute, "%s has no forwarding table of VRF %s, which the record names", n.name, w.m.vrfName(vrf))
		return
	}
	back, ok := n.lookup(vrf, p.src)
	if !ok || back.hop == local || n.peers[n.hops[back.hop].peer].GetName() != s.name {
		w.drop(n, DropRoute, "VRF %s at %s does not route the source %s back to %s: a Node takes a packet of a peer only from the addresses that its VRF routes to that peer, so traffic follows a leak both ways only",
			w.m.vrfName(vrf), n.name, p.src, s.name)
		return
	}
	w.step(n, StepRoute, vrf, Step{Route: &Route{Prefix: back.prefix, Next: s.name, What: back.what}}, "the source %s routes back to %s in VRF %s: %s", p.src, s.name, w.m.vrfName(vrf), back.what)
	to, ok := n.lookup(vrf, p.dst)
	if !ok || to.hop != local {
		w.drop(n, DropRoute, "the destination %s is no address of %s in VRF %s", p.dst, n.name, w.m.vrfName(vrf))
		return
	}
	w.step(n, StepRoute, vrf, Step{Route: &Route{Prefix: to.prefix, What: to.what}}, "%s leads to the host of %s: %s", to.prefix, n.name, to.what)

	// The session profile of the sender and the one of n judge it before the policy (NodeProfileInbound)
	if !w.profile(n, vrf, p, back.hop, false) {
		return
	}
	// The policy of the VRF judges the packet as the peer sent it, before the 1:1 NAT rules (NodePolicyInbound)
	if !w.judge(n, vrf, p, back.hop, false) {
		return
	}

	// The host takes the packet as its 1:1 NAT rules show it (NodeNatInbound)
	in, ok := w.translate(n, vrf, p, false)
	if !ok {
		w.drop(n, DropNAT, "%s cannot translate %s between the families of its 1:1 NAT rules", n.name, p)
		return
	}
	w.res.Verdict = Verdict{Delivered: true, Node: n.name, VRF: w.m.vrfName(vrf), VRFID: vrf, Source: in.src, Destination: in.dst,
		Text: fmt.Sprintf("the host of %s takes %s in VRF %s", n.name, in, w.m.vrfName(vrf))}
}

// translate gives the packet p of the VRF vrf of the Node n through its 1:1 NAT rules, out of the host into the
// overlay or in from the overlay to the host, with a step for each address that a rule rewrites. False when the
// rules take its two addresses into two families, which the data plane drops.
func (w *walk) translate(n *node, vrf uint32, p packet, out bool) (packet, bool) {
	q := p
	for _, a := range []*netip.Addr{&q.src, &q.dst} {
		to, rules := n.mapAddr(vrf, *a, out)
		from := *a
		for _, r := range rules {
			nat := &NAT{Name: w.m.natName(n.name, vrf, r), Inside: r.inside, Outside: r.outside, From: from, To: r.apply(from, out)}
			way := "the host's %s is %s in the VRF"
			if !out {
				way = "%s of the VRF is %s for the host"
			}
			w.step(n, StepNAT, vrf, Step{NAT: nat}, "1:1 NAT rule %s of %s (inside %s, outside %s): "+way, nat.Name, n.name, r.inside, r.outside, nat.From, nat.To)
			from = nat.To
		}
		*a = to
	}
	return q, q.src.Is4() == q.dst.Is4()
}

// judge is the policy of the VRF vrf of the Node n for the packet p between its host and the next hop hop, on the
// way out of the host when out is set: a step with the rule that judged it, and false when that denied it, which
// ends the walk.
func (w *walk) judge(n *node, vrf uint32, p packet, hop uint32, out bool) bool {
	v := n.vrfs[vrf]
	if v == nil || v.GetPolicy() == nil {
		w.step(n, StepPolicy, vrf, Step{Rule: &Rule{Allow: true, Out: out}}, "VRF %s has no policy at %s: nothing judges the packet", w.m.vrfName(vrf), n.name)
		return true
	}
	host, peer := n.hostEnd(vrf), n.hopEnd(vrf, hop)
	n.deviceEnds(vrf, p, out, &host, &peer)
	from, to := host, peer
	if !out {
		from, to = peer, host
	}
	way := "on its way out of the host"
	if !out {
		way = "on its way in to the host"
	}
	r := n.judge(vrf, p, from, to)
	if r == nil {
		w.step(n, StepPolicy, vrf, Step{Rule: &Rule{Name: DefaultDeny, Out: out}}, "no rule of VRF %s at %s matches the flow from %s to %s %s: the default action denies it", w.m.vrfName(vrf), n.name, from.what, to.what, way)
		w.drop(n, DropPolicy, "the policy of VRF %s at %s denies the flow: no rule allows it", w.m.vrfName(vrf), n.name)
		return false
	}
	allow := r.allow
	action := "denies"
	if allow {
		action = "allows"
	}
	w.step(n, StepPolicy, vrf, Step{Rule: &Rule{Name: r.name, Priority: r.priority, Allow: allow, Out: out}}, "rule %s (priority %d) of VRF %s at %s %s the flow from %s to %s %s", r.name, r.priority, w.m.vrfName(vrf), n.name, action, from.what, to.what, way)
	if !allow {
		w.drop(n, DropPolicy, "rule %s of VRF %s at %s denies the flow", r.name, w.m.vrfName(vrf), n.name)
	}
	return allow
}

// linkText says the link to the peer in the VRF: its kind, whether it encrypts, and where the Nodes are dialled.
func linkText(s *node, peer *controlpb.Peer, l *Link, vrf string) string {
	var b strings.Builder
	if l.Encrypted {
		fmt.Fprintf(&b, "the Noise session of %s to %s carries the packet in VRF %s, encrypted", s.name, peer.GetName(), vrf)
	} else {
		fmt.Fprintf(&b, "the link of kind %s of VRF %s carries the packet on VNI %d to the tunnel endpoint of %s: unencrypted, plain on a network that the operator trusts", l.Kind, vrf, l.VNI, peer.GetName())
	}
	for _, e := range []struct {
		name string
		list []Endpoint
	}{{peer.GetName(), l.Endpoints}, {s.name, l.SourceEndpoints}} {
		if len(e.list) == 0 {
			fmt.Fprintf(&b, "; %s has no endpoints, so no peer dials it", e.name)
			continue
		}
		var at []string
		for _, ep := range e.list {
			at = append(at, ep.Transport+" "+ep.Address)
		}
		fmt.Fprintf(&b, "; %s is dialled at %s", e.name, strings.Join(at, ", "))
	}
	return b.String()
}

// endpoints returns the endpoints of a Node as the control protocol carries them.
func endpoints(list []*controlpb.Endpoint) []Endpoint {
	var out []Endpoint
	for _, e := range list {
		name := strings.ToLower(strings.TrimPrefix(e.GetTransport().String(), "TRANSPORT_"))
		out = append(out, Endpoint{Transport: name, Address: e.GetAddress()})
	}
	return out
}

//
// The ends of the packet
//

// ends resolves the sender of q, the VRF of the packet and its two addresses as the host of the sender sees them.
// Of the VRFs of a sender that q leaves to the destination, the first in name order whose forwarding table leads
// the destination to another Node is the one; without such a VRF, the first in which the destination resolves, so
// that the walk explains the drop.
func (m *Model) ends(q Query) (*node, uint32, netip.Addr, netip.Addr, error) {
	s, vrf, src, err := m.source(q)
	if err != nil {
		return nil, 0, netip.Addr{}, netip.Addr{}, err
	}
	vrfs := []uint32{vrf}
	if vrf == 0 {
		vrfs = s.vrfIDs()
	}
	if len(vrfs) == 0 {
		return nil, 0, netip.Addr{}, netip.Addr{}, fmt.Errorf("%w: Node %q is a member of no VRF", intent.ErrInvalid, s.name)
	}
	type choice struct {
		vrf      uint32
		src, dst netip.Addr
	}
	var first *choice
	var firstErr error
	for _, v := range vrfs {
		dst, err := m.destination(s, v, src, q.To)
		a := src
		if err == nil {
			a, err = m.sourceFor(s, v, src, dst)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if r, ok := s.lookup(v, dst); ok && r.hop != local {
			return s, v, a, dst, nil
		}
		if first == nil {
			first = &choice{v, a, dst}
		}
	}
	if first == nil {
		return nil, 0, netip.Addr{}, netip.Addr{}, firstErr
	}
	return s, first.vrf, first.src, first.dst, nil
}

// sourceFor returns the source of a packet of the VRF vrf of the Node n to dst: src when it is valid, else the
// address of n in the VRF of the family of dst.
func (m *Model) sourceFor(n *node, vrf uint32, src, dst netip.Addr) (netip.Addr, error) {
	if src.IsValid() {
		if src.Is4() != dst.Is4() {
			return netip.Addr{}, fmt.Errorf("%w: the source %s and the destination %s are of two families", intent.ErrInvalid, src, dst)
		}
		return src, nil
	}
	for _, a := range n.self.GetAddresses() {
		if p, ok := hostPrefix(a.GetPrefix()); ok && a.GetVrfId() == vrf && p.Addr().Is4() == dst.Is4() {
			return p.Addr(), nil
		}
	}
	family := 6
	if dst.Is4() {
		family = 4
	}
	return netip.Addr{}, fmt.Errorf("%w: Node %q has no IPv%d address in VRF %s", intent.ErrInvalid, n.name, family, m.vrfName(vrf))
}

// source resolves From and VRF of q: the Node that sends the packet, the VRF (0 when q leaves it to the
// destination) and the source address (invalid when it is the address of the Node in that VRF).
func (m *Model) source(q Query) (*node, uint32, netip.Addr, error) {
	var vrf uint32
	if q.VRF != "" {
		v, ok := m.in.VRFs[q.VRF]
		if !ok {
			return nil, 0, netip.Addr{}, fmt.Errorf("%w: VRF %q", intent.ErrNotFound, q.VRF)
		}
		vrf = v.ID
	}
	if a, err := netip.ParseAddr(q.From); err == nil {
		a = a.Unmap()
		var found []string
		var at *node
		var in uint32
		for _, name := range slices.Sorted(maps.Keys(m.nodes)) {
			n := m.nodes[name]
			if v, ok := n.holds(a, vrf); ok {
				found = append(found, name)
				at, in = n, v
			}
		}
		switch len(found) {
		case 0:
			return nil, 0, netip.Addr{}, fmt.Errorf("%w: no Node holds the address %s%s", intent.ErrNotFound, a, inVRF(q.VRF))
		case 1:
			return at, in, a, nil
		}
		return nil, 0, netip.Addr{}, fmt.Errorf("%w: the Nodes %s hold the address %s: name the VRF", intent.ErrInvalid, strings.Join(found, ", "), a)
	}
	if n, ok := m.nodes[q.From]; ok {
		if vrf != 0 && n.vrfs[vrf] == nil {
			return nil, 0, netip.Addr{}, fmt.Errorf("%w: Node %q is not a member of VRF %q", intent.ErrInvalid, q.From, q.VRF)
		}
		return n, vrf, netip.Addr{}, nil
	}
	if gw, d, ok := m.device(q.From); ok {
		if vrf != 0 && d.GetVrfId() != vrf {
			return nil, 0, netip.Addr{}, fmt.Errorf("%w: Device %q is not in VRF %q", intent.ErrInvalid, q.From, q.VRF)
		}
		a, _ := deviceAddress(d, true)
		return gw, d.GetVrfId(), a, nil
	}
	if _, ok := m.in.Nodes[q.From]; ok {
		return nil, 0, netip.Addr{}, fmt.Errorf("%w: Node %q has no desired state: the licence in force does not cover it", intent.ErrInvalid, q.From)
	}
	return nil, 0, netip.Addr{}, fmt.Errorf("%w: %q is no Node, Device or IP address", intent.ErrNotFound, q.From)
}

// destination resolves To of a query in the VRF vrf of the sender s, whose source is src (invalid for its own
// address): an IP address as it is, a Node as the address of it that the VRF of s leads to that Node, a Device as
// its address.
func (m *Model) destination(s *node, vrf uint32, src netip.Addr, to string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(to); err == nil {
		return a.Unmap(), nil
	}
	if _, d, ok := m.device(to); ok {
		a, _ := deviceAddress(d, !src.IsValid() || src.Is4())
		return a, nil
	}
	n, ok := m.nodes[to]
	if !ok {
		if _, known := m.in.Nodes[to]; known {
			return netip.Addr{}, fmt.Errorf("%w: Node %q has no desired state: the licence in force does not cover it", intent.ErrInvalid, to)
		}
		return netip.Addr{}, fmt.Errorf("%w: %q is no Node, Device or IP address", intent.ErrNotFound, to)
	}
	if n == s {
		return netip.Addr{}, fmt.Errorf("%w: %q sends the packet itself: explain a packet to another Node", intent.ErrInvalid, to)
	}
	// The addresses of the Node, each as its 1:1 NAT rules show it to the VRFs, IPv4 first: the first that the
	// forwarding table of the VRF of s leads to that Node
	for _, a := range n.reachable() {
		if src.IsValid() && src.Is4() != a.Is4() {
			continue
		}
		if r, ok := s.lookup(vrf, a); ok && r.hop != local && s.peers[s.hops[r.hop].peer].GetName() == n.name {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: VRF %s at %s leads no address of %s to it: the two share no VRF and no leak joins them", intent.ErrInvalid, m.vrfName(vrf), s.name, n.name)
}

// device finds the Device name in the state of its gateway: the gateway and the Device.
func (m *Model) device(name string) (*node, *controlpb.Device, bool) {
	for _, gw := range slices.Sorted(maps.Keys(m.nodes)) {
		for _, d := range m.nodes[gw].devices {
			if d.GetName() == name && d.GetGateway() == gw && len(d.GetPublicKey()) != 0 {
				return m.nodes[gw], d, true
			}
		}
	}
	return nil, nil, false
}

// deviceAddress returns the IPv4 address of the Device d when v4 is set, else its IPv6 address; the other when it
// has only one.
func deviceAddress(d *controlpb.Device, v4 bool) (netip.Addr, bool) {
	var other netip.Addr
	for _, a := range d.GetAddresses() {
		p, ok := hostPrefix(a.GetPrefix())
		if !ok {
			continue
		}
		if p.Addr().Is4() == v4 {
			return p.Addr(), true
		}
		other = p.Addr()
	}
	return other, other.IsValid()
}

// vrfName names the VRF of the id id, as the intent does; its number when the intent has no such VRF.
func (m *Model) vrfName(id uint32) string {
	for _, name := range slices.Sorted(maps.Keys(m.in.VRFs)) {
		if m.in.VRFs[name].ID == id {
			return name
		}
	}
	return strconv.FormatUint(uint64(id), 10)
}

// routeTargets returns the route targets that the VRF of the id from exports and the VRF of the id to imports: the
// ones that leak the routes of from into to.
func (m *Model) routeTargets(from, to uint32) []string {
	f, t := m.vrfName(from), m.vrfName(to)
	for _, l := range m.in.Leaks() {
		if l.From == f && l.To == t {
			return l.RouteTargets
		}
	}
	return nil
}

// natName names the 1:1 NAT rule r of the Node of the name owner in the VRF vrf: its NAT resource, or 4via6.
func (m *Model) natName(owner string, vrf uint32, r natRule) string {
	if r.family {
		return "4via6"
	}
	v := m.vrfName(vrf)
	for _, name := range slices.Sorted(maps.Keys(m.in.NATs)) {
		n := m.in.NATs[name]
		inside, err := netip.ParsePrefix(n.Inside)
		outside, err2 := netip.ParsePrefix(n.Outside)
		if n.Node == owner && n.VRF == v && err == nil && err2 == nil && inside.Masked() == r.inside && outside.Masked() == r.outside {
			return name
		}
	}
	return r.inside.String() + " " + r.outside.String()
}

// inVRF says " in VRF name" for a VRF that a query names, nothing for none.
func inVRF(name string) string {
	if name == "" {
		return ""
	}
	return " in VRF " + name
}
