package desired

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// peerLeakText writes the Peer peer of the state s as the ids of the VRFs that the two share, then each of its routes as "vrf
// prefix", with " > vrf of the peer" for a route that a VRF of the peer leaks; "none" for no Peer.
func peerLeakText(s State, peer string) string {
	o, ok := s[Key{controlpb.Kind_KIND_PEER, peer}]
	if !ok {
		return "none"
	}
	p := o.GetPeer()
	text := fmt.Sprint(p.GetVrfIds())
	for _, r := range p.GetRoutes() {
		text += fmt.Sprintf("; %d %s", r.GetVrfId(), prefixText(r.GetPrefix()))
		if r.GetPeerVrfId() != 0 {
			text += fmt.Sprintf(" > %d", r.GetPeerVrfId())
		}
	}
	return text
}

// ruleText writes the Rule name of the state s as its VRF, action, protocol, ports and its two ends; "none" for no Rule.
func ruleText(s State, name string) string {
	o, ok := s[Key{controlpb.Kind_KIND_RULE, name}]
	if !ok {
		return "none"
	}
	r := o.GetRule()
	end := func(e *controlpb.RuleEnd) string {
		parts := append([]string(nil), e.GetTags()...)
		for _, p := range e.GetPrefixes() {
			parts = append(parts, prefixText(p))
		}
		if len(parts) == 0 {
			return "any"
		}
		return strings.Join(parts, ",")
	}
	var ports []string
	for _, p := range r.GetPorts() {
		ports = append(ports, fmt.Sprintf("%d-%d", p.GetFirst(), p.GetLast()))
	}
	return fmt.Sprintf("%d %s %d %s from %s to %s", r.GetVrfId(), r.GetAction(), r.GetProtocol(), strings.Join(ports, ","), end(r.GetFrom()), end(r.GetTo()))
}

// natText writes the 1:1 NAT rules of the Node name in its state s as "vrf inside > outside", one after the other.
func natText(s State, name string) string {
	var rules []string
	for _, r := range s[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetNat() {
		rules = append(rules, fmt.Sprintf("%d %s > %s", r.GetVrfId(), prefixText(r.GetInside()), prefixText(r.GetOutside())))
	}
	return strings.Join(rules, "; ")
}

// publishResources are the resources of the Endpoint tests: corp, which serves billing on its Node app, and vendor, which
// uses the same range and whose Node buyer, a consumer, presents its address through a 1:1 NAT rule; its Node guest has no tag
// and is no consumer. The ids of the VRFs are 101 and 202.
func publishResources() []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 101, "ula": "fd00:101::/48"}`),
		res(intent.KindVRF, "vendor", `{"id": 202, "ula": "fd00:202::/48", "dns": true}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(intent.KindNetwork, "vendor-lan", `{"vrf": "vendor", "ipv4Pool": "10.0.0.0/24"}`),
		res(intent.KindNode, "app", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "addresses": {"corp-lan": "10.0.0.1"}}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "addresses": {"corp-lan": "10.0.0.5"}}`),
		res(intent.KindNode, "buyer", `{"publicKey": "`+key3+`", "vrfs": ["vendor"], "tags": ["buyer"], "addresses": {"vendor-lan": "10.0.0.1"}}`),
		res(intent.KindNode, "guest", `{"publicKey": "`+key4+`", "vrfs": ["vendor"], "addresses": {"vendor-lan": "10.0.0.2"}}`),
		res(intent.KindNAT, "buyer-out", `{"vrf": "vendor", "node": "buyer", "inside": "10.0.0.1/32", "outside": "172.16.2.1/32"}`),
		res(intent.KindEndpoint, "billing", `{"vrf": "corp", "node": "app", "address": "10.0.0.1", "port": 443, "consumer": "vendor", "as": "172.16.1.1", "consumerTags": ["buyer"]}`),
	}
}

// An Endpoint gives the Node that serves it a 1:1 NAT rule and the rule of its VRF; each consumer the route to the published
// address, a Peer of the Node that serves it, and the rule of its VRF; the Node that serves it the route back to each consumer,
// a Peer of the consumer; and the zone of the consumer VRF the name. No other Node of either VRF is a Peer of the other VRF,
// and nothing else of the source VRF leaks, whichever Node of it has an address that the consumer VRF uses too.
func TestCompileEndpoint(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: publishResources()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := natText(states["app"], "app"), "101 10.0.0.1/32 > 172.16.1.1/32"; got != want {
		t.Errorf("app applies %q, want %q", got, want)
	}
	if got, want := natText(states["buyer"], "buyer"), "202 10.0.0.1/32 > 172.16.2.1/32"; got != want {
		t.Errorf("buyer applies %q, want %q", got, want)
	}
	for _, c := range []struct {
		node, peer string
		want       string // the VRFs shared, then each route; "none" for no Peer
	}{
		{"app", "buyer", "[]; 101 172.16.2.1/32 > 202"},
		{"app", "db", "[101]"},
		{"app", "guest", "none"},
		{"buyer", "app", "[]; 202 172.16.1.1/32 > 101"},
		{"buyer", "guest", "[202]"},
		{"buyer", "db", "none"},
		{"guest", "buyer", "[202]; 202 172.16.2.1/32"},
		{"guest", "app", "none"},
		{"db", "app", "[101]; 101 172.16.1.1/32"},
		{"db", "buyer", "none"},
	} {
		if got := peerLeakText(states[c.node], c.peer); got != c.want {
			t.Errorf("the Peer %s of %s is %q, want %q", c.peer, c.node, got, c.want)
		}
	}
	for _, c := range []struct{ node, rule, want string }{
		{"app", "billing.source", "101 RULE_ACTION_ALLOW 6 443-443 from any to 172.16.1.1/32"},
		{"db", "billing.source", "101 RULE_ACTION_ALLOW 6 443-443 from any to 172.16.1.1/32"},
		{"app", "billing.consumer", "none"},
		{"buyer", "billing.consumer", "202 RULE_ACTION_ALLOW 6 443-443 from buyer to 172.16.1.1/32"},
		{"guest", "billing.consumer", "202 RULE_ACTION_ALLOW 6 443-443 from buyer to 172.16.1.1/32"},
		{"buyer", "billing.source", "none"},
	} {
		if got := ruleText(states[c.node], c.rule); got != c.want {
			t.Errorf("the rule %s of %s is %q, want %q", c.rule, c.node, got, c.want)
		}
	}
	for _, c := range []struct{ node, vrf, want string }{
		{"buyer", "vendor", "vendor.ranz.internal\nbilling 172.16.1.1"},
		{"guest", "vendor", "vendor.ranz.internal\nbilling 172.16.1.1"},
		{"app", "vendor", "none"},
		{"app", "corp", "off"},
	} {
		if got := zoneText(states[c.node], c.vrf); got != c.want {
			t.Errorf("%s: the zone of %s is\n%s\nwant\n%s", c.node, c.vrf, got, c.want)
		}
	}

	// Without the Endpoint nothing of it is left: the other resources compile as they did
	gone, err := intent.Delete(in, intent.KindEndpoint, "billing")
	if err != nil {
		t.Fatal(err)
	}
	states, err = Compile(gone)
	if err != nil {
		t.Fatal(err)
	}
	if got := natText(states["app"], "app"); got != "" {
		t.Errorf("app applies %q without the Endpoint", got)
	}
	for _, c := range []struct{ node, peer string }{{"app", "buyer"}, {"buyer", "app"}} {
		if got := peerLeakText(states[c.node], c.peer); got != "none" {
			t.Errorf("the Peer %s of %s is %q without the Endpoint", c.peer, c.node, got)
		}
	}
	if got := ruleText(states["app"], "billing.source"); got != "none" {
		t.Errorf("app holds the rule %q without the Endpoint", got)
	}
	if got := zoneText(states["buyer"], "vendor"); got != "vendor.ranz.internal" {
		t.Errorf("the zone of vendor is %q without the Endpoint", got)
	}
}
