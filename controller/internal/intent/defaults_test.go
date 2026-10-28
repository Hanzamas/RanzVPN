package intent

import (
	"encoding/json"
	"testing"
)

// The starter rule is the rule of the first install until an operator narrows it in place: a rule of
// its name with an end, a protocol or ports, or another action or VRF, no longer allows all traffic
// inside VRF default, and `ranz status` must not say that it does (AUD1-DT-6, #454).
func TestIsStarterRule(t *testing.T) {
	var made Resource
	for _, r := range FirstInstall().Resources {
		if r.Kind == KindPolicy {
			made = r
		}
	}
	rule := func(spec string) Resource {
		return Resource{Kind: KindPolicy, Name: StarterRule, Spec: json.RawMessage(spec)}
	}
	for _, c := range []struct {
		what string
		r    Resource
		want bool
	}{
		{"as the first install made it", made, true},
		{"with a priority, which narrows nothing", rule(`{"vrf":"default","action":"allow","priority":10}`), true},
		{"narrowed to a protocol", rule(`{"vrf":"default","action":"allow","protocol":"tcp"}`), false},
		{"narrowed to ports", rule(`{"vrf":"default","action":"allow","ports":["443"]}`), false},
		{"narrowed to the Nodes of a tag", rule(`{"vrf":"default","action":"allow","from":{"tags":["web"]}}`), false},
		{"narrowed to an address at its other end", rule(`{"vrf":"default","action":"allow","to":{"addresses":["100.64.0.0/16"]}}`), false},
		{"turned into a deny rule", rule(`{"vrf":"default","action":"deny"}`), false},
		{"moved to another VRF", rule(`{"vrf":"lab","action":"allow"}`), false},
		{"not a spec", rule(`[1]`), false},
		{"a Policy of another name", Resource{Kind: KindPolicy, Name: "allow-web", Spec: made.Spec}, false},
		{"a resource of another kind", Resource{Kind: KindVRF, Name: StarterRule, Spec: made.Spec}, false},
	} {
		if got := IsStarterRule(c.r); got != c.want {
			t.Errorf("IsStarterRule of the rule %s (%s) is %v, want %v", c.what, c.r.Spec, got, c.want)
		}
	}
}
