package desired

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// holdResources returns VRF dc (30) in the tag mode trusted-underlay with gw, the gateway of Device phone, db (tag db) and
// lab (tag web), with the tags of gw and of phone that the JSON arrays gw and phone give.
func holdResources(gw, phone string) []intent.Resource {
	const phoneKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`),
		res(intent.KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24", "tagMode": "trusted-underlay"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "tags": `+gw+`, "vtep": {"address": "10.1.0.1"}, "wireguard": {"endpoint": "gw.example.net"}}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "tags": ["db"], "vtep": {"address": "10.1.0.2"}}`),
		res(intent.KindNode, "lab", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "tags": ["web"], "vtep": {"address": "10.1.0.3"}}`),
		res(intent.KindDevice, "phone", `{"network": "dc-net", "gateway": "gw", "publicKey": "`+phoneKey+`", "tags": `+phone+`}`),
	}
}

// holdStates returns the states that holdResources(gw, phone) compiles to, each Node reporting the Capability tags, with
// the numbers of numbers and the ones that the intent adds to them, which it returns too.
func holdStates(t *testing.T, gw, phone string, numbers GroupNumbers) (map[string]State, GroupNumbers) {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: holdResources(gw, phone)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	numbers = numbers.With(NumberGroups(in, numbers))
	SourceGroups(in, states, numbers, func(string) bool { return true })
	return states, numbers
}

// heldText returns the source groups of the NodeConfig of the Node name in its state st as text, "vrf group/tagset" each,
// by commas, with " held" after each group that is held.
func heldText(st State, name string) string {
	var parts []string
	for _, g := range st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		part := groupsText([]*controlpb.SourceGroup{g})
		if g.GetHeld() {
			part += " held"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// SDN-87: in VRF dc the groups are [db] 1 (db), [ops] 2 (Device phone) and [web] 3 (gw and lab), and db, lab and gw judge
// each other's claims. A Node whose tags, or those of a Device whose gateway it is, move into a set of tags that has its
// group ID already holds its own group in the VRF while a peer runs a state, acknowledged or in flight, that gives that
// group ID to another endpoint and does not let the Node assert it, as the peer would drop its claim as an unknown group;
// HoldGroups returns the peers that the hold waits for. A move into a new set of tags, whose group ID no state of a peer
// knows, holds nothing, and neither does a peer that runs the new state already, nor one that does not judge the claims of
// the Node. A Node whose groups did not change and held none needs no new look; one that held keeps holding until no peer
// runs such a state.
func TestHoldGroups(t *testing.T) {
	before, numbers := holdStates(t, `["web"]`, `["ops"]`, nil)
	of := func(states map[string]State) func(string) State {
		return func(node string) State { return states[node] }
	}
	runs := func(states ...map[string]State) func(string) []State {
		return func(node string) []State {
			var out []State
			for _, st := range states {
				out = append(out, st[node])
			}
			return out
		}
	}
	waits := func(holds map[string][]string) string {
		var parts []string
		for _, node := range slices.Sorted(maps.Keys(holds)) {
			parts = append(parts, node+" waits for "+strings.Join(holds[node], " "))
		}
		return strings.Join(parts, "; ")
	}

	for _, c := range []struct {
		what      string
		gw, phone string
		runs      func(after map[string]State) func(string) []State
		held      string // the groups of gw once HoldGroups ran
		waits     string
	}{
		{"the tags of gw move into [db], which db and lab give db alone, while both run the state before",
			`["db"]`, `["ops"]`, func(map[string]State) func(string) []State { return runs(before) },
			"30 1/0x1 held", "gw waits for db lab"},
		{"the tags of phone, whose gateway gw is, move into [db]",
			`["web"]`, `["db"]`, func(map[string]State) func(string) []State { return runs(before) },
			"30 3/0x4 held", "gw waits for db lab"},
		{"db runs the new state, lab the one before",
			`["db"]`, `["ops"]`, func(after map[string]State) func(string) []State {
				return func(node string) []State {
					if node == "db" {
						return []State{after[node]}
					}
					return []State{before[node]}
				}
			},
			"30 1/0x1 held", "gw waits for lab"},
		{"db and lab acknowledged the state before and have the new one in flight",
			`["db"]`, `["ops"]`, func(after map[string]State) func(string) []State { return runs(before, after) },
			"30 1/0x1 held", "gw waits for db lab"},
		{"both run the new state",
			`["db"]`, `["ops"]`, func(after map[string]State) func(string) []State { return runs(after) },
			"30 1/0x1", ""},
		{"neither ran a state yet",
			`["db"]`, `["ops"]`, func(map[string]State) func(string) []State { return runs(nil) },
			"30 1/0x1", ""},
		{"the tags of gw move into [admin], a new set whose group ID 4 no state before knows",
			`["admin"]`, `["ops"]`, func(map[string]State) func(string) []State { return runs(before) },
			"30 4/0x8", ""},
		{"nothing changes",
			`["web"]`, `["ops"]`, func(map[string]State) func(string) []State { return runs(before) },
			"30 3/0x4", ""},
	} {
		after, _ := holdStates(t, c.gw, c.phone, numbers)
		shared := after["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}]
		holds := HoldGroups(after, of(before), c.runs(after))
		if got := heldText(after["gw"], "gw"); got != c.held {
			t.Errorf("%s: the groups of gw are %q, want %q", c.what, got, c.held)
		}
		if got := waits(holds); got != c.waits {
			t.Errorf("%s: the holds are %q, want %q", c.what, got, c.waits)
		}
		for _, name := range []string{"db", "lab"} {
			if got := heldText(after[name], name); strings.Contains(got, "held") {
				t.Errorf("%s: %s, whose groups did not change, holds %q", c.what, name, got)
			}
		}
		// The NodeConfig that SourceGroups made, which the states may share, is not changed
		if slices.ContainsFunc(shared.GetNode().GetGroups(), func(g *controlpb.SourceGroup) bool { return g.GetHeld() }) {
			t.Errorf("%s: HoldGroups changed the NodeConfig that it replaced", c.what)
		}
	}

	// A hold stays while a peer runs the state before, whatever else changes, and goes once none does, with the Refuses of
	// the acknowledgement of each peer
	held, _ := holdStates(t, `["db"]`, `["ops"]`, numbers)
	HoldGroups(held, of(before), runs(before))
	for _, c := range []struct {
		what  string
		runs  func(after map[string]State) func(string) []State
		held  string
		waits string
	}{
		{"while db and lab run the state before", func(map[string]State) func(string) []State { return runs(before) }, "30 1/0x1 held", "gw waits for db lab"},
		{"once both run the new state", func(after map[string]State) func(string) []State { return runs(after) }, "30 1/0x1", ""},
	} {
		after, _ := holdStates(t, `["db"]`, `["ops"]`, numbers)
		holds := HoldGroups(after, of(held), c.runs(after))
		if got := heldText(after["gw"], "gw"); got != c.held {
			t.Errorf("the state before held the group of gw, %s: the groups of gw are %q, want %q", c.what, got, c.held)
		}
		if got := waits(holds); got != c.waits {
			t.Errorf("the state before held the group of gw, %s: the holds are %q, want %q", c.what, got, c.waits)
		}
	}
	plain, _ := holdStates(t, `["db"]`, `["ops"]`, numbers)
	for _, c := range []struct {
		what string
		runs []State
		st   State
		want bool
	}{
		{"db on the state before, gw holding", []State{before["db"]}, held["gw"], true},
		{"db on the new state, gw holding", []State{plain["db"]}, held["gw"], false},
		{"db on the state before with the new one in flight, gw holding", []State{before["db"], plain["db"]}, held["gw"], true},
		{"db on the state before, gw holding nothing", []State{before["db"]}, plain["gw"], false},
		{"no state of db, gw holding", []State{nil}, held["gw"], false},
	} {
		if got := Refuses(c.runs, "gw", c.st); got != c.want {
			t.Errorf("Refuses with %s is %v, want %v", c.what, got, c.want)
		}
	}
}
