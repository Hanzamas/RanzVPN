package explain

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
)

// ranz explain says what a prober meets at the front door of the Node that a path ends at (AUD1-DT-4, #452, decoy.go): the
// decoy of the Listener of the Node, or that it has none, or that the Node has no Listener at all.

// decoyKSP is the certificate source of the Listeners of these tests.
const decoyKSP = `"certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}`

// decoyScenario is four Nodes of VRF corp that may all talk to each other, and a rule that denies SSH: hub, whose Listener names
// the decoy 127.0.0.1:8080, gw, whose Listener names the TCP port 8443 and no decoy, lab, which has no Listener, and v6, whose
// Listener names the decoy [::1]:9090.
func decoyScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{Name: "decoy", Nodes: map[string]uint8{"hub": 1, "gw": 33, "lab": 65, "v6": 97}, Intent: document(t, `{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "hub", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.1"}}},
		{"kind": "Node", "name": "gw", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.2"}}},
		{"kind": "Node", "name": "lab", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.3"}}},
		{"kind": "Node", "name": "v6", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.4"}}},
		{"kind": "Listener", "name": "edge-hub", "spec": {"node": "hub", "decoy": "127.0.0.1:8080", `+decoyKSP+`}},
		{"kind": "Listener", "name": "edge-gw", "spec": {"node": "gw", "port": 8443, `+decoyKSP+`}},
		{"kind": "Listener", "name": "edge-v6", "spec": {"node": "v6", "decoy": "[::1]:9090", `+decoyKSP+`}},
		{"kind": "Policy", "name": "corp-all", "spec": {"vrf": "corp", "action": "allow"}},
		{"kind": "Policy", "name": "no-ssh", "spec": {"vrf": "corp", "action": "deny", "priority": 50, "protocol": "tcp", "ports": [22]}}
	]}`)}
}

// The second criterion of #452: the path to a Node whose Listener has a decoy names it, and the path to a Node whose Listener has
// none, or that has no Listener, says that there is none. One step names the front door of the Node that the link leads to, and
// not the one of the sender, and it follows the link, before the Node judges the packet.
func TestDecoyStep(t *testing.T) {
	m, _ := model(t, decoyScenario(t))
	for _, c := range []struct {
		from, to string
		want     Decoy
		text     string
	}{
		{"gw", "hub", Decoy{Listener: "edge-hub", Port: 443, Target: "127.0.0.1:8080"},
			"the front door of hub (Listener edge-hub, TCP port 443) has the decoy 127.0.0.1:8080: a prober of the TLS of the new protocol whose first frame does not open under the static key of hub gets the answer of that site on hub"},
		{"hub", "gw", Decoy{Listener: "edge-gw", Port: 8443},
			"the front door of gw (Listener edge-gw, TCP port 8443) has no decoy: a prober of the TLS of the new protocol meets the certificate of gw and then a closed connection"},
		{"hub", "lab", Decoy{},
			"lab has no Listener, so it listens on no port of its own: it has no front door and no decoy"},
		{"hub", "v6", Decoy{Listener: "edge-v6", Port: 443, Target: "[::1]:9090"},
			"the front door of v6 (Listener edge-v6, TCP port 443) has the decoy [::1]:9090: a prober of the TLS of the new protocol whose first frame does not open under the static key of v6 gets the answer of that site on v6"},
	} {
		t.Run(c.from+" to "+c.to, func(t *testing.T) {
			r, err := m.Explain(Query{From: c.from, To: c.to})
			if err != nil {
				t.Fatal(err)
			}
			got := steps(r, StepDecoy)
			if len(got) != 1 {
				t.Fatalf("the decoy steps are %+v, want one, the front door of %s", got, c.to)
			}
			if d := got[0]; d.Node != c.to || d.VRF != "" || d.Decoy == nil || *d.Decoy != c.want || d.Text != c.text {
				t.Errorf("the decoy step is %+v with %+v, want the Node %s with %+v saying %q", d, d.Decoy, c.to, c.want, c.text)
			}
			i := slices.IndexFunc(r.Steps, func(s Step) bool { return s.Kind == StepDecoy })
			if i < 1 || r.Steps[i-1].Kind != StepLink || r.Steps[i-1].Node != c.from {
				t.Errorf("the decoy step is step %d of %+v, want the one that follows the link of %s", i, r.Steps, c.from)
			}
			if !r.Verdict.Delivered || r.Verdict.Node != c.to {
				t.Errorf("the verdict is %+v, want the packet delivered to %s", r.Verdict, c.to)
			}
		})
	}
}

// The decoy is a fact of the Node that the link leads to, so a Node that drops the packet for its policy names it as well. A
// packet that is dropped before it has a link, at the Node that sends it, meets no front door.
func TestDecoyStepOfADroppedPacket(t *testing.T) {
	in, states, err := decoyScenario(t).Compile()
	if err != nil {
		t.Fatal(err)
	}
	ssh := Query{From: "gw", To: "hub", Protocol: "tcp", SourcePort: 40000, Port: 22}

	// gw denies SSH itself: no link, so no front door
	r, err := New(in, states).Explain(ssh)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict.Delivered || r.Verdict.Node != "gw" || r.Verdict.Reason != DropPolicy || len(steps(r, StepLink)) != 0 || len(steps(r, StepDecoy)) != 0 {
		t.Errorf("gw denies it: the verdict is %+v with the steps %+v, want a drop at gw before any link and no decoy step", r.Verdict, r.Steps)
	}

	// gw has no rule against SSH in its state, so it sends the packet, and hub drops it: the front door of hub is named
	broken := maps.Clone(states)
	st := maps.Clone(states["gw"])
	delete(st, desired.Key{Kind: controlpb.Kind_KIND_RULE, Name: "no-ssh"})
	broken["gw"] = st
	r, err = New(in, broken).Explain(ssh)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict.Delivered || r.Verdict.Node != "hub" || r.Verdict.Reason != DropPolicy {
		t.Fatalf("hub denies it: the verdict is %+v", r.Verdict)
	}
	if got := steps(r, StepDecoy); len(got) != 1 || got[0].Node != "hub" || got[0].Decoy.Target != "127.0.0.1:8080" {
		t.Errorf("the decoy steps are %+v, want the front door of hub with its decoy", got)
	}
}

// A link of kind vxlan or geneve goes plain to the tunnel endpoint of the Node and never to its front door, so the path names
// none, even to a Node whose Listener has a decoy.
func TestNoDecoyStepOnAPlainLink(t *testing.T) {
	for _, kind := range []string{"vxlan", "geneve"} {
		t.Run(kind, func(t *testing.T) {
			s := Scenario{Name: "plain", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}, Intent: document(t, `{"resources": [
				{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "`+kind+`", "vni": 3000}},
				{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}},
				{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["dc"], "addresses": {"dc-lan": "10.30.0.1"}, "vtep": {"address": "192.0.2.1"}}},
				{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["dc"], "addresses": {"dc-lan": "10.30.0.2"}, "vtep": {"address": "192.0.2.2"}}},
				{"kind": "Listener", "name": "edge-dc-2", "spec": {"node": "dc-2", "decoy": "127.0.0.1:8080", `+decoyKSP+`}},
				{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}}
			]}`)}
			m, _ := model(t, s)
			r, err := m.Explain(Query{From: "dc-1", To: "dc-2"})
			if err != nil {
				t.Fatal(err)
			}
			if link := steps(r, StepLink); len(link) != 1 || link[0].Link.Kind != kind || !r.Verdict.Delivered || r.Verdict.Node != "dc-2" {
				t.Fatalf("the packet is not carried by one link of kind %s to dc-2: %+v", kind, r)
			}
			if got := steps(r, StepDecoy); len(got) != 0 {
				t.Errorf("the decoy steps are %+v, want none on a link that does not reach the front door", got)
			}
		})
	}
}

// The Node reads the decoy only beside its Listener (src/Core/ControlListener.c), so a state that holds a decoy and no Listener says
// that the Node has none.
func TestDecoyWithoutAListenerIsNone(t *testing.T) {
	in, states, err := decoyScenario(t).Compile()
	if err != nil {
		t.Fatal(err)
	}
	states["lab"][desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: "lab"}].GetNode().ListenerDecoy = "127.0.0.1:8080"
	r, err := New(in, states).Explain(Query{From: "hub", To: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	got := steps(r, StepDecoy)
	if len(got) != 1 || got[0].Decoy == nil || *got[0].Decoy != (Decoy{}) || !strings.HasPrefix(got[0].Text, "lab has no Listener") || strings.Contains(got[0].Text, "127.0.0.1") {
		t.Errorf("the decoy steps are %+v, want one that says that lab has no Listener and names no decoy", got)
	}
}

// The step is in the JSON of the API: the Listener, its port and the target, which are left out when there is none.
func TestDecoyStepInJSON(t *testing.T) {
	m, _ := model(t, decoyScenario(t))
	for _, c := range []struct{ from, to, want string }{
		{"gw", "hub", `"decoy":{"listener":"edge-hub","port":443,"target":"127.0.0.1:8080"}`},
		{"hub", "gw", `"decoy":{"listener":"edge-gw","port":8443}`},
		{"hub", "lab", `"decoy":{}`},
	} {
		r, err := m.Explain(Query{From: c.from, To: c.to})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("the JSON of %s to %s is %s, want it to hold %s", c.from, c.to, b, c.want)
		}
		var back Result
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if got, want := steps(back, StepDecoy), steps(r, StepDecoy); len(got) != 1 || got[0].Decoy == nil || *got[0].Decoy != *want[0].Decoy || got[0].Text != want[0].Text {
			t.Errorf("the step of %s to %s reads back as %+v, want %+v", c.from, c.to, got, want)
		}
	}
}
