package controller_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The second criterion of #452 at the API of the controller (AUD1-DT-4): GET /api/v1/explain, which ranz explain calls, names the
// decoy of the front door of the Node that the path ends at, as the Listener of the intent in force gives it to the Node, and
// follows a change of it. hub has a Listener with the decoy 127.0.0.1:8080, gw has a Listener on TCP port 8443 with none, and lab
// has no Listener.
func TestExplainDecoy(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	s := explain.Scenario{Name: "decoy", Nodes: map[string]uint8{"hub": 1, "gw": 33, "lab": 65}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "hub", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.1"}}},
		{"kind": "Node", "name": "gw", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.2"}}},
		{"kind": "Node", "name": "lab", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.3"}}},
		{"kind": "Listener", "name": "edge-hub", "spec": {"node": "hub", "decoy": "127.0.0.1:8080", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}},
		{"kind": "Listener", "name": "edge-gw", "spec": {"node": "gw", "port": 8443, "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}},
		{"kind": "Policy", "name": "corp-all", "spec": {"vrf": "corp", "action": "allow"}}
	]}`), &s.Intent); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}

	// decoy explains the path from one Node to another, which the packet reaches, and returns its one step of the front door
	decoy := func(from, to string) explain.Step {
		t.Helper()
		r, err := h.api.Explain(ctx, explain.Query{From: from, To: to})
		if err != nil {
			t.Fatal(err)
		}
		var got []explain.Step
		for _, st := range r.Steps {
			if st.Kind == explain.StepDecoy {
				got = append(got, st)
			}
		}
		if len(got) != 1 || got[0].Node != to || got[0].Decoy == nil || !r.Verdict.Delivered || r.Verdict.Node != to {
			t.Fatalf("%s to %s: the decoy steps are %+v and the verdict %+v, want the one front door of %s", from, to, got, r.Verdict, to)
		}
		return got[0]
	}

	for _, c := range []struct {
		from, to string
		want     explain.Decoy
		text     string
	}{
		{"gw", "hub", explain.Decoy{Listener: "edge-hub", Port: 443, Target: "127.0.0.1:8080"}, "has the decoy 127.0.0.1:8080: a prober of the TLS of the new protocol"},
		{"hub", "gw", explain.Decoy{Listener: "edge-gw", Port: 8443}, "(Listener edge-gw, TCP port 8443) has no decoy"},
		{"hub", "lab", explain.Decoy{}, "lab has no Listener, so it listens on no port of its own: it has no front door and no decoy"},
	} {
		if st := decoy(c.from, c.to); *st.Decoy != c.want || !strings.Contains(st.Text, c.text) {
			t.Errorf("%s to %s: the decoy step is %+v with %+v, want %+v saying %q", c.from, c.to, st, st.Decoy, c.want, c.text)
		}
	}

	// The decoy of hub moves to an IPv6 loopback target, and is then taken away: explain follows the intent in force
	const cert = `"certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}`
	for _, c := range []struct {
		spec string
		want explain.Decoy
		text string
	}{
		{`{"node": "hub", "decoy": "[::1]:9090", ` + cert + `}`, explain.Decoy{Listener: "edge-hub", Port: 443, Target: "[::1]:9090"}, "has the decoy [::1]:9090"},
		{`{"node": "hub", ` + cert + `}`, explain.Decoy{Listener: "edge-hub", Port: 443}, "(Listener edge-hub, TCP port 443) has no decoy"},
	} {
		change := intent.Document{Resources: []intent.Resource{{Kind: intent.KindListener, Name: "edge-hub", Spec: json.RawMessage(c.spec)}}}
		if _, err := h.api.Apply(ctx, change); err != nil {
			t.Fatal(err)
		}
		if st := decoy("gw", "hub"); *st.Decoy != c.want || !strings.Contains(st.Text, c.text) {
			t.Errorf("after the change %s: the decoy step is %+v with %+v, want %+v saying %q", c.spec, st, st.Decoy, c.want, c.text)
		}
	}
}
