package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// ranz explain says what a prober meets at the front door of the Node that a path ends at (AUD1-DT-4, #452): the decoy of its
// Listener, none, or that the Node has no Listener. This is the second criterion of the ticket: with no decoy set, ranz explain
// says that there is none. hub has a Listener with the decoy 127.0.0.1:8080, gw has a Listener with none, and lab has no Listener.
func TestExplainCommandDecoy(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s := explain.Scenario{Name: "decoy", Nodes: map[string]uint8{"hub": 1, "gw": 33, "lab": 65}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "hub", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.1"}}},
		{"kind": "Node", "name": "gw", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.2"}}},
		{"kind": "Node", "name": "lab", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.3"}}},
		{"kind": "Listener", "name": "edge-hub", "spec": {"node": "hub", "decoy": "127.0.0.1:8080", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}},
		{"kind": "Listener", "name": "edge-gw", "spec": {"node": "gw", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}},
		{"kind": "Policy", "name": "corp-all", "spec": {"vrf": "corp", "action": "allow"}}
	]}`), &s.Intent); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}).Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte(admin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test server is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	fingerprint := fingerprintOf(srv.Certificate())
	run := func(args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint}, args...), &out, &errOut); code != 0 {
			t.Fatalf("ranz explain %v: exit code %d: %s", args, code, errOut.String())
		}
		return out.String()
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		// The decoy of the Listener of hub, a loopback target
		{[]string{"gw", "hub"}, "  hub  decoy   the front door of hub (Listener edge-hub, TCP port 443) has the decoy 127.0.0.1:8080: " +
			"a prober of the TLS of the new protocol, one whose first frame does not open under the static key of hub, gets the answer of that site on hub\n"},
		// A Listener that names none: ranz explain says that there is none
		{[]string{"hub", "gw"}, "  gw   decoy   the front door of gw (Listener edge-gw, TCP port 443) has no decoy: " +
			"a prober of the TLS of the new protocol meets the certificate of gw and then a closed connection\n"},
		// A Node that has no Listener
		{[]string{"hub", "lab"}, "  lab  decoy   lab has no Listener, so it listens on no port of its own: it has no front door and no decoy\n"},
	} {
		out := run(c.args...)
		if !strings.Contains(out, c.want) || strings.Count(out, "  decoy  ") != 1 {
			t.Errorf("ranz explain %v printed\n%s\nwithout the one line %q", c.args, out, c.want)
		}
		if !strings.Contains(out, "verdict: delivered to "+c.args[1]+" in VRF corp as ") {
			t.Errorf("ranz explain %v printed\n%s\nwhich does not deliver the packet to %s", c.args, out, c.args[1])
		}
	}

	// The answer of the API names the Listener, its port and the target of the decoy
	var res explain.Result
	if err := json.Unmarshal([]byte(run("-o", "json", "gw", "hub")), &res); err != nil {
		t.Fatal(err)
	}
	var got []explain.Decoy
	for _, step := range res.Steps {
		if step.Kind == explain.StepDecoy && step.Decoy != nil {
			got = append(got, *step.Decoy)
		}
	}
	if want := (explain.Decoy{Listener: "edge-hub", Port: 443, Target: "127.0.0.1:8080"}); len(got) != 1 || got[0] != want {
		t.Errorf("ranz explain -o json gw hub names the decoys %+v, want %+v", got, want)
	}
}
