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
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain -listener asks the controller to explain a Listener (SDN-94, #423): the mimic section, whether the Node reported
// the public key of its mimic server, and the Nodes that have a link to it. No Node is connected to this controller, so the key
// is not reported: the answer says that the Controller waits for it, and that the Node that dials the server has no link yet.
func TestExplainListenerCommand(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	doc, err := intent.ParseDocument([]byte(`{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
		{"kind": "Node", "name": "hub", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"],
			"endpoints": [{"transport": "mimic", "address": "hub.example.com:8443"}]}},
		{"kind": "Node", "name": "gw-1", "spec": {"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"]}},
		{"kind": "Listener", "name": "edge-hub", "spec": {"node": "hub", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"},
			"mimic": {"listen": ":8443", "serverNames": ["www.example.com"], "decoy": {"mode": "borrow", "dest": "www.example.com:443"}}}},
		{"kind": "Listener", "name": "edge-gw-1", "spec": {"node": "gw-1", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}}
	]}`))
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
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile}, args...), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	code, out, errOut := run("-listener", "edge-hub")
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Listener edge-hub of Node hub\n",
		"  mimic server: the sidecar listens on :8443, an address of its own, not the one of the front door\n",
		"  server names: www.example.com (the first is the name in the ClientHello of the links)\n",
		"  decoy: borrows the site at www.example.com:443, whose own certificate a prober sees\n",
		"  clock tolerance: 120000 ms\n",
		"  endpoints: hub.example.com:8443 (the clients dial these)\n",
		"  public key: not reported by Node hub\n",
		"  waiting: the Controller waits for the public key of Node hub: ",
		"  links: 0\n",
		"  no link yet: gw-1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ranz explain -listener printed\n%s\nwithout %q", out, want)
		}
	}

	code, out, _ = run("-o", "json", "-listener", "edge-hub")
	var res explain.ListenerResult
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil {
		t.Fatalf("ranz explain -o json -listener: exit code %d, %v:\n%s", code, err, out)
	}
	if res.Node != "hub" || res.KeyReported || res.Mimic == nil || res.Mimic.Listen != ":8443" || len(res.Unlinked) != 1 || res.Unlinked[0] != "gw-1" {
		t.Errorf("the answer in JSON is %+v, want the Listener of hub with its section, no key and gw-1 without a link", res)
	}

	code, out, _ = run("-listener", "edge-gw-1")
	if want := "Listener edge-gw-1 of Node gw-1\n  no mimic section: the Node is no mimic server\n"; code != 0 || out != want {
		t.Errorf("ranz explain -listener edge-gw-1: exit code %d:\n%s\nwant\n%s", code, out, want)
	}

	// What the controller refuses, and what ranz explain does not take with -listener
	for _, c := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"-listener", "nowhere"}, 1, `Listener "nowhere" (404 Not Found)`},
		{[]string{"-listener", "edge-hub", "hub"}, 2, "usage: ranz explain"},
		{[]string{"-listener", "edge-hub", "-vrf", "corp"}, 2, "usage: ranz explain"},
		{[]string{"-listener", "edge-hub", "-protocol", "tcp"}, 2, "usage: ranz explain"},
		{[]string{"-listener", "edge-hub", "-port", "80"}, 2, "usage: ranz explain"},
		{[]string{"-listener", "edge-hub", "-o", "xml"}, 2, "usage: ranz explain"},
	} {
		code, _, errOut := run(c.args...)
		if code != c.code || !strings.Contains(errOut, c.err) {
			t.Errorf("ranz explain %v: exit code %d, %q; want %d with %q", c.args, code, errOut, c.code, c.err)
		}
	}
	var out2, errOut2 bytes.Buffer
	if code := runExplain(ctx, []string{"-server", "https://127.0.0.1:1", "-token-file", tokenFile, "-listener", "edge-hub"}, &out2, &errOut2); code != 1 {
		t.Errorf("a controller that does not answer: exit code %d", code)
	}
}

// printListener says what the Controller knows of a mimic server: a Listener without a section has none; a server whose Node
// reported its key shows it, and each link; a server that names no mimic endpoint says that no Node dials it.
func TestPrintListener(t *testing.T) {
	render := func(r explain.ListenerResult) string {
		t.Helper()
		var out bytes.Buffer
		if err := printListener(&out, r); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	acme := &intent.MimicACME{Directory: "https://ca.example/dir", CacheDir: `C:\acme`}
	r := explain.ListenerResult{Listener: "edge-hub", Node: "hub", KeyReported: true, PublicKey: "00ff",
		Mimic:          &intent.ListenerMimic{Listen: "192.0.2.10:8443", ServerNames: []string{"a.example", "b.example"}, MaxTimeDiffMs: 5000, Decoy: intent.MimicDecoy{Mode: intent.MimicDecoyOwn, ACME: acme}},
		MimicEndpoints: []string{"hub.example.com:8443", "[2001:db8::10]:8443"},
		Links: []explain.ListenerLink{{Node: "gw-1", Address: "hub.example.com:8443", ServerName: "a.example"}, {Node: "gw-1", Address: "[2001:db8::10]:8443", ServerName: "a.example"},
			{Node: "gw-2", Address: "hub.example.com:8443", ServerName: "a.example"}}}
	want := `Listener edge-hub of Node hub
  mimic server: the sidecar listens on 192.0.2.10:8443, an address of its own, not the one of the front door
  server names: a.example, b.example (the first is the name in the ClientHello of the links)
  decoy: own site, certificate from the ACME service https://ca.example/dir, cache C:\acme
  clock tolerance: 5000 ms
  endpoints: hub.example.com:8443, [2001:db8::10]:8443 (the clients dial these)
  public key: reported by Node hub, 00ff (each client pins it)
  links: 3
    gw-1 dials hub.example.com:8443 as a.example
    gw-1 dials [2001:db8::10]:8443 as a.example
    gw-2 dials hub.example.com:8443 as a.example
`
	if got := render(r); got != want {
		t.Errorf("a server with its key reported is printed as\n%s\nwant\n%s", got, want)
	}

	// No endpoint of the mimic transport, and a certificate in files
	r = explain.ListenerResult{Listener: "edge-hub", Node: "hub", Waiting: "wait", Links: []explain.ListenerLink{}, Unlinked: []string{"gw-1", "gw-2"},
		Mimic: &intent.ListenerMimic{Listen: ":8443", ServerNames: []string{"a.example"}, MaxTimeDiffMs: 1, Decoy: intent.MimicDecoy{Mode: intent.MimicDecoyOwn, CertFile: `C:\c.pem`, KeyFile: `C:\k.pem`}}}
	got := render(r)
	for _, want := range []string{
		"  decoy: own site, certificate in C:\\c.pem, key in C:\\k.pem\n",
		"  endpoints: Node hub names no endpoint of the mimic transport, so no Node dials the server over mimic\n",
		"  public key: not reported by Node hub\n  waiting: wait\n  links: 0\n  no link yet: gw-1, gw-2\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("a server without an endpoint is printed as\n%s\nwithout %q", got, want)
		}
	}

	// The decoys of the other kinds, and a Listener that has no section
	if got, want := decoyText(intent.MimicDecoy{Mode: intent.MimicDecoyOwn, SelfSigned: true}), "own site, self-signed certificate (for tests only)"; got != want {
		t.Errorf("the self-signed decoy is %q, want %q", got, want)
	}
	if got, want := render(explain.ListenerResult{Listener: "edge-gw-1", Node: "gw-1", Links: []explain.ListenerLink{}}), "Listener edge-gw-1 of Node gw-1\n  no mimic section: the Node is no mimic server\n"; got != want {
		t.Errorf("a Listener without a section is printed as %q, want %q", got, want)
	}
}
