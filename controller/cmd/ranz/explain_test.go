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

// ranz explain asks the controller for the walk of a packet and prints each step with its Node and kind, then the
// verdict; with -o json it prints the answer of the API as it is. The scenario is the leak of tests/explain: a route
// that red leaks into shared, the rule of red that the leaked traffic meets, and the endpoints of the link.
func TestExplainCommand(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s, err := explain.LoadScenario("../../../tests/explain/leak.json")
	if err != nil {
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
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint}, args...), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	code, out, errOut := run("-protocol", "udp", "-sport", "40000", "-port", "53", "node-s", "node-r")
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut)
	}
	for _, want := range []string{
		"udp 10.100.0.1:40000 > 10.1.0.1:53 from node-s in VRF shared\n",
		"  node-s  route   10.1.0.1/32 leads to node-r: a route that VRF red leaks into VRF shared through the route targets 64512:1",
		"  node-r  policy  rule red-from-shared-dns (priority 1000) of VRF red at node-r allows the flow",
		"  node-s  link    the Noise session of node-s to node-r carries the packet in VRF red, encrypted; node-r has no endpoints",
		"verdict: delivered to node-r in VRF red as 10.100.0.1 > 10.1.0.1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ranz explain printed\n%s\nwithout %q", out, want)
		}
	}

	code, out, _ = run("-protocol", "tcp", "-sport", "40002", "-port", "23", "-o", "json", "node-s", "10.1.0.1")
	var res explain.Result
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil {
		t.Fatalf("ranz explain -o json: exit code %d, %v:\n%s", code, err, out)
	}
	if res.Verdict.Delivered || res.Verdict.Node != "node-r" || res.Verdict.Reason != explain.DropPolicy || res.Rules()["node-r"] != "red-no-telnet" {
		t.Errorf("the telnet packet ends %+v with the rules %v", res.Verdict, res.Rules())
	}
	code, out, _ = run("node-b", "10.100.0.1")
	if code != 0 || !strings.Contains(out, "verdict: dropped by node-b (route): no route of VRF blue at node-b holds 10.100.0.1\n") {
		t.Errorf("ranz explain node-b 10.100.0.1: exit code %d:\n%s", code, out)
	}

	// What the controller refuses, and what ranz explain does not take
	for _, c := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"nowhere", "node-r"}, 1, `"nowhere" is no Node, Device or IP address (404 Not Found)`},
		{[]string{"-vrf", "red", "node-s", "node-r"}, 1, `Node "node-s" is not a member of VRF "red" (400 Bad Request)`},
		{[]string{"node-s"}, 2, "usage: ranz explain"},
		{[]string{"-port", "70000", "node-s", "node-r"}, 2, "usage: ranz explain"},
		{[]string{"-o", "xml", "node-s", "node-r"}, 2, "usage: ranz explain"},
		{[]string{"-no-such-flag", "node-s", "node-r"}, 2, "flag provided but not defined"},
		{[]string{"-h"}, 0, "usage: ranz explain"},
	} {
		code, _, errOut := run(c.args...)
		if code != c.code || !strings.Contains(errOut, c.err) {
			t.Errorf("ranz explain %v: exit code %d, %q; want %d with %q", c.args, code, errOut, c.code, c.err)
		}
	}
	var out2, errOut2 bytes.Buffer
	if code := runExplain(ctx, []string{"-server", srv.URL, "-token-file", filepath.Join(t.TempDir(), "missing"), "node-s", "node-r"}, &out2, &errOut2); code != 1 || !strings.Contains(errOut2.String(), "the token file") {
		t.Errorf("a token file that does not exist: exit code %d, %q", code, errOut2.String())
	}
	if code := runExplain(ctx, []string{"-server", "https://127.0.0.1:1", "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "node-s", "node-r"}, &out2, &errOut2); code != 1 {
		t.Errorf("a controller that does not answer: exit code %d", code)
	}
}

// ranz explain prints the link of each step: a link of kind vxlan says that it is unencrypted (SDN-76, #356), and the
// link shows where each of its two Nodes is dialled, at the endpoints of its Node resource (SDN-93, #410). dc-1 and
// dc-2 share VRF dc, whose link is of kind vxlan, and VRF corp, which the Noise session carries.
func TestExplainCommandLinks(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s := explain.Scenario{Name: "links", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "vxlan", "vni": 3000}},
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["corp", "dc"], "addresses": {"dc-lan": "10.30.0.1", "corp-lan": "10.10.0.1"}, "vtep": {"address": "192.0.2.1"}}},
		{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["corp", "dc"], "addresses": {"dc-lan": "10.30.0.2", "corp-lan": "10.10.0.2"}, "vtep": {"address": "192.0.2.2"},
			"endpoints": [{"transport": "quic", "address": "dc-2.example.com:443"}, {"transport": "tls", "address": "203.0.113.2:443"}]}},
		{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}},
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
	const dialled = "; dc-2 is dialled at quic dc-2.example.com:443, tls 203.0.113.2:443; dc-1 has no endpoints, so no peer dials it\n"
	for _, c := range []struct{ vrf, link string }{
		{"dc", "  dc-1  link    the link of kind vxlan of VRF dc carries the packet on VNI 3000 to the tunnel endpoint of dc-2: unencrypted, plain on a network that the operator trusts" + dialled},
		{"corp", "  dc-1  link    the Noise session of dc-1 to dc-2 carries the packet in VRF corp, encrypted" + dialled},
	} {
		var out, errOut bytes.Buffer
		code := runExplain(ctx, []string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "-vrf", c.vrf, "-protocol", "udp", "-sport", "40000", "-port", "53", "dc-1", "dc-2"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("ranz explain -vrf %s dc-1 dc-2: exit code %d: %s", c.vrf, code, errOut.String())
		}
		if !strings.Contains(out.String(), c.link) || !strings.Contains(out.String(), "verdict: delivered to dc-2 in VRF "+c.vrf+" as ") {
			t.Errorf("ranz explain -vrf %s dc-1 dc-2 printed\n%s\nwithout the link %q, or not delivered to dc-2", c.vrf, out.String(), c.link)
		}
	}
}
