package controller_test

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// TestRunbookSetsUpAMimicServer is the ninth criterion of CORE-P2-7 (#424): the runbook of the first test says how an operator
// sets up a mimic server, step by step: the address of the sidecar and its port in the firewall, the certificate of the front door
// of the Listener with a read rule on its key for the account of the Node service, the mimic endpoint and the mimic section in the
// Intent, what the Node and the Controller then do with the key and the links, a restart, a probe and the end of the server, and it
// names the tracer that proves it in CI. A phrase is looked for in the part with the white space of the page folded into one space,
// as TestDocsNameTheMimicSection does. The Intent documents that the part writes are applied as ranz apply applies them, after the
// ones of steps 15 and 20 and with values in place of the ones in angle brackets, so that a command of the part that the Controller
// would refuse fails here. The lines of the node log and of ranz that the part quotes are looked for in the code too, so that the
// runbook and the code do not drift apart.
func TestRunbookSetsUpAMimicServer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// A checkout on Windows may hold a file with CRLF line endings (core.autocrlf)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	fold := func(s string) string { return strings.Join(strings.Fields(s), " ") }

	page := read(filepath.Join("docs", "first-test.md"))
	start := strings.Index(page, "\n## A mimic server\n")
	end := strings.Index(page, "\n## Part 6. Clean up\n")
	if start < 0 || end < start {
		t.Fatal(`docs/first-test.md has no part "A mimic server" before Part 6`)
	}
	text := fold(page[start:end])

	// The account of the Node service, which runs the sidecar and reads the key of the certificate of the front door
	_, account, found := strings.Cut(read(filepath.Join("src", "Cedar", "Node.h")), `#define NODE_SERVICE_ACCOUNT L"`)
	account, _, closed := strings.Cut(account, `"`)
	if !found || !closed {
		t.Fatal("src/Cedar/Node.h defines no NODE_SERVICE_ACCOUNT")
	}
	account = strings.ReplaceAll(account, `\\`, `\`)
	service, virtual := strings.CutPrefix(account, `NT SERVICE\`)
	if !virtual {
		t.Fatalf("the account of the Node service is %q, not a virtual account NT SERVICE\\NAME", account)
	}

	for _, want := range []string{
		"## A mimic server",
		"This part is no step of the test",
		`New-NetFirewallRule -DisplayName "Ranz mimic server" -Direction Inbound -Protocol TCP -LocalPort 8443`,
		`New-SelfSignedCertificate -Subject "CN=edge-a" -DnsName "edge-a" -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm ECDSA_nistP256 -Provider "Microsoft Software Key Storage Provider"`,
		`/grant "` + account + `:R"`,
		"Write it down as `<LISTENER-THUMBPRINT>`",
		`{"transport":"mimic","address":"<PC-A>:8443"}`,
		`"mimic":{"listen":"<PC-A>:8443","serverNames":["www.example.com"]`,
		`ranz apply -f C:\ranz-test\mimic.json`,
		"ranz explain -listener edge-a",
		"After a restart the Node reports the same key",
		"Restart-Service " + service,
		"It prints `200`",
		`ranz apply -f C:\ranz-test\mimic-end.json`,
		"ranz delete Listener edge-a",
		`Remove-Item -Path Cert:\LocalMachine\My\<LISTENER-THUMBPRINT> -DeleteKey`,
		`Remove-NetFirewallRule -DisplayName "Ranz mimic server"`,
		"(`vpntest mimictrace`, `.github/scripts/mimic-tracer.ps1`)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf(`the part "A mimic server" of docs/first-test.md does not say %q`, want)
		}
	}
	// The thumbprint is a value that the reader copies, as the others are
	if !strings.Contains(page, "| `<LISTENER-THUMBPRINT>` |") {
		t.Error("the values that the reader copies in docs/first-test.md have no row for <LISTENER-THUMBPRINT>")
	}

	// The documents that the commands of the runbook write, with values in place of the ones in angle brackets: an address of the
	// documentation range for PC A, the TLS port of the Controller, a static key of the Node service that is none of the test keys
	// of step 15, and a thumbprint
	values := strings.NewReplacer("<PC-A>", "192.0.2.10", "<PORT>", "443", "<NODE-KEY>", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
		"<LISTENER-THUMBPRINT>", strings.Repeat("0A", 20))
	document := func(name string) intent.Document {
		t.Helper()
		command := `Set-Content -Path C:\ranz-test\` + name + ` -Value '`
		for _, line := range strings.Split(page, "\n") {
			if doc, ok := strings.CutPrefix(line, command); ok && strings.HasSuffix(doc, "'") {
				d, err := intent.ParseDocument([]byte(values.Replace(strings.TrimSuffix(doc, "'"))))
				if err != nil {
					t.Fatalf("the document %s of docs/first-test.md does not parse: %v", name, err)
				}
				return d
			}
		}
		t.Fatalf("docs/first-test.md writes no document %s", name)
		return intent.Document{}
	}
	in, err := intent.Apply(intent.New(), intent.FirstInstall(), nil)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(name string) {
		t.Helper()
		next, err := intent.Apply(in, document(name), nil)
		if err != nil {
			t.Fatalf(`ranz apply -f C:\ranz-test\%s refuses the document of docs/first-test.md: %v`, name, err)
		}
		in = next
	}

	// Steps 15 and 20 come before the part, and its step 4 makes pc-a a mimic server
	apply("nodes.json")
	apply("pc-a.json")
	apply("mimic.json")
	section, ok := in.MimicOf("pc-a")
	if !ok || section.Listen != "192.0.2.10:8443" || !slices.Equal(section.ServerNames, []string{"www.example.com"}) || !section.Decoy.SelfSigned {
		t.Fatalf("the mimic section of pc-a after mimic.json is %+v, want the sidecar at <PC-A>:8443 for www.example.com with a self-signed decoy", section)
	}
	if mimic := (intent.Endpoint{Transport: intent.TransportMimic, Address: section.Listen}); !slices.Contains(in.Nodes["pc-a"].Endpoints, mimic) {
		t.Errorf("the endpoints of pc-a after mimic.json are %v, want the mimic endpoint %v that the clients dial", in.Nodes["pc-a"].Endpoints, mimic)
	}
	if _, port, err := net.SplitHostPort(section.Listen); err != nil || !strings.Contains(text, "-LocalPort "+port+" ") {
		t.Errorf("the firewall rule of docs/first-test.md does not open the port of the sidecar at %s", section.Listen)
	}
	// The front door of the Listener takes neither TCP port of the Controller of PC A: 443, or its fallback 5555
	if port := in.Listeners["edge-a"].Port; port == intent.DefaultListenerPort || port == 5555 {
		t.Errorf("the front door of the Listener edge-a of docs/first-test.md listens on TCP port %d, which the Controller of PC A holds", port)
	}

	// Its step 9 takes the section and the mimic endpoint out, and then the Listener
	apply("mimic-end.json")
	if _, ok := in.MimicOf("pc-a"); ok || slices.ContainsFunc(in.Nodes["pc-a"].Endpoints, func(e intent.Endpoint) bool { return e.Transport == intent.TransportMimic }) {
		t.Errorf("pc-a is a mimic server still after mimic-end.json, with the endpoints %v", in.Nodes["pc-a"].Endpoints)
	}
	if _, err := intent.Delete(in, intent.KindListener, "edge-a"); err != nil {
		t.Errorf("ranz delete Listener edge-a of docs/first-test.md is refused: %v", err)
	}

	// The lines that the part quotes, each in the code that says it
	for _, q := range []struct{ line, file string }{
		{"so the node made the key of the server: it reports its public key", "src/Cedar/NodeMimicState.c"},
		{"the sidecar of the server listens", "src/Cedar/NodeMimicState.c"},
		{"Mimic transport unavailable: ", "src/Cedar/NodeMimicState.c"},
		{"ranz.exe, which holds the sidecar, is not installed at", "src/Cedar/NodeMimicState.c"},
		{"has none, so its sidecar stopped, and the", "src/Cedar/NodeMimicState.c"},
		{"setting and the key of the server are gone", "src/Cedar/NodeMimicState.c"},
		{"sidecar counters", "src/Cedar/NodeMimic.c"},
		{"the front door listens on TCP port", "src/Cedar/NodeListener.c"},
		{"has none, so the node listens on no port of its own", "src/Cedar/NodeListener.c"},
		{"no mimic section: the Node is no mimic server", "controller/cmd/ranz/explain_listener.go"},
	} {
		if !strings.Contains(text, q.line) {
			t.Errorf(`the part "A mimic server" of docs/first-test.md does not quote the line %q`, q.line)
		}
		if !strings.Contains(read(filepath.FromSlash(q.file)), q.line) {
			t.Errorf("%s does not say %q, which docs/first-test.md quotes", q.file, q.line)
		}
	}
}
