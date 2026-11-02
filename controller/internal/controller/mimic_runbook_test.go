package controller_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunbookSetsUpAMimicServer is the ninth criterion of CORE-P2-7 (#424): the runbook of the first test says how an operator
// sets up a mimic server, step by step: the address of the sidecar and its port in the firewall, the mimic endpoint and the mimic
// section in the Intent, what the Node and the Controller then do with the key and the links, a probe, and the end of the server,
// and it names the tracer that proves it in CI. A phrase is looked for with the white space of the page folded into one space, as
// TestDocsNameTheMimicSection does. The lines of the node log that the runbook quotes are looked for in the code of the Node too,
// so that the runbook and the log do not drift apart.
func TestRunbookSetsUpAMimicServer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	runbook := read(filepath.Join("docs", "first-test.md"))
	for _, want := range []string{
		"## A mimic server",
		"This part is no step of the test",
		`New-NetFirewallRule -DisplayName "Ranz mimic server" -Direction Inbound -Protocol TCP -LocalPort 8443`,
		`{"transport":"mimic","address":"<PC-A>:8443"}`,
		`"mimic":{"listen":"<PC-A>:8443","serverNames":["www.example.com"]`,
		`ranz apply -f C:\ranz-test\mimic.json`,
		"ranz explain -listener edge-a",
		"After a restart the Node reports the same key",
		`Remove-NetFirewallRule -DisplayName "Ranz mimic server"`,
		"(`vpntest mimictrace`, `.github/scripts/mimic-tracer.ps1`)",
	} {
		if !strings.Contains(runbook, want) {
			t.Errorf("docs/first-test.md does not say %q", want)
		}
	}

	code := read(filepath.Join("src", "Cedar", "NodeMimicState.c"))
	for _, line := range []string{
		"so the node made the key of the server: it reports its public key",
		"the sidecar of the server listens",
		"Mimic transport unavailable: ",
		"ranz.exe, which holds the sidecar, is not installed at",
	} {
		if !strings.Contains(runbook, line) {
			t.Errorf("docs/first-test.md does not quote the line %q of the node log", line)
		}
		if !strings.Contains(code, line) {
			t.Errorf("src/Cedar/NodeMimicState.c does not log %q, which docs/first-test.md quotes", line)
		}
	}
}
