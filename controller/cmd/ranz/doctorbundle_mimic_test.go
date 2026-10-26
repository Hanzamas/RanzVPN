package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mimicPrivateKey is the REALITY private key that the tests plant in the settings of a Node: the private
// key of Alice in RFC 7748 section 6.1, as `ranz mimic -keygen` writes a key.
const mimicPrivateKey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

// The REALITY private key of a mimic server is part of the MimicServer setting of the Node, which the
// text dump of its configuration store holds as it holds every setting (CORE-P2-6, #406). The
// diagnostics bundle carries that dump and the logs of the mimicry sidecars, and the key is in none of
// its parts: the redaction blanks the value of private_key in the escaped JSON of the dump.
func TestDoctorBundleBlanksTheMimicKey(t *testing.T) {
	nodeDir, controllerDir := t.TempDir(), t.TempDir()
	write := func(dir, name, text string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodeLog := filepath.Join(nodeDir, "node_log")
	write(nodeLog, "node_20261026.log", "2026-10-26 10:00:00.000 Mimic server sidecar ready: ranz mimic (protocol 1), REALITY listener on 127.0.0.1:55443\r\n")
	write(nodeLog, "ranz-mimic-server.log", "time=2026-10-26T10:00:00Z level=INFO msg=\"connected to the node\" command=\"ranz.exe mimic -pipe x -log y\"\n")
	// The setting as CsDump writes it: a quoted string with escaped quotes
	write(nodeDir, nodeConfigFile, "schema 1\n"+
		`setting name="MimicServer" value="{\"listen\":\"127.0.0.1:0\",\"private_key\":\"`+mimicPrivateKey+`\",\"short_ids\":[\"a1b2\"],\"server_names\":[\"decoy.test\"],\"decoy\":{\"self_signed\":true}}"`+"\n"+
		`setting name="Roles" value="none"`+"\n")

	out := filepath.Join(t.TempDir(), "host.zip")
	var stdout, stderr bytes.Buffer
	args := []string{"-bundle", "-o", out, "-node-dir", nodeDir, "-controller-dir", controllerDir}
	if code := runDoctor(context.Background(), args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("ranz doctor --bundle: exit code %d, stderr %q, stdout:\n%s", code, stderr.String(), stdout.String())
	}
	files, data := hostBundleFiles(t, out)

	for _, name := range []string{"node/config.txt", "node/logs/node_20261026.log", "node/logs/ranz-mimic-server.log"} {
		if _, ok := files[name]; !ok {
			t.Errorf("the bundle has no part %s", name)
		}
	}
	if text := files["node/config.txt"]; !strings.Contains(text, "MimicServer") || !strings.Contains(text, "decoy.test") || !strings.Contains(text, "private_key") {
		t.Errorf("the configuration of the Node in the bundle lost more than the key:\n%s", text)
	}
	for name, content := range files {
		if strings.Contains(strings.ToLower(content), mimicPrivateKey) {
			t.Errorf("the part %s holds the REALITY private key:\n%s", name, content)
		}
	}
	if bytes.Contains(data, []byte(mimicPrivateKey)) {
		t.Error("the archive holds the REALITY private key")
	}
}
