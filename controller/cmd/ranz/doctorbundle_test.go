package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// The secrets that the files of a host hold in the tests of ranz doctor --bundle.
const (
	hostBGPPassword = "Sup3rS3cretBgpMd5"
	hostAPIToken    = "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23"
	hostFileToken   = "ranz_ZYXWVUTSRQPONMLKJIHGFEDCBA2"
	hostKeyBody     = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCplantedhostkeybody"
)

// hostFiles writes the files of a host that has a Node and a Controller on it, with secrets in
// them, and returns the data directory of the Node and the one of the Controller.
func hostFiles(t *testing.T) (nodeDir, controllerDir string) {
	t.Helper()
	nodeDir, controllerDir = t.TempDir(), t.TempDir()
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
	write(nodeLog, "node_20261023.log", "2026-10-23 10:00:00.000 Node started: 4 workers\r\n2026-10-23 10:00:01.000 BGP peer 192.0.2.1 password="+hostBGPPassword+" accepted\r\n")
	write(nodeLog, "node_20261023~01.log", "2026-10-23 11:00:00.000 Role relay started\r\n")
	write(nodeLog, "ranz-bgp.log", "time=2026-10-23T10:00:02Z level=INFO msg=\"connected to the node\" command=\"ranz.exe bgp -pipe x -log y\"\n")
	write(nodeDir, nodeConfigFile, "setting\tRoles\tserver, relay\nsetting\tBgp\t{\"peers\": [{\"address\": \"192.0.2.1\", \"password\": \""+hostBGPPassword+"\"}]}\nuser\tcorp\talice\tpassword set\n")
	write(controllerDir, "controller.log", "2026-10-23T10:00:00.000Z INFO first start: the admin token is created token="+hostAPIToken+" file=admin.token\n")
	// What no source names stays on the host: the token file, the keys and the databases
	write(controllerDir, "admin.token", hostFileToken+"\n")
	write(controllerDir, "controller.key", "-----BEGIN PRIVATE KEY-----\n"+hostKeyBody+"\n-----END PRIVATE KEY-----\n")
	write(nodeDir, "ranz_node.db", "SQLite format 3 passwordHash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")
	return nodeDir, controllerDir
}

// hostBundleFiles returns the files of the ZIP archive at path by name.
func hostBundleFiles(t *testing.T, path string) (map[string]string, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("%s is no ZIP archive: %v", path, err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
	}
	return files, data
}

// ranz doctor --bundle is the first half of the second criterion of SDN-54 (#247, user story 58): it
// writes the bundle of the host, with the parts that its sources name and no secret in any of them.
// The files that no source names, the token file, the keys and the databases, are not in it, and a
// bundle is never written over a file.
func TestDoctorBundle(t *testing.T) {
	nodeDir, controllerDir := hostFiles(t)
	out := filepath.Join(t.TempDir(), "host.zip")
	args := []string{"-bundle", "-o", out, "-node-dir", nodeDir, "-controller-dir", controllerDir}
	var stdout, stderr bytes.Buffer
	if code := runDoctor(context.Background(), args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("ranz doctor --bundle: exit code %d, stderr %q, stdout:\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "All checks passed") || !strings.Contains(stdout.String(), "Diagnostics bundle written to "+out+": ") {
		t.Errorf("the output of ranz doctor --bundle is\n%s", stdout.String())
	}
	files, data := hostBundleFiles(t, out)

	// The parts: the ones that the sources name, and no other
	want := []string{bundle.ManifestName, "system.json", "doctor.txt", "node/logs/node_20261023.log", "node/logs/node_20261023~01.log",
		"node/logs/ranz-bgp.log", "node/config.txt", "controller/logs/controller.log"}
	for name := range files {
		if !slices.Contains(want, name) && name != "services.json" {
			t.Errorf("the bundle holds the part %s, which no source names", name)
		}
	}
	for _, name := range want {
		if _, ok := files[name]; !ok {
			t.Errorf("the bundle has no part %s", name)
		}
	}
	var m bundle.Manifest
	if err := json.Unmarshal([]byte(files[bundle.ManifestName]), &m); err != nil {
		t.Fatal(err)
	}
	if m.Kind != "host" || m.Product != "Ranz" || !strings.HasPrefix(m.Version, version.Version+".") || len(m.Parts) != len(files)-1 {
		t.Errorf("the manifest is %+v", m)
	}
	for _, p := range m.Parts {
		redacted := p.Name == "node/logs/node_20261023.log" || p.Name == "node/config.txt" || p.Name == "controller/logs/controller.log"
		if redacted && p.Redactions == 0 {
			t.Errorf("the manifest counts no secret replaced in %s, which held one", p.Name)
		}
	}

	// What the parts say
	if report := files["doctor.txt"]; !strings.Contains(report, "Checking 'Kernel System'... Pass") || !strings.Contains(report, "All checks passed") {
		t.Errorf("the report of the checks in the bundle is\n%s", report)
	}
	if text := files["node/logs/node_20261023.log"]; !strings.Contains(text, "Node started: 4 workers") || !strings.Contains(text, "BGP peer 192.0.2.1") {
		t.Errorf("the log of the Node in the bundle is\n%s", text)
	}
	if text := files["node/config.txt"]; !strings.Contains(text, "server, relay") || !strings.Contains(text, "192.0.2.1") {
		t.Errorf("the configuration of the Node in the bundle is\n%s", text)
	}

	// No secret in any part, and none from a file that no source names
	for _, secret := range []string{hostBGPPassword, hostAPIToken, hostFileToken, hostKeyBody, "c2FsdA$aGFzaA"} {
		for name, content := range files {
			if strings.Contains(content, secret) {
				t.Errorf("the part %s holds the secret %q:\n%s", name, secret, content)
			}
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the archive holds the secret %q", secret)
		}
	}

	// A bundle is never written over a file, and the one that is there stays as it was
	stdout.Reset()
	stderr.Reset()
	if code := runDoctor(context.Background(), args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "exists already") || stdout.Len() != 0 {
		t.Errorf("ranz doctor --bundle over a file: exit code %d, stderr %q, stdout %q", code, stderr.String(), stdout.String())
	}
	if again, err := os.ReadFile(out); err != nil || !bytes.Equal(again, data) {
		t.Errorf("the bundle that was there was changed: %v", err)
	}
}

// Without -o the bundle is ranz-host-NAME-TIME.zip in the current directory, and -o without -bundle is
// an error of the arguments.
func TestDoctorBundleDefaultFile(t *testing.T) {
	nodeDir, controllerDir := hostFiles(t)
	t.Chdir(t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := runDoctor(context.Background(), []string{"-bundle", "-node-dir", nodeDir, "-controller-dir", controllerDir}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("ranz doctor --bundle: exit code %d, stderr %q, stdout:\n%s", code, stderr.String(), stdout.String())
	}
	matches, err := filepath.Glob("ranz-host-*.zip")
	if err != nil || len(matches) != 1 || !regexp.MustCompile(`^ranz-host-.+-\d{8}T\d{6}Z\.zip$`).MatchString(matches[0]) {
		t.Errorf("the bundle files in the current directory are %q, %v", matches, err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runDoctor(context.Background(), []string{"-o", "x.zip"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "needs -bundle") || stdout.Len() != 0 {
		t.Errorf("ranz doctor -o without -bundle: exit code %d, stderr %q, stdout %q", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat("x.zip"); err == nil {
		t.Error("ranz doctor -o without -bundle wrote a file")
	}
}

// The sources of a host that has no Node and no Controller on it give the host and the report only, a
// source that fails is named in the manifest, and a bundle that fails leaves no file.
func TestHostSourcesAndFailedBundle(t *testing.T) {
	var names []string
	for _, s := range hostSources("report\n", "", "") {
		names = append(names, s.Name)
	}
	if want := []string{"system", "services", "doctor"}; !slices.Equal(names, want) {
		t.Errorf("the sources of a bare host are %q, want %q", names, want)
	}
	dir := t.TempDir()
	// A file that cannot be a configuration of the Node: a directory in its place is an error of the source
	nodeDir := filepath.Join(dir, "node")
	if err := os.MkdirAll(filepath.Join(nodeDir, nodeConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "x.zip")
	m, err := writeBundle(context.Background(), out, hostSources("report\n", nodeDir, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Problems) == 0 || !strings.Contains(strings.Join(m.Problems, "\n"), "node configuration") {
		t.Errorf("the manifest names the problems %q, want the configuration of the Node", m.Problems)
	}
	// A bundle whose context ended fails, and no file stays
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failed := filepath.Join(dir, "failed.zip")
	if _, err := writeBundle(ctx, failed, hostSources("report\n", "", "")); err == nil {
		t.Error("a bundle whose context ended was written")
	}
	if _, err := os.Stat(failed); err == nil {
		t.Error("a bundle that failed left its file")
	}
}
