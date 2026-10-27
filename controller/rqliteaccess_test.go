package controllercmd

// The credential of the store and the encryption between the members (AUD1-DT-8, #456, ADR-0026
// amendment of 2026-10-27): rqlited runs with -auth, the controller, reset-admin, backup and
// restore send the credential, and -rqlite-external refuses a plain URL that is not loopback. The
// mutual TLS of the cluster is in cluster_test.go.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// -rqlite-external takes an https URL with its CA, and a plain http URL on loopback only: any
// other host would carry the credential and the store in clear text.
func TestParseFlagsRqliteExternalURL(t *testing.T) {
	for _, c := range []struct {
		url string
		ok  bool
	}{
		{"http://127.0.0.1:4001", true},
		{"http://localhost:4001", true},
		{"http://[::1]:4001", true},
		{"https://rqlite.example.com:4001", true},
		{"https://10.1.2.3:4001", true},
		{"http://10.1.2.3:4001", false},
		{"http://rqlite.example.com:4001", false},
		{"http://0.0.0.0:4001", false},
		{"ftp://127.0.0.1:4001", false},
		{"127.0.0.1:4001", false},
	} {
		_, err := parseFlags([]string{"-rqlite-external", "-rqlite", c.url})
		if (err == nil) != c.ok {
			t.Errorf("-rqlite-external -rqlite %s: %v, want accepted %v", c.url, err, c.ok)
		}
	}
	// Without -rqlite-external the controller runs the member itself, on the host that -rqlite names
	if _, err := parseFlags([]string{"-rqlite", "http://10.1.2.3:4001"}); err != nil {
		t.Errorf("-rqlite of the member of the controller: %v", err)
	}
}

// The members of a cluster use mutual TLS: -rqlite-join needs the three files, and the three go
// together.
func TestParseFlagsNodeCertificates(t *testing.T) {
	certs := []string{"-rqlite-node-ca-cert", "ca.pem", "-rqlite-node-cert", "node.pem", "-rqlite-node-key", "node.key"}
	join := []string{"-rqlite-join", "127.0.0.1:4002,127.0.0.1:4012,127.0.0.1:4022", "-rqlite-expect", "3"}
	for _, c := range []struct {
		name string
		args []string
		ok   bool
	}{
		{"a cluster with the files", slices.Concat(join, certs), true},
		{"a cluster without them", join, false},
		{"a cluster with two of them", slices.Concat(join, certs[:4]), false},
		{"a single member with the files", certs, true},
		{"a single member with one file", certs[:2], false},
		{"an external rqlite with the files", slices.Concat([]string{"-rqlite-external"}, certs), false},
	} {
		if _, err := parseFlags(c.args); (err == nil) != c.ok {
			t.Errorf("%s: %v, want accepted %v", c.name, err, c.ok)
		}
	}
}

// The first start of a single controller makes the credential, with a random password that is
// kept in the file and read again at the next start; a member of a cluster does not make it, and
// neither does a command that only reaches a store.
func TestRqliteAccessCredentialFile(t *testing.T) {
	parse := func(dir string, args ...string) config {
		t.Helper()
		cfg, err := parseFlags(append([]string{"-data", dir}, args...))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	dir := t.TempDir()
	file := filepath.Join(dir, rqliteAuthFile)

	a, path, created, err := parse(dir).rqliteAccess(false)
	if err != nil || a.User != "" || path != "" || created {
		t.Fatalf("a command that reaches a store made or read a credential: %+v %q %v, %v", a, path, created, err)
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a command that reaches a store made the credential file (%v)", err)
	}
	cluster := parse(dir, "-rqlite-join", "127.0.0.1:4002,127.0.0.1:4012,127.0.0.1:4022", "-rqlite-node-ca-cert", "a", "-rqlite-node-cert", "b", "-rqlite-node-key", "c")
	if _, _, _, err := cluster.rqliteAccess(true); err == nil || !strings.Contains(err.Error(), rqliteAuthFile) {
		t.Errorf("a member of a cluster with no credential file: %v, want an error that names %s", err, rqliteAuthFile)
	}

	a, path, created, err = parse(dir).rqliteAccess(true)
	if err != nil || !created || path != file || a.User != sidecar.CredentialUser || len(a.Password) < 32 {
		t.Fatalf("the first start made %+v %q created %v, %v", a, path, created, err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the credential file has the mode %v, want 0600", fi.Mode().Perm())
	}
	again, _, created, err := parse(dir).rqliteAccess(true)
	if err != nil || created || again.User != a.User || again.Password != a.Password {
		t.Errorf("the next start made or changed the credential: %+v created %v, %v", again, created, err)
	}
	if got, _, _, err := parse(dir).rqliteAccess(false); err != nil || got.Password != a.Password {
		t.Errorf("a command that reaches a store read %+v, %v, want %+v", got, err, a)
	}
	// A member of a cluster reads the file of the first member
	if got, _, _, err := cluster.rqliteAccess(true); err != nil || got.Password != a.Password {
		t.Errorf("a member of a cluster read %+v, %v, want %+v", got, err, a)
	}
	// An external rqlite with a file that is not there is an error, and with none it is reached open
	ext := parse(t.TempDir(), "-rqlite-external")
	if got, path, _, err := ext.rqliteAccess(false); err != nil || got.User != "" || path != "" {
		t.Errorf("an external rqlite with no credential file: %+v %q, %v", got, path, err)
	}
	ext = parse(t.TempDir(), "-rqlite-external", "-rqlite-auth", filepath.Join(t.TempDir(), "none.json"))
	if _, _, _, err := ext.rqliteAccess(false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an external rqlite with a -rqlite-auth that is not there: %v", err)
	}
}

// startRun runs the controller of args in this process, as TestRunServesWithItsRqliteMember does,
// and returns its configuration and the function that stops it and returns how it ended.
func startRun(t *testing.T, args ...string) (config, func() error) {
	t.Helper()
	addrs := freeAddrs(t, 3)
	dir := t.TempDir()
	cfg, err := parseFlags(append([]string{
		"-data", dir, "-listen", addrs[0], "-name", "c1", "-rqlite", "http://" + addrs[1], "-rqlite-raft", addrs[2], "-lease", "2s",
	}, append(memberRqlited(t), args...)...))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, runWith(t, cfg)
}

// runWith runs the controller of cfg in this process until the function it returns is called, or
// the test ends, and waits until it serves.
func runWith(t *testing.T, cfg config) func() error {
	t.Helper()
	var logs, rqliteOut bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, slog.New(slog.NewTextHandler(&logs, nil)), &rqliteOut, hooks{ready: func() { close(ready) }})
	}()
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		return <-done
	}
	t.Cleanup(func() { _ = stop() })
	select {
	case <-ready:
	case err := <-done:
		stopped = true
		cancel()
		t.Fatalf("the controller ended before it served: %v\n%s%s", err, logs.String(), rqliteOut.String())
	case <-time.After(clusterTimeout):
		_ = stop()
		t.Fatalf("the controller did not serve within %v\n%s%s", clusterTimeout, logs.String(), rqliteOut.String())
	}
	return stop
}

// rqliteStatus asks the rqlite of cfg to run a query on api_tokens with the credential user and
// password ("" for none) and returns the HTTP status.
func rqliteStatus(t *testing.T, cfg config, user, password string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, cfg.rqliteURL+"/db/query?q=SELECT+name+FROM+api_tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// The first criterion of #456: the first start makes the credential and starts rqlited with it. A
// request to its HTTP port with no credential, or a wrong one, gets 401, so a local process that
// does not hold the file cannot read the api_tokens table; the one that holds it reads it. Then
// reset-admin, backup and restore work against the running service, and against the stopped one,
// which they start the rqlited of themselves for.
func TestRqliteNeedsTheCredential(t *testing.T) {
	cfg, stop := startRun(t)
	file := filepath.Join(cfg.dataDir, rqliteAuthFile)
	user, password, err := sidecar.ReadCredential(file)
	if err != nil {
		t.Fatalf("the first start made no credential: %v", err)
	}

	if got := rqliteStatus(t, cfg, "", ""); got != http.StatusUnauthorized {
		t.Errorf("a request with no credential got %d, want 401", got)
	}
	if got := rqliteStatus(t, cfg, user, "not-"+password); got != http.StatusUnauthorized {
		t.Errorf("a request with a wrong password got %d, want 401", got)
	}
	if got := rqliteStatus(t, cfg, "someone", password); got != http.StatusUnauthorized {
		t.Errorf("a request with a wrong user got %d, want 401", got)
	}
	if got := rqliteStatus(t, cfg, user, password); got != http.StatusOK {
		t.Errorf("a request with the credential got %d, want 200", got)
	}
	// The store without the credential cannot even open, with it the tokens are there
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	short, shortCancel := context.WithTimeout(ctx, 2*time.Second)
	if st, err := store.Open(short, cfg.rqliteURL); err == nil {
		st.Close()
		t.Error("the store opened an rqlite that asks for a credential with none")
	}
	shortCancel()
	a, _, _, err := cfg.rqliteAccess(false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWith(ctx, cfg.rqliteURL, a)
	if err != nil {
		t.Fatal(err)
	}
	if ts, err := rbac.New(st).List(ctx); err != nil || len(ts) != 1 || ts[0].Name != rbac.FirstAdmin {
		t.Errorf("the tokens with the credential: %+v, %v", ts, err)
	}
	st.Close()

	allowed := func() error { return nil }
	backupFile := filepath.Join(cfg.dataDir, "store.backup")
	// Against the running service
	if _, _, err := resetAdmin(ctx, cfg, allowed, io.Discard); err != nil {
		t.Errorf("reset-admin against the running service: %v", err)
	}
	if _, err := backup(ctx, cfg, backupFile, allowed, io.Discard); err != nil {
		t.Errorf("backup against the running service: %v", err)
	}
	if err := restore(ctx, cfg, backupFile, allowed, io.Discard); err != nil {
		t.Errorf("restore against the running service: %v", err)
	}

	if err := stop(); err != nil {
		t.Fatalf("the controller ended with %v", err)
	}
	// Against the stopped service, whose rqlited each command starts, with the credential
	if _, _, err := resetAdmin(ctx, cfg, allowed, io.Discard); err != nil {
		t.Errorf("reset-admin against the stopped service: %v", err)
	}
	if _, err := backup(ctx, cfg, backupFile, allowed, io.Discard); err != nil {
		t.Errorf("backup against the stopped service: %v", err)
	}
	if err := restore(ctx, cfg, backupFile, allowed, io.Discard); err != nil {
		t.Errorf("restore against the stopped service: %v", err)
	}
	if _, again, err := sidecar.ReadCredential(file); err != nil || again != password {
		t.Errorf("the credential file changed under the commands (%v)", err)
	}
}

// A restart finds the credential file and uses the same credential, on the data that it protects.
func TestRqliteCredentialSurvivesARestart(t *testing.T) {
	cfg, stop := startRun(t)
	file := filepath.Join(cfg.dataDir, rqliteAuthFile)
	_, first, err := sidecar.ReadCredential(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	defer runWith(t, cfg)()
	if _, second, err := sidecar.ReadCredential(file); err != nil || second != first {
		t.Errorf("the credential changed at the restart (%v)", err)
	}
	if got := rqliteStatus(t, cfg, "", ""); got != http.StatusUnauthorized {
		t.Errorf("after the restart a request with no credential got %d, want 401", got)
	}
}
