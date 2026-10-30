package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The tests of the certificate of a Controller on this host (AUD1-DT-13, #461): ranz checks a loopback address
// by the fingerprint in the data directory of the Controller, or by -tls-fingerprint, and sends no token to
// what does not have it.

// fingerprintOf returns the TLS fingerprint of the certificate cert, as the Controller writes it to its data
// directory.
func fingerprintOf(cert *x509.Certificate) string {
	return keys.Fingerprint(tls.Certificate{Leaf: cert})
}

// answering is a TLS server on a loopback address that stands for what answers on the port of the Controller:
// it counts the connections that it accepts, and keeps the Authorization header of each request that reaches it.
type answering struct {
	srv *httptest.Server

	mu    sync.Mutex
	conns int
	auth  []string
}

// countingListener counts the connections that its listener accepts.
type countingListener struct {
	net.Listener
	a *answering
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.a.mu.Lock()
		l.a.conns++
		l.a.mu.Unlock()
	}
	return c, err
}

// answerer starts a server that answers every call as the admin token, with a certificate of a key of its own.
// It returns the server and the TLS fingerprint of that certificate.
func answerer(t *testing.T) (*answering, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(key)
	if err != nil {
		t.Fatal(err)
	}
	a := &answering{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		a.mu.Unlock()
		api.Reply(w, http.StatusOK, rbac.Token{Name: "admin", Role: rbac.Admin})
	}))
	srv.Listener = countingListener{Listener: srv.Listener, a: a}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	a.srv = srv
	return a, keys.Fingerprint(cert)
}

// seen returns the connections that the server accepted and the Authorization headers that it got.
func (a *answering) seen() (int, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conns, append([]string(nil), a.auth...)
}

// TestRanzRefusesAnotherKeyOnLoopbackAndSendsNoToken is the third criterion of AUD1-DT-13 (#461): a listener on a
// loopback address that presents another key makes ranz refuse and send no token, and the right key works. The
// fingerprint comes from the file of the data directory, and -tls-fingerprint takes the place of the file.
func TestRanzRefusesAnotherKeyOnLoopbackAndSendsNoToken(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	other, otherFP := answerer(t)
	if rightFP == otherFP {
		t.Fatal("two keys have one fingerprint")
	}
	dir := t.TempDir()
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	trustFingerprint(t, dir)
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte("ranz_ADMINSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// whoami calls the server at the URL with the fingerprint and the data directory that ranz is given
	whoami := func(url, fingerprint, controllerDir string) (string, error) {
		t.Helper()
		c, err := newClient(url, tokenFile, "", fingerprint, controllerDir)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = do(ctx, c, []string{"whoami"}, &out)
		return out.String(), err
	}

	// The right key works, and the token goes with the call
	out, err := whoami(right.srv.URL, "", dir)
	if err != nil || !strings.Contains(out, `"name": "admin"`) {
		t.Fatalf("the listener with the key of the Controller gave %q, %v, want its answer", out, err)
	}
	if conns, auth := right.seen(); conns != 1 || len(auth) != 1 || auth[0] != "Bearer ranz_ADMINSECRET" {
		t.Errorf("the right listener got %d connections and the headers %q, want one call with the token", conns, auth)
	}

	// Another key is refused: the refusal says what ranz found and what it expected, and no request reaches the
	// listener, so the token stays with ranz
	_, err = whoami(other.srv.URL, "", dir)
	refusal := loopbackRefusal(err)
	var refused *mismatch
	if !errors.As(refusal, &refused) || refused.err.Got != otherFP || refused.err.Want != rightFP {
		t.Fatalf("the listener with another key gave %v, want a refusal with its fingerprint %s and the %s of the Controller", err, otherFP, rightFP)
	}
	for _, want := range []string{"sent no token", other.srv.URL, otherFP, rightFP, filepath.Join(dir, servercert.FingerprintFile)} {
		if !strings.Contains(refusal.Error(), want) {
			t.Errorf("the refusal %q does not say %q", refusal, want)
		}
	}
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got the headers %q, want no request: the token must not leave ranz", auth)
	}

	// -tls-fingerprint takes the place of the file, whichever it names
	if out, err := whoami(other.srv.URL, otherFP, dir); err != nil || !strings.Contains(out, `"name": "admin"`) {
		t.Errorf("the fingerprint of the listener on the command line gave %q, %v, want its answer", out, err)
	}
	_, err = whoami(right.srv.URL, otherFP, dir)
	var pinned *api.FingerprintError
	if !errors.As(err, &pinned) || loopbackRefusal(err) != nil {
		t.Errorf("the fingerprint of another key on the command line gave %v, want the plain refusal of the pin", err)
	}
	if _, auth := right.seen(); len(auth) != 1 {
		t.Errorf("the right listener got %d requests, want the one of the first call and none of the refused one", len(auth))
	}
}

// Where ranz cannot read the fingerprint it sends no token and does not even connect: the file is not there, it
// holds no fingerprint, or the data directory is the default one of the service and the Controller is not on this
// host. The refusal names the data directory and asks for -tls-fingerprint.
func TestRanzSendsNoTokenToLoopbackWithoutAFingerprint(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte("ranz_ADMINSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, garbled := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(garbled, servercert.FingerprintFile), []byte("not a fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustFingerprint(t, garbled)

	for _, c := range []struct {
		name, dir, want string
	}{
		{"a data directory with no file", empty, empty},
		{"a data directory that is not there", filepath.Join(empty, "none"), filepath.Join(empty, "none")},
		{"a file with no fingerprint", garbled, "no TLS fingerprint"},
		{"the data directory of the service", "", controllercmd.DefaultDataDir()},
	} {
		cl, err := newClient(right.srv.URL, tokenFile, "", "", c.dir)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		err = do(ctx, cl, []string{"whoami"}, &bytes.Buffer{})
		refusal := loopbackRefusal(err)
		var refused *unchecked
		if !errors.As(refusal, &refused) {
			t.Errorf("%s: %v, want the refusal to call without a fingerprint", c.name, err)
			continue
		}
		for _, want := range []string{"sends no token", right.srv.URL, "-tls-fingerprint", "RANZ_TLS_FINGERPRINT", "-controller-dir", servercert.FingerprintFile, c.want} {
			if !strings.Contains(refusal.Error(), want) {
				t.Errorf("%s: the refusal %q does not say %q", c.name, refusal, want)
			}
		}
		if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
			t.Errorf("%s: the listener got %d connections and %d requests, want none: ranz must not connect before it knows who answers", c.name, conns, len(auth))
		}
	}
	// A call with a body, which ranz sends as a POST, is refused as well
	post, err := newClient(right.srv.URL, tokenFile, "", "", empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := do(ctx, post, []string{"token", "create", "-role", "viewer", "ci"}, &bytes.Buffer{}); loopbackRefusal(err) == nil {
		t.Errorf("a call with a body gave %v, want the refusal to call without a fingerprint", err)
	}
	if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
		t.Errorf("the listener got %d connections and %d requests, want none", conns, len(auth))
	}

	// With the fingerprint on the command line the same server answers
	pinned, err := newClient(right.srv.URL, tokenFile, "", rightFP, garbled)
	if err != nil {
		t.Fatal(err)
	}
	if err := do(ctx, pinned, []string{"whoami"}, &bytes.Buffer{}); err != nil {
		t.Errorf("with the fingerprint on the command line ranz gave %v", err)
	}
}

// Only a loopback host is checked by the data directory: a host that is not one has its certificate checked as
// before, by its chain or by -tls-fingerprint, and a plain HTTP address of the host has no certificate.
func TestRanzChecksOnlyLoopbackByTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		server string
		client bool // whether the client has a transport of its own: it checks nothing itself, a pin or a refusal does
	}{
		{"https://ctl.example", false},
		{"https://192.0.2.10:5555", false},
		{"http://127.0.0.1:7080", false},
		{"https://127.0.0.1", true},
		{"https://localhost:5555", true},
		{"https://[::1]:443", true},
	} {
		cl, err := newClient(c.server, "", "ranz_X", "", dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := cl.HTTP != nil; got != c.client {
			t.Errorf("%s: a transport of its own is %v, want %v", c.server, got, c.client)
			continue
		}
		if !c.client {
			continue
		}
		if _, ok := cl.HTTP.Transport.(refusing); !ok {
			t.Errorf("%s: the data directory %s holds no fingerprint, and the client does not refuse", c.server, dir)
		}
	}
	// A fingerprint on the command line pins a host that is not loopback, as before
	cl, err := newClient("https://ctl.example", "", "ranz_X", testFingerprint, dir)
	if err != nil || cl.HTTP == nil {
		t.Errorf("a host that is not loopback with a fingerprint gave %+v, %v, want a pinned client", cl, err)
	}
}

// ranz explain has the connection flags of the CLI and checks a loopback address as the CLI does: it sends no token
// without a fingerprint to check by, nor to another key, and takes the data directory from -controller-dir or from
// RANZ_CONTROLLER_DIR, and the fingerprint from -tls-fingerprint.
func TestRanzExplainChecksLoopbackToo(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	other, otherFP := answerer(t)
	dir, empty := t.TempDir(), t.TempDir()
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	trustFingerprint(t, dir)
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte("ranz_ADMINSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// explainAt runs ranz explain toward server with the flags, and returns its exit code and its standard error
	explainAt := func(server string, flags ...string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		args := append([]string{"-server", server, "-token-file", tokenFile}, flags...)
		code := runExplain(ctx, append(args, "node-a", "node-b"), &out, &errOut)
		return code, errOut.String()
	}

	// With no fingerprint to check by it sends no token and does not even connect
	code, errOut := explainAt(right.srv.URL, "-controller-dir", empty)
	for _, want := range []string{"sends no token", "-tls-fingerprint", empty} {
		if code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("ranz explain with no fingerprint: exit code %d, %q, want 1 and %q", code, errOut, want)
		}
	}
	if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
		t.Errorf("the listener got %d connections and %d requests, want none: ranz must not connect before it knows who answers", conns, len(auth))
	}

	// Another key is refused with both fingerprints, and no request reaches its listener
	code, errOut = explainAt(other.srv.URL, "-controller-dir", dir)
	for _, want := range []string{"sent no token", otherFP, rightFP} {
		if code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("ranz explain toward another key: exit code %d, %q, want 1 and %q", code, errOut, want)
		}
	}
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got the headers %q, want no request: the token must not leave ranz", auth)
	}

	// The right key works, by the file of the data directory that the flag names, by the one that RANZ_CONTROLLER_DIR
	// names, and by -tls-fingerprint
	explainAt(right.srv.URL, "-controller-dir", dir)
	t.Setenv("RANZ_CONTROLLER_DIR", dir)
	explainAt(right.srv.URL)
	if _, auth := right.seen(); len(auth) != 2 || auth[0] != "Bearer ranz_ADMINSECRET" || auth[1] != auth[0] {
		t.Errorf("the right listener got the headers %q, want two calls with the token", auth)
	}
	explainAt(other.srv.URL, "-tls-fingerprint", otherFP)
	if _, auth := other.seen(); len(auth) != 1 || auth[0] != "Bearer ranz_ADMINSECRET" {
		t.Errorf("the listener with the fingerprint on the command line got the headers %q, want one call with the token", auth)
	}
}

// ranz login and ranz node login (SDN-32, #226) have the connection flags of the CLI and check a loopback address as
// the CLI does: a password or a code goes to the key of the Controller only. With no fingerprint to check by, or toward
// another key, they send nothing and do not even connect; the data directory comes from -controller-dir or from
// RANZ_CONTROLLER_DIR, and -tls-fingerprint takes the place of the file.
func TestRanzLoginChecksLoopbackToo(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	other, otherFP := answerer(t)
	dir, empty := t.TempDir(), t.TempDir()
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	trustFingerprint(t, dir)
	// loginAt runs ranz login with a password toward server and the flags, and returns its exit code and its standard
	// error
	loginAt := func(server string, flags ...string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		args := append([]string{"-server", server, "-user", "alice"}, flags...)
		code := runLogin(ctx, args, strings.NewReader("a password\n"), &out, &errOut)
		return code, errOut.String()
	}

	// With no fingerprint to check by it sends no password and does not even connect
	code, errOut := loginAt(right.srv.URL, "-controller-dir", empty)
	for _, want := range []string{"sends no token", "-tls-fingerprint", empty} {
		if code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("ranz login with no fingerprint: exit code %d, %q, want 1 and %q", code, errOut, want)
		}
	}
	if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
		t.Errorf("the listener got %d connections and %d requests, want none: ranz must not connect before it knows who answers", conns, len(auth))
	}

	// Another key is refused with both fingerprints, and no request reaches its listener
	code, errOut = loginAt(other.srv.URL, "-controller-dir", dir)
	for _, want := range []string{"sent no token", otherFP, rightFP} {
		if code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("ranz login toward another key: exit code %d, %q, want 1 and %q", code, errOut, want)
		}
	}
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got %d requests, want none: the password must not leave ranz", len(auth))
	}

	// The right key gets the login, by the file of the data directory that the flag names, by the one that
	// RANZ_CONTROLLER_DIR names, and by -tls-fingerprint
	loginAt(right.srv.URL, "-controller-dir", dir)
	t.Setenv("RANZ_CONTROLLER_DIR", dir)
	loginAt(right.srv.URL)
	if _, auth := right.seen(); len(auth) != 2 {
		t.Errorf("the right listener got %d requests, want the two logins", len(auth))
	}
	loginAt(other.srv.URL, "-tls-fingerprint", otherFP)
	if _, auth := other.seen(); len(auth) != 1 {
		t.Errorf("the listener with the fingerprint on the command line got %d requests, want the login", len(auth))
	}

	// ranz node login asks the Node service for its key, and then makes the same check
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	node := &fakeNode{answers: map[string]string{"key": `{"publicKey":"` + base64.StdEncoding.EncodeToString(nodeKey.Public()) + `"}`}}
	var out, nodeErr bytes.Buffer
	code = nodeLogin(ctx, []string{"-server", other.srv.URL, "-controller-dir", dir, "-device"}, &out, &nodeErr, node)
	for _, want := range []string{"sent no token", otherFP, rightFP} {
		if code != 1 || !strings.Contains(nodeErr.String(), want) {
			t.Errorf("ranz node login toward another key: exit code %d, %q, want 1 and %q", code, nodeErr.String(), want)
		}
	}
	if _, auth := other.seen(); len(auth) != 1 {
		t.Errorf("the listener with another key got %d requests, want the one of the login with its fingerprint and none of the Node's", len(auth))
	}
}

// loopbackRefusal finds the refusal in what the HTTP client made of it, and in nothing else.
func TestLoopbackRefusal(t *testing.T) {
	u := &unchecked{server: "https://127.0.0.1", dir: "d", err: os.ErrNotExist}
	m := &mismatch{server: "https://127.0.0.1", file: "f", err: &api.FingerprintError{Got: "a", Want: "b"}}
	if got := loopbackRefusal(u); got != error(u) {
		t.Errorf("the refusal to call is found as %v", got)
	}
	if got := loopbackRefusal(m); got != error(m) {
		t.Errorf("the mismatch is found as %v", got)
	}
	if !errors.Is(u, os.ErrNotExist) || !errors.Is(m, m.err) {
		t.Error("the refusals do not unwrap to their causes")
	}
	for _, err := range []error{nil, errors.New("connection refused"), &api.Error{Status: http.StatusUnauthorized}} {
		if got := loopbackRefusal(err); got != nil {
			t.Errorf("%v holds the refusal %v", err, got)
		}
	}
}

// The refusal of a fingerprint file that another account may have written (AUD1-DT-14, #496) says so in its one line,
// with what it refuses and why, and asks for -tls-fingerprint. It does not send the reader to that file for the
// fingerprint, as the refusal of a file that cannot be read does.
func TestTheRefusalOfAFileThatIsNotTrustedSaysWhy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "controller")
	why := &controllercmd.UntrustedError{Path: dir, Why: `may be written by BUILTIN\Users`}
	untrusted := (&unchecked{server: "https://127.0.0.1", dir: dir, err: why}).Error()
	for _, want := range []string{"sends no token to https://127.0.0.1", "does not trust that file", dir + ` may be written by BUILTIN\Users`, "SYSTEM, the Administrators and the account of the Controller service", "-tls-fingerprint", "RANZ_TLS_FINGERPRINT"} {
		if !strings.Contains(untrusted, want) {
			t.Errorf("the refusal %q does not say %q", untrusted, want)
		}
	}
	unreadable := (&unchecked{server: "https://127.0.0.1", dir: dir, err: os.ErrPermission}).Error()
	for _, c := range []struct {
		text, says, not string
	}{
		{untrusted, "does not trust", "finds it in that file"},
		{unreadable, "cannot be read", "does not trust"},
	} {
		if !strings.Contains(c.text, c.says) || strings.Contains(c.text, c.not) || strings.Contains(c.text, "\n") {
			t.Errorf("the refusal %q does not say %q in one line, or says %q", c.text, c.says, c.not)
		}
	}
}
