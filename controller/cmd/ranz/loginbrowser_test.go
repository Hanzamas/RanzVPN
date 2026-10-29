package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The browser login checks the Controller before it opens the browser (AUD1-DT-19, #506). ranz login and ranz node
// login in the browser send the user to a page where a password is typed, and a browser cannot check the certificate
// that it is shown. So ranz makes one call to that page through the client that checks the certificate as the CLI
// checks a call with a token (loopback.go), and opens no browser when the call is refused. The tests of
// loopback_test.go show that the logins which send their secret themselves go to the key of the Controller only.

// browsed is what the browser of a test was asked to open: the pages, and for each the number of requests that the
// listener the test watches had got by the time ranz opened it.
type browsed struct {
	mu       sync.Mutex
	pages    []string
	requests []int
}

// opened returns the pages that ranz opened, and for each the requests of the watched listener by then.
func (b *browsed) opened() ([]string, []int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.pages...), append([]int(nil), b.requests...)
}

// browseRecording replaces the browser of ranz, until the test ends, with one that records the pages that ranz opens
// and the requests that the listener watched had got by then, and that does what a user does who signs in: it brings
// a code to the loopback redirect of the page, so that the login goes on. A nil watched has no requests to count.
func browseRecording(t *testing.T, watched *answering) *browsed {
	t.Helper()
	b := &browsed{}
	before := openBrowser
	t.Cleanup(func() { openBrowser = before })
	openBrowser = func(page string) error {
		n := 0
		if watched != nil {
			_, auth := watched.seen()
			n = len(auth)
		}
		b.mu.Lock()
		b.pages = append(b.pages, page)
		b.requests = append(b.requests, n)
		b.mu.Unlock()
		u, err := url.Parse(page)
		if err != nil {
			return err
		}
		q := u.Query()
		resp, err := http.Get(q.Get("redirect_uri") + "?" + url.Values{"code": {"a-code"}, "state": {q.Get("state")}}.Encode())
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	return b
}

// TestRanzLoginOpensNoBrowserBeforeItHasCheckedTheCertificate is the first criterion of AUD1-DT-19 (#506): with a
// listener on a loopback address that presents another key than the Controller's, ranz login opens no browser, sends
// nothing and says that the certificate is not the one of the Controller; with the right key it opens the browser.
func TestRanzLoginOpensNoBrowserBeforeItHasCheckedTheCertificate(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	other, otherFP := answerer(t)
	dir, empty := t.TempDir(), t.TempDir()
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	browser := browseRecording(t, right)
	// loginAt runs ranz login, which signs in in the browser, toward server with the flags, and returns its exit code
	// and its standard error
	loginAt := func(server string, flags ...string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runLogin(ctx, append([]string{"-server", server}, flags...), nil, &out, &errOut)
		return code, errOut.String()
	}
	noBrowser := func(what string) {
		t.Helper()
		if pages, _ := browser.opened(); len(pages) != 0 {
			t.Errorf("%s: ranz opened the browser at %q, want no browser", what, pages)
		}
	}

	// Another key: ranz opens no browser, shows no page to open, sends no request, and says that the certificate is not
	// the one that the file of the Controller names, with both fingerprints
	code, errOut := loginAt(other.srv.URL, "-controller-dir", dir)
	if code != 1 {
		t.Errorf("ranz login toward another key: exit code %d, want 1", code)
	}
	for _, want := range []string{"no browser was opened", "sent no token", other.srv.URL, otherFP, rightFP, filepath.Join(dir, servercert.FingerprintFile)} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ranz login toward another key says %q, want it to say %q", errOut, want)
		}
	}
	if strings.Contains(errOut, "Sign in on the page") {
		t.Errorf("ranz login toward another key shows a page to sign in on: %q", errOut)
	}
	noBrowser("toward another key")
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got %d requests, want none: nothing may leave ranz for it", len(auth))
	}

	// No fingerprint to check by: ranz does not even connect, and opens no browser
	code, errOut = loginAt(right.srv.URL, "-controller-dir", empty)
	if code != 1 {
		t.Errorf("ranz login with no fingerprint: exit code %d, want 1", code)
	}
	for _, want := range []string{"no browser was opened", "sends no token", "-tls-fingerprint", empty} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ranz login with no fingerprint says %q, want it to say %q", errOut, want)
		}
	}
	noBrowser("with no fingerprint to check by")
	if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
		t.Errorf("the listener got %d connections and %d requests, want none: ranz must not connect before it knows who answers", conns, len(auth))
	}

	// The fingerprint of another key on the command line is refused as the file is, and the message does not carry the
	// query of the request, which holds the state and the challenge of the login
	code, errOut = loginAt(other.srv.URL, "-tls-fingerprint", rightFP)
	if code != 1 {
		t.Errorf("ranz login toward another key with its fingerprint on the command line: exit code %d, want 1", code)
	}
	for _, want := range []string{"no browser was opened", otherFP, rightFP} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ranz login toward another key with its fingerprint on the command line says %q, want it to say %q", errOut, want)
		}
	}
	if strings.Contains(errOut, "code_challenge") {
		t.Errorf("ranz login says %q, which holds the query of the call that was refused", errOut)
	}
	noBrowser("toward another key with its fingerprint on the command line")
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got %d requests, want none", len(auth))
	}

	// A server of the right key that does not serve the authorization page, as a Controller of before the logins does not:
	// no browser, and the message says what it answered
	older := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no bearer token", http.StatusUnauthorized)
	}))
	t.Cleanup(older.Close)
	code, errOut = loginAt(older.URL, "-tls-fingerprint", fingerprintOf(older.Certificate()))
	if code != 1 {
		t.Errorf("ranz login toward a server that serves no authorization page: exit code %d, want 1", code)
	}
	for _, want := range []string{"no browser was opened", "did not serve its authorization page", "401"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ranz login toward a server that serves no authorization page says %q, want it to say %q", errOut, want)
		}
	}
	noBrowser("toward a server that serves no authorization page")

	// The right key: the call that checks the Controller comes first, carries no token, and the browser opens at the
	// page, which ranz also says in case no browser opens
	_, errOut = loginAt(right.srv.URL, "-controller-dir", dir)
	pages, requests := browser.opened()
	if len(pages) != 1 || !strings.HasPrefix(pages[0], right.srv.URL+login.AuthorizePath+"?") {
		t.Fatalf("ranz login toward the key of the Controller opened %q, want its authorization page once", pages)
	}
	if requests[0] != 1 {
		t.Errorf("the listener had got %d requests when the browser opened, want the one call that checked it", requests[0])
	}
	if !strings.Contains(errOut, "Sign in on the page that opens in your browser") || !strings.Contains(errOut, pages[0]) {
		t.Errorf("ranz login says %q, want it to name the page that it opens", errOut)
	}
	_, auth := right.seen()
	for _, h := range auth {
		if h != "" {
			t.Errorf("a request of ranz login carried the header %q, want none: a login carries no token", h)
		}
	}
}

// TestRanzNodeLoginOpensNoBrowserBeforeItHasCheckedTheCertificate is the second criterion of AUD1-DT-19 (#506): ranz node
// login does the same, and asks the Node service for nothing but its key before the check.
func TestRanzNodeLoginOpensNoBrowserBeforeItHasCheckedTheCertificate(t *testing.T) {
	ctx := context.Background()
	right, rightFP := answerer(t)
	other, otherFP := answerer(t)
	dir := t.TempDir()
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(nodeKey.Public())
	browser := browseRecording(t, right)
	node := &fakeNode{answers: map[string]string{"key": `{"publicKey":"` + publicKey + `"}`}}
	// nodeLoginAt runs ranz node login, which signs in in the browser, toward server, and returns its exit code and its
	// standard error
	nodeLoginAt := func(server string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := nodeLogin(ctx, []string{"-server", server, "-controller-dir", dir}, &out, &errOut, node)
		return code, errOut.String()
	}

	// Another key: no browser, no request, both fingerprints, and the Node service is asked for its key and restarted
	// for nothing
	code, errOut := nodeLoginAt(other.srv.URL)
	if code != 1 {
		t.Errorf("ranz node login toward another key: exit code %d, want 1", code)
	}
	for _, want := range []string{"no browser was opened", "sent no token", other.srv.URL, otherFP, rightFP} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ranz node login toward another key says %q, want it to say %q", errOut, want)
		}
	}
	if pages, _ := browser.opened(); len(pages) != 0 {
		t.Errorf("ranz node login toward another key opened the browser at %q, want no browser", pages)
	}
	if _, auth := other.seen(); len(auth) != 0 {
		t.Errorf("the listener with another key got %d requests, want none: nothing may leave ranz for it", len(auth))
	}
	if len(node.commands) != 1 || node.commands[0] != "key" || node.restarts != 0 {
		t.Errorf("ranz node login toward another key asked the Node service %q and restarted it %d times, want its key and nothing else", node.commands, node.restarts)
	}

	// The right key: the call that checks the Controller comes first, and the browser opens at the page of the device
	nodeLoginAt(right.srv.URL)
	pages, requests := browser.opened()
	if len(pages) != 1 || !strings.HasPrefix(pages[0], right.srv.URL+login.AuthorizePath+"?") {
		t.Fatalf("ranz node login toward the key of the Controller opened %q, want its authorization page once", pages)
	}
	if u, err := url.Parse(pages[0]); err != nil || u.Query().Get("node_key") != publicKey {
		t.Errorf("the page %q does not ask for the enrolment of the key %s of the Node (%v)", pages[0], publicKey, err)
	}
	if requests[0] != 1 {
		t.Errorf("the listener had got %d requests when the browser opened, want the one call that checked it", requests[0])
	}
}
