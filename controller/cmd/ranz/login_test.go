package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// testPassword is the password of the user alice of startLoginController.
const testPassword = "correct horse battery staple"

// loginController is a controller of a first install with its logins in front of its API, as ranz
// controller serves them, for the commands of the logins.
type loginController struct {
	srv         *httptest.Server
	admin       *api.Client
	key         []byte // the Noise static key of the controller
	fingerprint string // the TLS fingerprint of srv
}

// startLoginController runs the controller, whose intent holds the user alice with the password
// testPassword and the API role operator. Its device codes may be polled every second.
func startLoginController(t *testing.T) *loginController {
	t.Helper()
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key, Defaults: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	tokens := rbac.New(st)
	var secret string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { secret = s; return nil }); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var fingerprint string
	logins := login.New(login.Config{Controller: c, Tokens: tokens, Interval: time.Second, Fingerprint: func() string {
		mu.Lock()
		defer mu.Unlock()
		return fingerprint
	}})
	srv := httptest.NewTLSServer(api.WithLogins(logins, api.Handler(c, tokens, api.Status{})))
	t.Cleanup(srv.Close)
	mu.Lock()
	fingerprint = nodecontroller.Fingerprint(srv.Certificate().RawSubjectPublicKeyInfo)
	mu.Unlock()
	lc := &loginController{srv: srv, admin: &api.Client{URL: srv.URL, Token: secret, HTTP: srv.Client()}, key: key.Public(), fingerprint: fingerprint}
	doc, err := intent.ParseDocument([]byte(`{"resources": [{"kind": "User", "name": "alice", "spec": {}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.admin.SetUserPassword(ctx, "alice", testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.admin.SetUserRole(ctx, "alice", rbac.Operator); err != nil {
		t.Fatal(err)
	}
	return lc
}

// flags returns the connection flags of the CLI for the controller, with its fingerprint pinned.
func (lc *loginController) flags(args ...string) []string {
	return append([]string{"-server", lc.srv.URL, "-tls-fingerprint", lc.fingerprint}, args...)
}

// browseAs replaces the browser of ranz with one that opens the authorization page that ranz opens and
// signs in on it as user with password, as a person does, until the test ends.
func (lc *loginController) browseAs(t *testing.T, user, password string) {
	t.Helper()
	before := openBrowser
	t.Cleanup(func() { openBrowser = before })
	openBrowser = func(page string) error {
		u, err := url.Parse(page)
		if err != nil {
			return err
		}
		browser := lc.srv.Client()
		resp, err := browser.Get(page)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("the authorization page: %s", resp.Status)
		}
		form := u.Query()
		form.Set("user", user)
		form.Set("password", password)
		// The browser follows the redirect to the loopback port of ranz
		resp, err = browser.PostForm(u.Scheme+"://"+u.Host+u.Path, form)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
}

// userCodeLine is the line of a device code login that tells the user where to type which code.
var userCodeLine = regexp.MustCompile(`open (\S+) and type the code ([A-Z]{4}-[A-Z]{4})`)

// typeCode waits until the command whose standard error is stderr shows the page and the user code of
// a device code login, and signs in there as user with password, as a person does on another device.
func (lc *loginController) typeCode(t *testing.T, stderr *syncBuffer, user, password string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if m := userCodeLine.FindStringSubmatch(stderr.String()); m != nil {
			resp, err := lc.srv.Client().PostForm(m[1], url.Values{"user_code": {m[2]}, "user": {user}, "password": {password}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("the sign-in on the device page: %s", resp.Status)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the command showed no user code: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ranz login with the password of a user prints its user token, or writes it to the file of -o and
// prints it without its secret; the token works for the API with the role of the user. A wrong
// password fails with the refusal of the controller.
func TestLoginWithThePasswordOfAUser(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	var out, errOut bytes.Buffer
	if code := runLogin(ctx, lc.flags("-user", "alice"), strings.NewReader(testPassword+"\r\n"), &out, &errOut); code != 0 {
		t.Fatalf("ranz login -user alice: exit code %d, stderr %q", code, errOut.String())
	}
	var tok rbac.UserToken
	if err := json.Unmarshal(out.Bytes(), &tok); err != nil || tok.Role != rbac.Operator || tok.User != "alice" || !strings.HasPrefix(tok.Secret, "ranz_") {
		t.Fatalf("ranz login printed %s (%v)", out.String(), err)
	}
	c := &api.Client{URL: lc.srv.URL, Token: tok.Secret, HTTP: lc.srv.Client()}
	if who, err := c.Whoami(ctx); err != nil || who.User != "alice" || who.Role != rbac.Operator {
		t.Errorf("whoami with the token of ranz login: %+v, %v", who, err)
	}

	file := filepath.Join(t.TempDir(), "alice.token")
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte(testPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := runLogin(ctx, lc.flags("-user", "alice", "-password-file", passwordFile, "-o", file), nil, &out, &errOut); code != 0 {
		t.Fatalf("ranz login -o: exit code %d, stderr %q", code, errOut.String())
	}
	b, err := os.ReadFile(file)
	if err != nil || !strings.HasPrefix(string(b), "ranz_") || strings.Contains(out.String(), strings.TrimSpace(string(b))) || !strings.Contains(out.String(), `"tokenFile"`) {
		t.Errorf("ranz login -o wrote %q and printed %s (%v)", b, out.String(), err)
	}

	errOut.Reset()
	if code := runLogin(ctx, lc.flags("-user", "alice"), strings.NewReader("not the password\n"), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "the user name or the password is wrong") {
		t.Errorf("ranz login with a wrong password: exit code %d, stderr %q", code, errOut.String())
	}
	for _, args := range [][]string{{"extra"}, {"-device", "-user", "alice"}, {"-nope"}} {
		if code := runLogin(ctx, lc.flags(args...), nil, &out, &errOut); code != 2 {
			t.Errorf("ranz login %q: exit code %d, want 2", args, code)
		}
	}
	if code := runLogin(ctx, []string{"-server", "https://127.0.0.1:1", "-tls-fingerprint", "abc"}, nil, &out, &errOut); code != 1 {
		t.Errorf("ranz login with a fingerprint that is no fingerprint: exit code %d, want 1", code)
	}
}

// ranz login in the browser: ranz opens the authorization page, the user signs in there, and ranz takes
// the user token with the code that the browser brings to its loopback port. With -device the user
// types the code that ranz shows on the device page instead.
func TestLoginInTheBrowserAndWithADeviceCode(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	lc.browseAs(t, "alice", testPassword)
	var out bytes.Buffer
	errOut := &syncBuffer{}
	if code := runLogin(ctx, lc.flags(), nil, &out, errOut); code != 0 {
		t.Fatalf("ranz login: exit code %d, stderr %q", code, errOut.String())
	}
	var tok rbac.UserToken
	if err := json.Unmarshal(out.Bytes(), &tok); err != nil || tok.Role != rbac.Operator || tok.Secret == "" || !strings.Contains(errOut.String(), login.AuthorizePath) {
		t.Fatalf("ranz login printed %s and %q (%v)", out.String(), errOut.String(), err)
	}

	out.Reset()
	errOut = &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- runLogin(ctx, lc.flags("-device"), nil, &out, errOut) }()
	lc.typeCode(t, errOut, "alice", testPassword)
	if code := <-done; code != 0 {
		t.Fatalf("ranz login -device: exit code %d, stderr %q", code, errOut.String())
	}
	if err := json.Unmarshal(out.Bytes(), &tok); err != nil || tok.User != "alice" || tok.Secret == "" {
		t.Errorf("ranz login -device printed %s (%v)", out.String(), err)
	}

	// A browser login whose user signs in with a wrong password brings no code: ranz waits, and its
	// context ends the wait
	lc.browseAs(t, "alice", "not the password")
	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if code := runLogin(wctx, lc.flags(), nil, &out, &syncBuffer{}); code != 1 {
		t.Errorf("ranz login whose user typed a wrong password: exit code %d, want 1", code)
	}
}

// ranz node login takes the static key of the Node, enrols it through the login of its user, sets the
// Controller settings of the Node to the address of -server and the keys of the controller, and
// restarts the service; the Node resource is a device of the user.
func TestNodeLoginEnrolsTheNode(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(lc.srv.URL, "https://")
	set := "controller set " + address + " " + base64.StdEncoding.EncodeToString(lc.key) + " " + lc.fingerprint
	settings := `{"controller":{"address":"` + address + `","publicKey":"` + base64.StdEncoding.EncodeToString(lc.key) + `","tlsFingerprint":"` + lc.fingerprint + `"},"connected":false,"generation":0}`
	f := &fakeNode{answers: map[string]string{"key": `{"publicKey":"` + base64.StdEncoding.EncodeToString(nodeKey.Public()) + `"}`, set: settings}}
	lc.browseAs(t, "alice", testPassword)
	var out bytes.Buffer
	errOut := &syncBuffer{}
	if code := nodeLogin(ctx, lc.flags("-name", "alice-pc"), &out, errOut, f); code != 0 {
		t.Fatalf("ranz node login: exit code %d, stderr %q", code, errOut.String())
	}
	if len(f.commands) != 2 || f.commands[0] != "key" || f.commands[1] != set || f.restarts != 1 {
		t.Fatalf("ranz node login sent the Node %q and restarted it %d times, want key, %q and a restart", f.commands, f.restarts, set)
	}
	var a nodeLoginAnswer
	if err := json.Unmarshal(out.Bytes(), &a); err != nil || a.Node != "alice-pc" || a.User != "alice" || a.Controller == nil || a.Controller.Address != address {
		t.Fatalf("ranz node login printed %s (%v)", out.String(), err)
	}
	users, err := lc.admin.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || len(users[0].Devices) != 1 || users[0].Devices[0].Name != "alice-pc" {
		t.Errorf("the devices of alice are %+v, want the Node alice-pc", users)
	}

	// With -device, a Node that is enrolled already gets its enrolment again
	f = &fakeNode{answers: f.answers}
	out.Reset()
	errOut = &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- nodeLogin(ctx, lc.flags("-device"), &out, errOut, f) }()
	lc.typeCode(t, errOut, "alice", testPassword)
	if code := <-done; code != 0 || !strings.Contains(out.String(), `"node": "alice-pc"`) || f.restarts != 1 {
		t.Errorf("ranz node login -device: exit code %d, %d restarts, stdout %s, stderr %q", code, f.restarts, out.String(), errOut.String())
	}

	// A Node that the service cannot be asked of, and a server that is not https
	if code := nodeLogin(ctx, lc.flags(), &out, errOut, &fakeNode{err: fmt.Errorf("needs administrator rights")}); code != 1 {
		t.Errorf("ranz node login without the Node service: exit code %d, want 1", code)
	}
	if code := nodeLogin(ctx, []string{"-server", "http://127.0.0.1"}, &out, errOut, f); code != 2 {
		t.Errorf("ranz node login -server http: exit code %d, want 2", code)
	}
}

// The address of the control stream is the host and the port of -server, 443 when it names none.
func TestControlAddress(t *testing.T) {
	for server, want := range map[string]string{"https://controller.example": "controller.example:443", "https://10.0.0.1:5555/": "10.0.0.1:5555",
		"https://[2001:db8::1]": "[2001:db8::1]:443"} {
		if got, err := controlAddress(server); err != nil || got != want {
			t.Errorf("controlAddress(%q) = %q, %v, want %q", server, got, err, want)
		}
	}
	for _, server := range []string{"http://controller.example", "controller.example", "https://"} {
		if got, err := controlAddress(server); err == nil {
			t.Errorf("controlAddress(%q) = %q, want an error", server, got)
		}
	}
}

// ranz user role gives a user an API role, lists the roles and takes one away, with the answers of the
// API; it needs the role admin.
func TestUserRoleCommands(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	var out bytes.Buffer
	if err := do(ctx, lc.admin, []string{"user", "role", "set", "alice", "admin"}, &out); err != nil || !strings.Contains(out.String(), `"role": "admin"`) {
		t.Errorf("ranz user role set: %v, %s", err, out.String())
	}
	out.Reset()
	if err := do(ctx, lc.admin, []string{"user", "role", "list"}, &out); err != nil || !strings.Contains(out.String(), `"user": "alice"`) {
		t.Errorf("ranz user role list: %v, %s", err, out.String())
	}
	out.Reset()
	if err := do(ctx, lc.admin, []string{"user", "role", "clear", "alice"}, &out); err != nil || !strings.Contains(out.String(), `"role": "admin"`) {
		t.Errorf("ranz user role clear: %v, %s", err, out.String())
	}
	if err := do(ctx, lc.admin, []string{"user", "role", "clear", "alice"}, &out); httpStatusOf(err) != http.StatusNotFound {
		t.Errorf("ranz user role clear of a user that holds none: %v, want 404", err)
	}
	if err := do(ctx, lc.admin, []string{"user", "role", "set", "alice", "root"}, &out); httpStatusOf(err) != http.StatusBadRequest {
		t.Errorf("ranz user role set with a role that does not exist: %v, want 400", err)
	}
	if err := do(ctx, lc.admin, []string{"user", "role", "set", "alice"}, &out); err != errUsage {
		t.Errorf("ranz user role set without a role: %v, want the usage", err)
	}
	// ranz token role changes the role of an API token in place; the last admin token keeps admin
	if err := do(ctx, lc.admin, []string{"token", "role", rbac.FirstAdmin, "viewer"}, &out); httpStatusOf(err) != http.StatusConflict {
		t.Errorf("ranz token role of the last admin token: %v, want 409", err)
	}
	if _, err := lc.admin.CreateToken(ctx, "ops", rbac.Operator); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := do(ctx, lc.admin, []string{"token", "role", "ops", "viewer"}, &out); err != nil || !strings.Contains(out.String(), `"role": "viewer"`) {
		t.Errorf("ranz token role ops viewer: %v, %s", err, out.String())
	}
	viewer := &api.Client{URL: lc.srv.URL, Token: createUserToken(t, lc, "alice"), HTTP: lc.srv.Client()}
	if err := do(ctx, viewer, []string{"user", "role", "list"}, &out); httpStatusOf(err) != http.StatusUnauthorized {
		t.Errorf("ranz user role list with the token of a user whose role went: %v, want 401", err)
	}
}

// createUserToken logs user in with the password of startLoginController, while it holds a role, and
// takes the role away again; it returns the user token, which authenticates nothing after that.
func createUserToken(t *testing.T, lc *loginController, user string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := lc.admin.SetUserRole(ctx, user, rbac.Viewer); err != nil {
		t.Fatal(err)
	}
	in, err := (&login.Client{URL: lc.srv.URL, HTTP: lc.srv.Client()}).SignIn(ctx, user, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.admin.DeleteUserRole(ctx, user); err != nil {
		t.Fatal(err)
	}
	return in.Secret
}

// httpStatusOf returns the HTTP status of an error of the API, 0 for another error.
func httpStatusOf(err error) int {
	if e, ok := err.(*api.Error); ok {
		return e.Status
	}
	return 0
}
