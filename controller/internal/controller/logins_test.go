// Controller conformance for the logins of users (SDN-32 #226), with the harness and the node simulator
// of conformance_test.go: a node enrols after a browser login and after a device code login and joins
// with the keys that the login gave it; a wrong password is refused and recorded in the audit log, and
// the throttle refuses the next ones without a check; a User that an admin gave an API role gets a user
// token that the Guard takes with that role, until the role changes, goes or the User logs out.
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// alicePassword is the password of the User alice of newLoginEnv.
const alicePassword = "correct horse battery staple"

// loginEnv is a controller with the logins in front of its API, as ranz controller serves them, a
// client of the logins, and a browser.
type loginEnv struct {
	h *harness
	// srv serves the API of h with the logins in front of its Guard and the audit log on it
	srv    *httptest.Server
	client *login.Client
	// browser sends what a browser sends, and follows no redirect, so that a test sees where it goes
	browser *http.Client
	// fingerprint is the TLS fingerprint of the port of h, where the nodes open their control streams
	fingerprint string
}

// newLoginEnv returns a controller of a first install (VRF default, ADR-0034) whose intent holds the User
// alice, with a password and at most 2 devices, and its logins. The device codes may be polled every
// 100 ms.
func newLoginEnv(t *testing.T) *loginEnv {
	return newLoginEnvWith(t, nil)
}

// newLoginEnvWith is newLoginEnv for a test that sets something of the harness before the controller starts,
// such as the sealing key that the PresharedKeys of the Devices need (portaldevice_test.go): set, when it is
// not nil, runs on the harness before its first start.
func newLoginEnvWith(t *testing.T, set func(*harness)) *loginEnv {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), defaults: true}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if set != nil {
		set(h)
	}
	h.start()
	t.Cleanup(h.stop)
	ctx := context.Background()
	st, err := h.api.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tokens := rbac.New(h.st)
	logins := login.New(login.Config{Controller: h.c, Tokens: tokens, Fingerprint: func() string { return st.TLSFingerprint }, Interval: 100 * time.Millisecond})
	routes := api.AuditCalls(h.c, api.Routes(h.c, tokens, api.Status{}))
	srv := httptest.NewTLSServer(api.WithLogins(logins, api.AuditRefusals(audit.NewLog(h.st, nil), api.Guard(tokens, routes))))
	t.Cleanup(srv.Close)
	browser := *srv.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.applyDoc(usersDoc(t, `{"kind": "User", "name": "alice", "spec": {"displayName": "Alice", "maxDevices": 2}}`))
	if _, err := h.api.SetUserPassword(ctx, "alice", alicePassword); err != nil {
		t.Fatal(err)
	}
	return &loginEnv{h: h, srv: srv, client: &login.Client{URL: srv.URL, HTTP: srv.Client()}, browser: &browser, fingerprint: st.TLSFingerprint}
}

// open sends the request of a browser to target and returns the status and the body of the answer,
// and where it goes next.
func (e *loginEnv) open(t *testing.T, method, target string, form url.Values) (int, string, string) {
	t.Helper()
	var resp *http.Response
	var err error
	if method == http.MethodPost {
		resp, err = e.browser.PostForm(target, form)
	} else {
		resp, err = e.browser.Get(target)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

// caller returns a client of the API of e, with the audit log on it, that calls with the token secret.
func (e *loginEnv) caller(secret string) *api.Client {
	return &api.Client{URL: e.srv.URL, Token: secret, HTTP: e.srv.Client()}
}

// inPage returns the static key key as a page of the logins shows it: base64, with the plus signs that
// html/template escapes.
func inPage(key []byte) string {
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString(key), "+", "&#43;")
}

// join runs the simulated node with the static key key and the keys of the controller that the
// enrolment res gave it, as a Node takes them from ranz node login, and waits until the controller has
// it connected at its first Generation.
func (e *loginEnv) join(t *testing.T, key keys.Static, res login.Result) *sim {
	t.Helper()
	if res.Controller == nil {
		t.Fatalf("the enrolment of %s gave no keys of the controller: %+v", res.Node, res)
	}
	ck, err := base64.StdEncoding.DecodeString(res.Controller.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s := e.h.newSim(res.Node, key)
	s.ControllerKey, s.TLSFingerprint = ck, res.Controller.TLSFingerprint
	s.start(e.h)
	s.update(t)
	e.h.waitNode(res.Node, 1, true)
	e.h.checkState(s)
	return s
}

// oauthCode returns the error code of a refusal of the token endpoint or of a page of the logins.
func oauthCode(err error) string {
	var e *login.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// nodeSpec returns the spec of the Node resource name, as the intent completed it.
func (e *loginEnv) nodeSpec(t *testing.T, name string) intent.Node {
	t.Helper()
	rs, err := e.h.api.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := in.Nodes[name]
	if !ok {
		t.Fatalf("the intent holds no Node %s", name)
	}
	return n
}

// TestNodeEnrolsAfterABrowserLogin is the first criterion of SDN-32 (#226), for the browser login: the
// client of a node listens on a loopback port and opens the authorization page with the static key of
// the node and a code challenge; the user signs in there as alice; the browser brings the code to the
// loopback port; the client exchanges it with its verifier and gets the enrolment, with the keys of the
// controller. The node then opens its control stream with those keys and joins: the Node resource is a
// device of alice, in VRF default, and the login and the revision that made the Node are alice's in the
// audit log. A code is exchanged once.
func TestNodeEnrolsAfterABrowserLogin(t *testing.T) {
	e := newLoginEnv(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)
	key := fixedKey(193)
	verifier, challenge := login.NewVerifier()
	cb, err := login.ListenCallback("state-of-the-client")
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	req := login.Request{RedirectURI: cb.URL(), State: "state-of-the-client", Challenge: challenge, Device: &login.Device{Key: key.Public(), Name: "alice-laptop"}}

	// The browser opens the authorization page: it names the device and holds the form
	status, body, _ := e.open(t, http.MethodGet, e.client.AuthorizeURL(req), nil)
	keyText := base64.StdEncoding.EncodeToString(key.Public())
	if status != http.StatusOK || !strings.Contains(body, inPage(key.Public())) || !strings.Contains(body, "alice-laptop") || !strings.Contains(body, `name="password"`) {
		t.Fatalf("the authorization page: %d\n%s", status, body)
	}
	// The user signs in on it, and the browser goes to the loopback port with the code
	form := req.Values()
	form.Set("user", "alice")
	form.Set("password", alicePassword)
	status, body, location := e.open(t, http.MethodPost, e.srv.URL+login.AuthorizePath, form)
	if status != http.StatusSeeOther || !strings.HasPrefix(location, cb.URL()+"?") {
		t.Fatalf("the sign-in on the authorization page: %d to %q\n%s", status, location, body)
	}
	resp, err := http.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	code, err := cb.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The client exchanges the code for the enrolment, which carries the keys of the controller
	res, err := e.client.Exchange(ctx, code, cb.URL(), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if res.Node != "alice-laptop" || res.User != "alice" || res.Revision == 0 || res.AccessToken != "" ||
		res.Controller.PublicKey != base64.StdEncoding.EncodeToString(e.h.key.Public()) || res.Controller.TLSFingerprint != e.fingerprint {
		t.Fatalf("the exchange gave %+v (%+v), want the Node alice-laptop of alice with the keys of the controller", res, res.Controller)
	}
	// The node receives the result: it opens its control stream with the keys of the login and joins
	e.join(t, key, res)
	if n := e.nodeSpec(t, "alice-laptop"); n.Owner != "alice" || n.PublicKey != keyText || len(n.VRFs) != 1 || n.VRFs[0] != intent.DefaultVRF {
		t.Errorf("the Node resource of the device is %+v, want a device of alice in VRF default", n)
	}

	// The audit log holds the login of alice and the revision that her login made
	recs := e.h.waitAudit(e.h.api, "the login and the revision of alice", func(rs []audit.Record) bool {
		var logged, revised bool
		for _, r := range rs {
			logged = logged || r.Kind == audit.Login && r.Actor == audit.ActorUser("alice")
			revised = revised || r.Kind == audit.IntentChange && r.Revision == res.Revision
		}
		return logged && revised
	})
	for _, r := range recs {
		switch {
		case r.Kind == audit.Login && r.Actor == audit.ActorUser("alice"):
			checkAuditRecord(t, r, since, audit.ActorUser("alice"), "127.0.0.1", audit.Success, "", 0)
		case r.Kind == audit.IntentChange && r.Revision == res.Revision:
			checkAuditRecord(t, r, since, audit.ActorUser("alice"), "127.0.0.1", audit.Success, intent.OpApply, res.Revision)
		}
	}

	// A code is exchanged once
	if _, err := e.client.Exchange(ctx, code, cb.URL(), verifier); oauthCode(err) != "invalid_grant" {
		t.Errorf("a second exchange of the code: %v, want invalid_grant", err)
	}
}

// TestNodeEnrolsAfterADeviceCodeLogin is the first criterion of SDN-32 (#226), for the device code
// login: the node asks for a device code with its static key and polls; alice opens the device page
// with the code that the node shows, sees what she lets in, and signs in; the next poll gives the node
// its enrolment, under a name that the controller draws, and the node joins with it. A third device of
// alice is one more than her maximum: the login gives it nothing, as `ranz apply` would refuse it.
func TestNodeEnrolsAfterADeviceCodeLogin(t *testing.T) {
	e := newLoginEnv(t)
	ctx := context.Background()
	key := fixedKey(225)
	a, err := e.client.StartDevice(ctx, &login.Device{Key: key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := login.NormalizeUserCode(a.UserCode); !ok || a.VerificationURI != e.srv.URL+login.DevicePath ||
		a.VerificationURIComplete != a.VerificationURI+"?user_code="+url.QueryEscape(a.UserCode) || a.ExpiresIn != 600 || a.Interval != 1 {
		t.Fatalf("the device authorization is %+v", a)
	}
	// Nobody signed in yet
	if _, err := e.client.Exchange(ctx, "no code", "http://127.0.0.1:1/", "v"); oauthCode(err) != "invalid_grant" {
		t.Errorf("the exchange of a code that does not exist: %v, want invalid_grant", err)
	}
	polled := make(chan error, 1)
	var res login.Result
	pctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	go func() {
		var err error
		res, err = e.client.PollDevice(pctx, a)
		polled <- err
	}()

	// alice opens the page that the node shows, with the code: it names the key of the node
	status, body, _ := e.open(t, http.MethodGet, a.VerificationURIComplete, nil)
	if status != http.StatusOK || !strings.Contains(body, inPage(key.Public())) || !strings.Contains(body, a.UserCode) {
		t.Fatalf("the device page with the code: %d\n%s", status, body)
	}
	// A code that no device waits with is refused
	status, body, _ = e.open(t, http.MethodPost, e.srv.URL+login.DevicePath, url.Values{"user_code": {"BCDF-GHJK"}, "user": {"alice"}, "password": {alicePassword}})
	if status != http.StatusNotFound || !strings.Contains(body, "No device waits with this code") {
		t.Errorf("a user code that no device waits with: %d\n%s", status, body)
	}
	// alice signs in with the code, typed in small letters
	status, body, _ = e.open(t, http.MethodPost, e.srv.URL+login.DevicePath, url.Values{"user_code": {strings.ToLower(a.UserCode)}, "user": {"alice"}, "password": {alicePassword}})
	if status != http.StatusOK || !strings.Contains(body, "alice-1") {
		t.Fatalf("the sign-in on the device page: %d\n%s", status, body)
	}
	if err := <-polled; err != nil {
		t.Fatal(err)
	}
	if res.Node != "alice-1" || res.User != "alice" || res.Controller == nil || res.Controller.TLSFingerprint != e.fingerprint {
		t.Fatalf("the poll gave %+v, want the Node alice-1 of alice with the keys of the controller", res)
	}
	// The node receives the result and joins
	e.join(t, key, res)
	// The device code is answered once
	if _, err := e.client.PollDevice(ctx, a); oauthCode(err) != "invalid_grant" {
		t.Errorf("a poll of a device code that was answered: %v, want invalid_grant", err)
	}
	// A device that alice holds already is its enrolment again, with no new revision
	again, err := e.client.StartDevice(ctx, &login.Device{Key: key.Public(), Name: "another-name"})
	if err != nil {
		t.Fatal(err)
	}
	if status, body, _ := e.open(t, http.MethodPost, e.srv.URL+login.DevicePath, url.Values{"user_code": {again.UserCode}, "user": {"alice"}, "password": {alicePassword}}); status != http.StatusOK {
		t.Fatalf("the sign-in for a device that alice holds: %d\n%s", status, body)
	}
	if r, err := e.client.PollDevice(ctx, again); err != nil || r.Node != "alice-1" || r.Revision != res.Revision {
		t.Errorf("the enrolment of a device that alice holds: %+v (%v), want Node alice-1 at revision %d", r, err, res.Revision)
	}

	// The second device of alice is her maximum; a third gets nothing and changes nothing
	if _, err := e.h.api.Apply(ctx, usersDoc(t, userNode("alice-phone", "alice", 1))); err != nil {
		t.Fatal(err)
	}
	before := e.h.resources()
	third, err := e.client.StartDevice(ctx, &login.Device{Key: fixedKey(17).Public()})
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.open(t, http.MethodPost, e.srv.URL+login.DevicePath, url.Values{"user_code": {third.UserCode}, "user": {"alice"}, "password": {alicePassword}})
	if status != http.StatusForbidden || !strings.Contains(body, "the maximum is 2") {
		t.Errorf("the sign-in for a third device of alice: %d\n%s", status, body)
	}
	if _, err := e.client.PollDevice(ctx, third); oauthCode(err) != "access_denied" {
		t.Errorf("the poll of the third device: %v, want access_denied", err)
	}
	if after := e.h.resources(); after != before {
		t.Errorf("the refused device changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
}

// TestAWrongPasswordIsRefusedAndAudited is the second criterion of SDN-32 (#226): a login with a wrong
// password is refused, by each of the three ways in, and the refusal is in the audit log, with the name
// that the login gave as its actor and the address it came from. The browser and the device get nothing
// of it, and the intent does not change. After five wrong passwords in a row the throttle refuses the
// login at once, also with the right password, and says when to try again.
func TestAWrongPasswordIsRefusedAndAudited(t *testing.T) {
	for _, way := range []string{"password", "browser", "device"} {
		t.Run(way, func(t *testing.T) {
			e := newLoginEnv(t)
			ctx := context.Background()
			since := time.Now().Add(-time.Second)
			before := e.h.resources()
			switch way {
			case "password":
				_, err := e.client.SignIn(ctx, "alice", "not the password of alice")
				var le *login.Error
				if !errors.As(err, &le) || le.Status != http.StatusUnauthorized || !strings.Contains(le.Code, "the user name or the password is wrong") {
					t.Fatalf("a password login with a wrong password: %v, want 401", err)
				}
			case "browser":
				_, challenge := login.NewVerifier()
				req := login.Request{RedirectURI: "http://127.0.0.1:49152/callback", Challenge: challenge, Device: &login.Device{Key: fixedKey(193).Public()}}
				form := req.Values()
				form.Set("user", "alice")
				form.Set("password", "not the password of alice")
				status, body, location := e.open(t, http.MethodPost, e.srv.URL+login.AuthorizePath, form)
				if status != http.StatusUnauthorized || location != "" || !strings.Contains(body, "the user name or the password is wrong") || !strings.Contains(body, `name="password"`) {
					t.Fatalf("a browser login with a wrong password: %d to %q\n%s", status, location, body)
				}
			case "device":
				a, err := e.client.StartDevice(ctx, &login.Device{Key: fixedKey(193).Public()})
				if err != nil {
					t.Fatal(err)
				}
				status, body, _ := e.open(t, http.MethodPost, e.srv.URL+login.DevicePath, url.Values{"user_code": {a.UserCode}, "user": {"alice"}, "password": {"not the password of alice"}})
				if status != http.StatusUnauthorized || !strings.Contains(body, "the user name or the password is wrong") {
					t.Fatalf("a device code login with a wrong password: %d\n%s", status, body)
				}
				pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				defer cancel()
				if _, err := e.client.PollDevice(pctx, a); !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("the device polled after a wrong password and got %v, want nothing until its context ended", err)
				}
			}
			recs := e.h.waitAudit(e.h.api, "the refused login of alice", func(rs []audit.Record) bool {
				return len(auditOfKind(rs, audit.AuthFailed)) > 0
			})
			failed := auditOfKind(recs, audit.AuthFailed)
			checkAuditRecord(t, failed[0], since, audit.ActorUser("alice"), "127.0.0.1", audit.Failure, "", 0)
			if !strings.Contains(failed[0].Message, "the user name or the password is wrong") {
				t.Errorf("the record of the refused login says %q", failed[0].Message)
			}
			for _, r := range auditOfKind(recs, audit.Login) {
				t.Errorf("a refused login made the login record %+v", r)
			}
			if after := e.h.resources(); after != before {
				t.Errorf("a refused login changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
			}
		})
	}

	// The throttle: after five wrong passwords in a row the right one is refused too, without a check
	e := newLoginEnv(t)
	ctx := context.Background()
	for range 4 {
		if _, err := e.client.SignIn(ctx, "alice", "not the password of alice"); err == nil {
			t.Fatal("a wrong password was taken")
		}
	}
	// A name that no User has is refused in the same words, and counts for the address as well
	if _, err := e.client.SignIn(ctx, "nobody", "still not a password"); !strings.Contains(errText(err), "the user name or the password is wrong") {
		t.Fatalf("the fifth wrong password: %v", err)
	}
	_, err := e.client.SignIn(ctx, "alice", alicePassword)
	var le *login.Error
	if !errors.As(err, &le) || le.Status != http.StatusTooManyRequests || !strings.Contains(le.Code, "too many failed logins") {
		t.Fatalf("the right password after five wrong ones: %v, want 429 Too Many Requests", err)
	}
	if _, err := e.client.SignIn(ctx, "nobody", alicePassword); !strings.Contains(errText(err), "too many failed logins") {
		t.Errorf("a login of another name from the same address: %v, want the throttle of the address", err)
	}
}

// TestATokenChangesItsRoleInPlace: the decision of 2026-10-22 on SDN-32 (#226) gives the API tokens of
// SDN-14 a change of role in place with the logins. An admin gives a token another role; the token
// keeps its secret, and its next call has the new role. Only an admin changes a role, and the last admin
// token keeps the role admin.
func TestATokenChangesItsRoleInPlace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("apply1.json")
	ops := h.client(h.token("ops", rbac.Operator))
	if _, err := ops.Apply(ctx, labVRF); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SetTokenRole(ctx, "ops", rbac.Admin); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator gives itself the role admin: %v, want 403", err)
	}
	if tok, err := h.api.SetTokenRole(ctx, "ops", rbac.Viewer); err != nil || tok != (rbac.Token{Name: "ops", Role: rbac.Viewer}) {
		t.Fatalf("an admin makes ops a viewer: %+v, %v", tok, err)
	}
	if _, err := ops.Delete(ctx, intent.KindVRF, "lab"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the token ops, a viewer now, deletes: %v, want 403", err)
	}
	if who, err := ops.Whoami(ctx); err != nil || who.Role != rbac.Viewer {
		t.Errorf("whoami of ops: %+v, %v", who, err)
	}
	if _, err := h.api.SetTokenRole(ctx, rbac.FirstAdmin, rbac.Operator); httpStatus(err) != http.StatusConflict {
		t.Errorf("the last admin token loses the role admin: %v, want 409", err)
	}
	if _, err := h.api.SetTokenRole(ctx, "nobody", rbac.Viewer); httpStatus(err) != http.StatusNotFound {
		t.Errorf("the role of a token that does not exist: %v, want 404", err)
	}
	if _, err := h.api.SetTokenRole(ctx, "ops", "root"); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a role that does not exist: %v, want 400", err)
	}
}

// errText returns the text of err, empty for none.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestAUserWithARoleLogsInToTheAPI: a User holds no API role until an admin gives it one, and its login
// gives it no user token before. With a role, a password login and a browser login each give a user
// token that the Guard takes with that role, and the calls of the token are alice's in the audit log.
// The role changes in place; taking it away, a ban of the User and a logout end the tokens at once.
// Only an admin gives a role, and only an admin sets the password of a User that holds one.
func TestAUserWithARoleLogsInToTheAPI(t *testing.T) {
	e := newLoginEnv(t)
	ctx := context.Background()
	if _, err := e.client.SignIn(ctx, "alice", alicePassword); !strings.Contains(errText(err), "holds no API role") {
		t.Fatalf("the login of alice, who holds no API role: %v, want a refusal that says so", err)
	}
	operator := e.h.client(e.h.token("ops", rbac.Operator))
	if _, err := operator.SetUserRole(ctx, "alice", rbac.Operator); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator gives alice a role: %v, want 403", err)
	}
	if _, err := e.h.api.SetUserRole(ctx, "nobody", rbac.Viewer); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a role for a User that the intent does not hold: %v, want 404", err)
	}
	if ur, err := e.h.api.SetUserRole(ctx, "alice", rbac.Operator); err != nil || ur != (rbac.UserRole{User: "alice", Role: rbac.Operator}) {
		t.Fatalf("an admin gives alice the role operator: %+v, %v", ur, err)
	}
	if rs, err := e.h.api.UserRoles(ctx); err != nil || len(rs) != 1 || rs[0].User != "alice" {
		t.Errorf("the API roles of users are %+v (%v), want alice's", rs, err)
	}
	if _, err := operator.UserRoles(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator lists the roles of users: %v, want 403", err)
	}

	in, err := e.client.SignIn(ctx, "alice", alicePassword)
	if err != nil {
		t.Fatal(err)
	}
	if in.Role != rbac.Operator || in.User != "alice" || !strings.HasPrefix(in.Secret, "ranz_") || in.Expires.Before(time.Now().Add(11*time.Hour)) || in.Expires.After(time.Now().Add(13*time.Hour)) {
		t.Fatalf("the user token of alice is %+v", in)
	}
	alice := e.caller(in.Secret)
	if who, err := alice.Whoami(ctx); err != nil || who != (rbac.Token{Name: "user:alice", Role: rbac.Operator, User: "alice"}) {
		t.Errorf("whoami with the user token: %+v, %v", who, err)
	}
	res, err := alice.Apply(ctx, labVRF)
	if err != nil {
		t.Fatalf("an operator's apply with the user token: %v", err)
	}
	if _, err := alice.Tokens(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the user token of an operator lists the API tokens: %v, want 403", err)
	}
	e.h.waitAudit(e.h.api, "the apply of alice", func(rs []audit.Record) bool {
		for _, r := range auditOfKind(rs, audit.IntentChange) {
			if r.Revision == res.Revision {
				return r.Actor == audit.ActorUser("alice")
			}
		}
		return false
	})

	// Only an admin sets the password of a User that holds a role
	if _, err := operator.SetUserPassword(ctx, "alice", "a password of the operator"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator sets the password of alice, who holds a role: %v, want 403", err)
	}
	if _, err := e.h.api.SetUserPassword(ctx, "alice", alicePassword); err != nil {
		t.Errorf("an admin sets the password of alice: %v", err)
	}

	// The role changes in place, and taking it away ends the token at once
	if _, err := e.h.api.SetUserRole(ctx, "alice", rbac.Viewer); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Delete(ctx, intent.KindVRF, "lab"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the user token of alice, now a viewer, deletes: %v, want 403", err)
	}
	if ur, err := e.h.api.DeleteUserRole(ctx, "alice"); err != nil || ur.Role != rbac.Viewer {
		t.Fatalf("taking the role of alice away: %+v, %v", ur, err)
	}
	if _, err := alice.Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the user token of alice after her role went: %v, want 401", err)
	}
	if _, err := e.h.api.DeleteUserRole(ctx, "alice"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("taking away the role of a User that holds none: %v, want 404", err)
	}

	// A browser login gives a user token too, through the exchange of its code
	if _, err := e.h.api.SetUserRole(ctx, "alice", rbac.Admin); err != nil {
		t.Fatal(err)
	}
	verifier, challenge := login.NewVerifier()
	req := login.Request{RedirectURI: "http://127.0.0.1:49152/callback", State: "s", Challenge: challenge}
	form := req.Values()
	form.Set("user", "alice")
	form.Set("password", alicePassword)
	status, body, location := e.open(t, http.MethodPost, e.srv.URL+login.AuthorizePath, form)
	u, err := url.Parse(location)
	if status != http.StatusSeeOther || err != nil || u.Query().Get("state") != "s" || u.Query().Get("code") == "" {
		t.Fatalf("the browser login of alice for a user token: %d to %q\n%s", status, location, body)
	}
	tok, err := e.client.Exchange(ctx, u.Query().Get("code"), req.RedirectURI, verifier)
	if err != nil || tok.TokenType != "Bearer" || tok.Role != rbac.Admin || tok.ExpiresIn <= 0 || tok.Node != "" {
		t.Fatalf("the exchange for a user token: %+v, %v", tok, err)
	}
	admin := e.caller(tok.AccessToken)
	if _, err := admin.Tokens(ctx); err != nil {
		t.Errorf("the user token of an admin lists the API tokens: %v", err)
	}
	// A wrong verifier gets nothing for a code
	status, _, location = e.open(t, http.MethodPost, e.srv.URL+login.AuthorizePath, form)
	if u, err = url.Parse(location); status != http.StatusSeeOther || err != nil {
		t.Fatal(status, location)
	}
	if _, err := e.client.Exchange(ctx, u.Query().Get("code"), req.RedirectURI, strings.Repeat("v", 43)); oauthCode(err) != "invalid_grant" {
		t.Errorf("the exchange with a wrong verifier: %v, want invalid_grant", err)
	}

	// A logout ends the token; a ban of the User ends the others
	if out, err := e.client.SignOut(ctx, tok.AccessToken); err != nil || out.User != "alice" {
		t.Errorf("the logout of alice: %+v, %v", out, err)
	}
	if _, err := admin.Tokens(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the user token after the logout: %v, want 401", err)
	}
	in, err = e.client.SignIn(ctx, "alice", alicePassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.h.api.Ban(ctx, "alice", "left the company"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(in.Secret).Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the user token of alice after her ban: %v, want 401", err)
	}
	if _, err := e.client.SignIn(ctx, "alice", alicePassword); !strings.Contains(errText(err), "banned") {
		t.Errorf("the login of alice after her ban: %v, want a refusal that says she is banned", err)
	}
}
