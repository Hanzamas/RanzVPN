package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// fakeController is the controller of the tests: the Users and their passwords, the Nodes it enrolled,
// and the audit records it was given.
type fakeController struct {
	mu       sync.Mutex
	users    map[string]string // the password of each User
	expires  map[string]time.Time
	checks   int // the passwords it checked
	enrolled map[string][]byte
	refuse   error // the error of the next enrolment
	records  []audit.Record
}

func newFakeController() *fakeController {
	return &fakeController{users: map[string]string{"alice": "the password of alice", "bob": "the password of bob"}, expires: map[string]time.Time{},
		enrolled: map[string][]byte{}}
}

func (f *fakeController) AuthenticateUser(_ context.Context, l controller.Login) (controller.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if p, ok := f.users[l.User]; !ok || p != l.Password {
		return controller.Account{}, controller.ErrBadCredentials
	}
	return controller.Account{Name: l.User, User: intent.User{Expires: f.expires[l.User]}}, nil
}

func (f *fakeController) EnrolDevice(_ context.Context, user, name string, key []byte) (controller.Enrolment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.refuse; err != nil {
		f.refuse = nil
		return controller.Enrolment{}, err
	}
	if name == "" {
		name = fmt.Sprintf("%s-%d", user, len(f.enrolled)+1)
	}
	f.enrolled[name] = key
	return controller.Enrolment{Node: name, User: user, Revision: uint64(len(f.enrolled))}, nil
}

func (f *fakeController) RecordAudit(_ context.Context, r audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, r)
	return nil
}

func (f *fakeController) PublicKey() []byte { return make([]byte, 32) }

// change runs fn on f, as the server would see it between two calls.
func (f *fakeController) change(fn func(f *fakeController)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// checked returns the number of passwords that f checked.
func (f *fakeController) checked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

// recorded returns the audit records of the kind kind.
func (f *fakeController) recorded(kind string) []audit.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Record
	for _, r := range f.records {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// fakeTokens are the API roles and the user tokens of the tests.
type fakeTokens struct {
	mu     sync.Mutex
	roles  map[string]rbac.Role
	issued map[string]rbac.UserToken
}

func (f *fakeTokens) UserRole(_ context.Context, name string) (rbac.Role, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roles[name]
	return r, ok, nil
}

func (f *fakeTokens) IssueUserToken(_ context.Context, name string, expires time.Time) (rbac.UserToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roles[name]
	if !ok {
		return rbac.UserToken{}, fmt.Errorf("%w: user %q", rbac.ErrNoRole, name)
	}
	tok := rbac.UserToken{Token: rbac.Token{Name: "user:" + name, Role: r, User: name}, Secret: fmt.Sprintf("ranz_u_%d", len(f.issued)), Expires: expires}
	f.issued[tok.Secret] = tok
	return tok, nil
}

func (f *fakeTokens) RevokeUserToken(_ context.Context, secret string) (rbac.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok, ok := f.issued[secret]
	if !ok {
		return rbac.Token{}, rbac.ErrUnauthenticated
	}
	delete(f.issued, secret)
	return tok.Token, nil
}

// testEnv is a Server of fakes behind a test server, with its clock.
type testEnv struct {
	s       *Server
	c       *fakeController
	tokens  *fakeTokens
	srv     *httptest.Server
	client  *Client
	browser *http.Client

	mu  sync.Mutex
	now time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	e := &testEnv{c: newFakeController(), tokens: &fakeTokens{roles: map[string]rbac.Role{"alice": rbac.Admin}, issued: map[string]rbac.UserToken{}},
		now: time.Date(2026, time.October, 28, 9, 0, 0, 0, time.UTC)}
	e.s = New(Config{Controller: e.c, Tokens: e.tokens, Fingerprint: func() string { return strings.Repeat("ab", 32) }})
	e.s.now = e.clock
	e.srv = httptest.NewServer(e.s)
	t.Cleanup(e.srv.Close)
	e.client = &Client{URL: e.srv.URL}
	e.browser = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

func (e *testEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *testEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// open sends the request of a browser and returns the status, the body and where it goes next.
func (e *testEnv) open(t *testing.T, method, target string, form url.Values) (int, string, string) {
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

// token posts form to the token endpoint and returns the status and the error code of the answer.
func (e *testEnv) token(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	resp, err := http.PostForm(e.srv.URL+TokenPath, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var o OAuthError
	_ = json.NewDecoder(resp.Body).Decode(&o)
	return resp.StatusCode, o.Code
}

func errorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func errorStatus(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// A password login gives a User that holds an API role a user token that lasts the life of the
// Config, and no longer than the User; a wrong password, a name that no User has and a User without a
// role are refused, each with its record in the audit log. A logout ends the token.
func TestPasswordLogin(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	in, err := e.client.SignIn(ctx, "alice", "the password of alice")
	if err != nil {
		t.Fatal(err)
	}
	if in.Role != rbac.Admin || in.User != "alice" || !in.Expires.Equal(e.clock().Add(DefaultTokenLife)) {
		t.Errorf("the login of alice gave %+v", in)
	}
	e.c.change(func(f *fakeController) { f.expires["alice"] = e.clock().Add(time.Hour) })
	if in, err = e.client.SignIn(ctx, "alice", "the password of alice"); err != nil || !in.Expires.Equal(e.clock().Add(time.Hour)) {
		t.Errorf("the token of a User that expires in an hour: %+v, %v", in, err)
	}
	for _, c := range []struct{ user, password string }{{"alice", "wrong"}, {"nobody", "the password of alice"}} {
		_, err := e.client.SignIn(ctx, c.user, c.password)
		if errorStatus(err) != http.StatusUnauthorized || errorCode(err) != controller.ErrBadCredentials.Error() {
			t.Errorf("%s with %q: %v, want 401 and the one refusal of wrong credentials", c.user, c.password, err)
		}
	}
	if _, err := e.client.SignIn(ctx, "bob", "the password of bob"); errorStatus(err) != http.StatusForbidden || !strings.Contains(errorCode(err), "holds no API role") {
		t.Errorf("bob, who holds no API role: %v, want 403", err)
	}
	failed := e.c.recorded(audit.AuthFailed)
	if len(failed) != 2 || failed[0].Actor != "user:alice" || failed[1].Actor != "user:nobody" || failed[0].Source != "127.0.0.1" || failed[0].Outcome != audit.Failure {
		t.Errorf("the records of the failed logins are %+v", failed)
	}
	logins := e.c.recorded(audit.Login)
	if len(logins) != 3 || logins[0].Outcome != audit.Success || logins[2].Actor != "user:bob" || logins[2].Outcome != audit.Failure {
		t.Errorf("the records of the logins are %+v", logins)
	}
	// A body that is not a login is refused before anything is checked
	resp, err := http.Post(e.srv.URL+Root, "application/json", strings.NewReader(`{"user": "alice", "secret": "x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a body that is not a login: %d", resp.StatusCode)
	}
	// The logout
	if tok, err := e.client.SignOut(ctx, in.Secret); err != nil || tok.User != "alice" {
		t.Errorf("the logout: %+v, %v", tok, err)
	}
	if _, err := e.client.SignOut(ctx, in.Secret); errorStatus(err) != http.StatusUnauthorized {
		t.Errorf("a second logout of the token: %v, want 401", err)
	}
	if _, err := e.client.SignOut(ctx, ""); errorStatus(err) != http.StatusUnauthorized {
		t.Errorf("a logout without a token: %v, want 401", err)
	}
	if out := e.c.recorded(audit.Logout); len(out) != 1 || out[0].Actor != "user:alice" {
		t.Errorf("the records of the logouts are %+v", out)
	}
}

// The throttle: five failed logins in a row for a name, or from a source, and the next one is refused
// at once, without a check of the password, with Retry-After, until a try came back a minute later.
func TestThrottle(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	for i := range tries {
		if _, err := e.client.SignIn(ctx, "alice", fmt.Sprintf("wrong %d", i)); errorStatus(err) != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: %v", i, err)
		}
	}
	checks := e.c.checked()
	resp, err := http.Post(e.srv.URL+Root, "application/json", strings.NewReader(`{"user": "alice", "password": "the password of alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if more := e.c.checked() - checks; resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "60" || more != 0 {
		t.Fatalf("the right password after %d wrong ones: %d, Retry-After %q, %d checks more", tries, resp.StatusCode, resp.Header.Get("Retry-After"), more)
	}
	if r := e.c.recorded(audit.AuthFailed); !strings.Contains(r[len(r)-1].Message, "the password was not checked") {
		t.Errorf("the record of the throttled login is %+v", r[len(r)-1])
	}
	// A try comes back after a minute
	e.advance(tryBack)
	if _, err := e.client.SignIn(ctx, "alice", "the password of alice"); err != nil {
		t.Errorf("the right password a minute later: %v", err)
	}
	if _, err := e.client.SignIn(ctx, "alice", "wrong again"); errorStatus(err) != http.StatusUnauthorized {
		t.Errorf("a wrong password a minute later: %v", err)
	}
	if _, err := e.client.SignIn(ctx, "alice", "the password of alice"); errorStatus(err) != http.StatusTooManyRequests {
		t.Errorf("the right password after the try that came back failed: %v, want 429", err)
	}
}

// The limiter alone: each key its own tries, a key per IPv6 /64, one key for every name that no User
// can have, and a full table that forgets the keys whose tries all came back.
func TestLimiter(t *testing.T) {
	now := time.Date(2026, time.October, 28, 9, 0, 0, 0, time.UTC)
	l := newLimiter()
	for range tries {
		l.fail(now, "a")
	}
	if w := l.wait(now, "a"); w != tryBack {
		t.Errorf("a key with no try left waits %v, want %v", w, tryBack)
	}
	if w := l.wait(now, "b"); w != 0 {
		t.Errorf("another key waits %v", w)
	}
	if w := l.wait(now.Add(tryBack/2), "a", "b"); w != tryBack/2 {
		t.Errorf("half a minute later the key waits %v", w)
	}
	if w := l.wait(now.Add(tryBack), "a"); w != 0 {
		t.Errorf("a minute later the key waits %v", w)
	}
	if sourceKey("2001:db8::1") != sourceKey("2001:db8::2") || sourceKey("2001:db8::1") == sourceKey("2001:db8:0:1::1") || sourceKey("10.0.0.1") == sourceKey("10.0.0.2") {
		t.Error("the sources are not keyed by IPv4 address and IPv6 /64")
	}
	if sourceKey("::ffff:10.0.0.1") != sourceKey("10.0.0.1") || sourceKey("not an address") != "source not an address" {
		t.Error("a mapped address is not its IPv4 address")
	}
	if nameKey("Not A Name") != nameKey("../../x") || nameKey("alice") == nameKey("bob") {
		t.Error("the names are not keyed by name, with one key for what is no name")
	}
	for i := range maxKeys {
		l.fail(now, fmt.Sprint(i))
	}
	l.fail(now, "one more")
	if _, ok := l.keys["one more"]; ok {
		t.Error("a full table took one more key")
	}
	l.fail(now.Add(10*tryBack), "one more")
	if _, ok := l.keys["one more"]; !ok || len(l.keys) != 1 {
		t.Errorf("a full table of keys whose tries came back holds %d keys", len(l.keys))
	}
}

// A browser login: the authorization page and its form, the redirect with the code and the state, the
// exchange with the verifier, once, and what goes wrong on the way.
func TestBrowserLogin(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	verifier, challenge := NewVerifier()
	key := []byte(strings.Repeat("k", 32))
	req := Request{RedirectURI: "http://127.0.0.1:50000/callback?client=1", State: "s1", Challenge: challenge, Device: &Device{Key: key, Name: "laptop"}}
	status, body, _ := e.open(t, http.MethodGet, e.client.AuthorizeURL(req), nil)
	if status != http.StatusOK || !strings.Contains(body, base64.StdEncoding.EncodeToString(key)) || !strings.Contains(body, "laptop") {
		t.Fatalf("the authorization page: %d\n%s", status, body)
	}
	resp, err := e.browser.Get(e.client.AuthorizeURL(req))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' http://127.0.0.1:50000;") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("the Content Security Policy of the page is %q", csp)
	}
	if status, body, _ := e.open(t, http.MethodGet, e.srv.URL+AuthorizePath+"?client_id=evil", nil); status != http.StatusBadRequest || strings.Contains(body, `name="password"`) {
		t.Errorf("a page of a request that is not valid: %d\n%s", status, body)
	}

	form := req.Values()
	form.Set("user", "alice")
	form.Set("password", "wrong")
	if status, body, location := e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form); status != http.StatusUnauthorized || location != "" || !strings.Contains(body, "the user name or the password is wrong") {
		t.Errorf("the form with a wrong password: %d to %q\n%s", status, location, body)
	}
	form.Set("password", "the password of alice")
	status, _, location := e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	u, err := url.Parse(location)
	if status != http.StatusSeeOther || err != nil || u.Host != "127.0.0.1:50000" || u.Query().Get("client") != "1" || u.Query().Get("state") != "s1" {
		t.Fatalf("the form with the right password: %d to %q", status, location)
	}
	code := u.Query().Get("code")
	if _, err := e.client.Exchange(ctx, code, "http://127.0.0.1:50000/other", verifier); errorCode(err) != "invalid_grant" {
		t.Errorf("the exchange with another redirect URI: %v", err)
	}
	// That spent the code
	if _, err := e.client.Exchange(ctx, code, req.RedirectURI, verifier); errorCode(err) != "invalid_grant" {
		t.Errorf("the exchange of a spent code: %v", err)
	}
	_, _, location = e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	u, _ = url.Parse(location)
	res, err := e.client.Exchange(ctx, u.Query().Get("code"), req.RedirectURI, verifier)
	if err != nil || res.Node != "laptop" || res.User != "alice" || res.Controller.TLSFingerprint != strings.Repeat("ab", 32) {
		t.Fatalf("the exchange: %+v, %v", res, err)
	}
	// A code ends after a minute
	_, _, location = e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	u, _ = url.Parse(location)
	e.advance(codeLife)
	if _, err := e.client.Exchange(ctx, u.Query().Get("code"), req.RedirectURI, verifier); errorCode(err) != "invalid_grant" {
		t.Errorf("the exchange of a code a minute old: %v", err)
	}
	// An enrolment that the controller refuses sends the browser back with access_denied
	e.c.change(func(f *fakeController) { f.refuse = fmt.Errorf("%w: the maximum is 2", intent.ErrInvalid) })
	_, _, location = e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	if u, _ = url.Parse(location); u.Query().Get("error") != "access_denied" || !strings.Contains(u.Query().Get("error_description"), "the maximum is 2") || u.Query().Get("code") != "" {
		t.Errorf("a refused enrolment went to %q", location)
	}
	if r := e.c.recorded(audit.Enrolment); len(r) != 1 || r[0].Outcome != audit.Failure {
		t.Errorf("the records of the refused enrolment are %+v", r)
	}

	// The token endpoint refuses what is not a grant of this controller
	for _, c := range []struct {
		form   url.Values
		status int
		code   string
	}{
		{url.Values{"grant_type": {"authorization_code"}, "client_id": {"other"}}, http.StatusUnauthorized, "invalid_client"},
		{url.Values{"grant_type": {"password"}, "client_id": {ClientID}}, http.StatusBadRequest, "unsupported_grant_type"},
		{url.Values{"grant_type": {"authorization_code", "authorization_code"}, "client_id": {ClientID}}, http.StatusBadRequest, "invalid_request"},
		{url.Values{"grant_type": {DeviceGrant}, "client_id": {ClientID}, "device_code": {"nothing"}}, http.StatusBadRequest, "invalid_grant"},
	} {
		if status, code := e.token(t, c.form); status != c.status || code != c.code {
			t.Errorf("%v: %d %s, want %d %s", c.form, status, code, c.status, c.code)
		}
	}
}

// A browser login for a user token: the token is made when the client takes the code, with the role of
// the User; a User without a role gets access_denied.
func TestBrowserLoginForAUserToken(t *testing.T) {
	e := newTestEnv(t)
	verifier, challenge := NewVerifier()
	req := Request{RedirectURI: "http://127.0.0.1:50000/", Challenge: challenge}
	form := req.Values()
	form.Set("user", "alice")
	form.Set("password", "the password of alice")
	_, _, location := e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	u, _ := url.Parse(location)
	res, err := e.client.Exchange(context.Background(), u.Query().Get("code"), req.RedirectURI, verifier)
	if err != nil || res.TokenType != "Bearer" || res.Role != rbac.Admin || res.ExpiresIn != int64(DefaultTokenLife/time.Second) || res.AccessToken == "" {
		t.Fatalf("the exchange for a user token: %+v, %v", res, err)
	}
	form.Set("user", "bob")
	form.Set("password", "the password of bob")
	_, _, location = e.open(t, http.MethodPost, e.srv.URL+AuthorizePath, form)
	if u, _ = url.Parse(location); u.Query().Get("error") != "access_denied" || !strings.Contains(u.Query().Get("error_description"), "holds no API role") {
		t.Errorf("the browser login of bob, who holds no role, went to %q", location)
	}
}

// A device code login: the code and the user code, the polls before the user signed in, too soon, and
// after; the device page with and without the code; a user code that no device waits with; the end
// of a device code.
func TestDeviceCodeLogin(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	key := []byte(strings.Repeat("d", 32))
	a, err := e.client.StartDevice(ctx, &Device{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if uc, ok := NormalizeUserCode(a.UserCode); !ok || uc != a.UserCode || a.Interval != 5 || a.VerificationURI != e.srv.URL+DevicePath {
		t.Fatalf("the device authorization is %+v", a)
	}
	poll := url.Values{"grant_type": {DeviceGrant}, "client_id": {ClientID}, "device_code": {a.DeviceCode}}
	if status, code := e.token(t, poll); status != http.StatusBadRequest || code != "authorization_pending" {
		t.Errorf("the first poll: %d %s", status, code)
	}
	if _, code := e.token(t, poll); code != "slow_down" {
		t.Errorf("a poll at once: %s, want slow_down", code)
	}
	e.advance(DefaultInterval)
	if _, code := e.token(t, poll); code != "slow_down" {
		t.Errorf("a poll after the first interval, which the slow_down made 10 s: %s, want slow_down", code)
	}
	e.advance(3 * DefaultInterval)
	if _, code := e.token(t, poll); code != "authorization_pending" {
		t.Errorf("a poll after the longer interval: %s, want authorization_pending", code)
	}

	if status, body, _ := e.open(t, http.MethodGet, e.srv.URL+DevicePath, nil); status != http.StatusOK || !strings.Contains(body, `name="user_code"`) {
		t.Errorf("the device page without a code: %d\n%s", status, body)
	}
	if status, body, _ := e.open(t, http.MethodGet, a.VerificationURIComplete, nil); status != http.StatusOK || !strings.Contains(body, base64.StdEncoding.EncodeToString(key)) {
		t.Errorf("the device page with the code: %d\n%s", status, body)
	}
	if status, _, _ := e.open(t, http.MethodGet, e.srv.URL+DevicePath+"?user_code=BCDF-GHJK", nil); status != http.StatusNotFound {
		t.Errorf("the device page with a code that no device waits with: %d", status)
	}
	form := url.Values{"user_code": {a.UserCode}, "user": {"alice"}, "password": {"wrong"}}
	if status, _, _ := e.open(t, http.MethodPost, e.srv.URL+DevicePath, form); status != http.StatusUnauthorized {
		t.Errorf("the device form with a wrong password: %d", status)
	}
	form.Set("password", "the password of alice")
	status, body, _ := e.open(t, http.MethodPost, e.srv.URL+DevicePath, form)
	if status != http.StatusOK || !strings.Contains(body, "alice-1") {
		t.Fatalf("the device form: %d\n%s", status, body)
	}
	if status, _, _ := e.open(t, http.MethodPost, e.srv.URL+DevicePath, form); status != http.StatusNotFound {
		t.Errorf("the device form for a device that a user let in: %d, want 404", status)
	}
	e.advance(time.Minute)
	res, err := e.client.PollDevice(ctx, a)
	if err != nil || res.Node != "alice-1" || res.User != "alice" {
		t.Fatalf("the poll after the sign-in: %+v, %v", res, err)
	}
	if _, code := e.token(t, poll); code != "invalid_grant" {
		t.Errorf("a poll of the answered device code: %s", code)
	}

	// A device code for a user token, which ends before anyone signs in
	b, err := e.client.StartDevice(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, body, _ := e.open(t, http.MethodGet, b.VerificationURIComplete, nil); status != http.StatusOK || !strings.Contains(body, "user token") {
		t.Errorf("the device page of a device code for a user token: %d\n%s", status, body)
	}
	e.advance(deviceLife)
	if _, err := e.client.PollDevice(ctx, b); errorCode(err) != "expired_token" {
		t.Errorf("the poll of a device code ten minutes old: %v", err)
	}
	// One that a user signs in for
	c, err := e.client.StartDevice(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, body, _ := e.open(t, http.MethodPost, e.srv.URL+DevicePath, url.Values{"user_code": {c.UserCode}, "user": {"alice"}, "password": {"the password of alice"}}); status != http.StatusOK ||
		!strings.Contains(body, "signed in as user alice") {
		t.Errorf("the device form for a user token: %d\n%s", status, body)
	}
	if res, err := e.client.PollDevice(ctx, c); err != nil || res.AccessToken == "" || res.Role != rbac.Admin {
		t.Errorf("the poll for a user token: %+v, %v", res, err)
	}

	// A request of the device authorization endpoint that is not valid
	for _, f := range []url.Values{{"client_id": {"other"}}, {"client_id": {ClientID}, "node_key": {"AAAA"}}, {"client_id": {ClientID}, "node_name": {"x"}}} {
		resp, err := http.PostForm(e.srv.URL+DeviceCodePath, f)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("a device code request %v: %d", f, resp.StatusCode)
		}
	}
	// At most maxGrantsPerSource device codes wait from one source
	for range maxGrantsPerSource {
		if _, err := e.client.StartDevice(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.client.StartDevice(ctx, nil); errorCode(err) != "temporarily_unavailable" {
		t.Errorf("one device code more than a source may have: %v", err)
	}
}

// Five user codes in a row that no device waits with, and the device page refuses the source for a
// minute.
func TestUserCodeThrottle(t *testing.T) {
	e := newTestEnv(t)
	for range tries {
		e.open(t, http.MethodPost, e.srv.URL+DevicePath, url.Values{"user_code": {"BCDF-GHJK"}, "user": {"alice"}, "password": {"x"}})
	}
	if status, _, _ := e.open(t, http.MethodGet, e.srv.URL+DevicePath+"?user_code=BCDF-GHJK", nil); status != http.StatusTooManyRequests {
		t.Errorf("the device page after five wrong user codes: %d", status)
	}
	if status, _, _ := e.open(t, http.MethodPost, e.srv.URL+DevicePath, url.Values{"user_code": {"BCDF-GHJK"}}); status != http.StatusTooManyRequests {
		t.Errorf("the device form after five wrong user codes: %d", status)
	}
	if n := e.c.checked(); n != 0 {
		t.Errorf("a wrong user code checked %d passwords", n)
	}
}

// The requests of the authorization page: what ParseAuthorize takes, and what it refuses.
func TestParseAuthorize(t *testing.T) {
	_, challenge := NewVerifier()
	good := Request{RedirectURI: "http://127.0.0.1:8080/cb", State: "s", Challenge: challenge, Device: &Device{Key: make([]byte, 32), Name: "pc-1"}}
	got, err := ParseAuthorize(good.Values())
	if err != nil || got.RedirectURI != good.RedirectURI || got.State != "s" || got.Device == nil || got.Device.Name != "pc-1" {
		t.Fatalf("ParseAuthorize(%v) = %+v, %v", good.Values(), got, err)
	}
	if got, err := ParseAuthorize(Request{RedirectURI: "http://127.0.0.1:1/", Challenge: challenge}.Values()); err != nil || got.Device != nil {
		t.Errorf("a request for a user token: %+v, %v", got, err)
	}
	for name, change := range map[string]func(url.Values){
		"response type":     func(v url.Values) { v.Set("response_type", "token") },
		"client":            func(v url.Values) { v.Set("client_id", "other") },
		"https redirect":    func(v url.Values) { v.Set("redirect_uri", "https://127.0.0.1:8080/cb") },
		"remote redirect":   func(v url.Values) { v.Set("redirect_uri", "http://example.com:8080/cb") },
		"localhost":         func(v url.Values) { v.Set("redirect_uri", "http://localhost:8080/cb") },
		"no port":           func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1/cb") },
		"user in redirect":  func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:80@example.com/cb") },
		"fragment":          func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:8080/cb#x") },
		"plain method":      func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"short challenge":   func(v url.Values) { v.Set("code_challenge", "abc") },
		"long state":        func(v url.Values) { v.Set("state", strings.Repeat("s", maxState+1)) },
		"bad key":           func(v url.Values) { v.Set("node_key", "AAAA") },
		"bad name":          func(v url.Values) { v.Set("node_name", "Not A Name") },
		"name without key":  func(v url.Values) { v.Del("node_key") },
		"twice":             func(v url.Values) { v.Add("state", "t") },
		"challenge missing": func(v url.Values) { v.Del("code_challenge") },
	} {
		v := good.Values()
		change(v)
		if _, err := ParseAuthorize(v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ParseAuthorize(%v) gave %v, want ErrInvalid", name, v, err)
		}
	}
}

// A verifier verifies its own challenge and no other, and only a verifier of the right form does.
func TestVerifyChallenge(t *testing.T) {
	verifier, challenge := NewVerifier()
	other, _ := NewVerifier()
	if !VerifyChallenge(verifier, challenge) || VerifyChallenge(other, challenge) || VerifyChallenge("", challenge) ||
		VerifyChallenge(strings.Repeat("a", maxVerifier+1), challenge) || VerifyChallenge(verifier[:42]+"!", challenge) {
		t.Error("VerifyChallenge does not check the verifier against its challenge")
	}
	// The example of RFC 7636 appendix B
	if !VerifyChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") {
		t.Error("VerifyChallenge does not verify the example of RFC 7636")
	}
}

// User codes: drawn from the alphabet as XXXX-XXXX, and taken as a person types them.
func TestUserCodes(t *testing.T) {
	for range 100 {
		c := newUserCode()
		if n, ok := NormalizeUserCode(c); !ok || n != c {
			t.Fatalf("the user code %q normalizes to %q, %v", c, n, ok)
		}
	}
	for in, want := range map[string]string{"bcdf-ghjk": "BCDF-GHJK", "BCDFGHJK": "BCDF-GHJK", " bcdf ghjk ": "BCDF-GHJK"} {
		if got, ok := NormalizeUserCode(in); !ok || got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "ВCDF-GHJK"} {
		if got, ok := NormalizeUserCode(in); ok {
			t.Errorf("NormalizeUserCode(%q) = %q, want no user code", in, got)
		}
	}
}

// The callback of a browser login takes the redirect with its state, refuses one with another state,
// and passes an error of the controller on.
func TestCallback(t *testing.T) {
	cb, err := ListenCallback("s1")
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	if !strings.HasPrefix(cb.URL(), "http://127.0.0.1:") {
		t.Errorf("the redirect URI is %s", cb.URL())
	}
	for _, target := range []string{cb.URL() + "?state=other&code=c0", strings.TrimSuffix(cb.URL(), "/callback") + "/other"} {
		resp, err := http.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s was taken", target)
		}
	}
	resp, err := http.Get(cb.URL() + "?state=s1&code=c1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, err := cb.Wait(context.Background()); err != nil || code != "c1" {
		t.Errorf("the callback gave %q, %v", code, err)
	}

	denied, err := ListenCallback("s2")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	resp, err = http.Get(denied.URL() + "?state=s2&error=access_denied&error_description=no+role")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := denied.Wait(context.Background()); errorCode(err) != "access_denied" || !strings.Contains(err.Error(), "no role") {
		t.Errorf("the callback of a refused login gave %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := denied.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a wait whose context ended: %v", err)
	}
}

// The paths of the logins that do not exist, and the methods that they do not take.
func TestUnknownCalls(t *testing.T) {
	e := newTestEnv(t)
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, Root + "/nothing", http.StatusNotFound},
		{http.MethodGet, Root, http.StatusMethodNotAllowed},
		{http.MethodGet, TokenPath, http.StatusMethodNotAllowed},
	} {
		req, err := http.NewRequest(c.method, e.srv.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, resp.StatusCode, c.status)
		}
	}
}
