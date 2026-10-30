package login

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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

// joinSecret is the secret of a join token of the tests, which has the form of one.
var joinSecret = controller.JoinTokenPrefix + strings.Repeat("A", 26)

// portalController is the fake controller of the tests of the portal: it holds join tokens, and takes the join
// of a device with one, which the controller of ranz-controller does.
type portalController struct {
	*fakeController
	tokens map[string]string // the User of each join token that waits, by secret
	joined map[string][]byte // the static key of each device that joined, by the name of its Node
	refuse error             // the error of the next join with a token that waits
}

func (p *portalController) JoinDevice(_ context.Context, secret, name string, key []byte) (controller.Enrolment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user, ok := p.tokens[secret]
	if !ok {
		return controller.Enrolment{}, controller.ErrBadJoinToken
	}
	if err := p.refuse; err != nil {
		p.refuse = nil
		return controller.Enrolment{User: user}, err
	}
	delete(p.tokens, secret)
	if name == "" {
		name = fmt.Sprintf("%s-%d", user, len(p.joined)+1)
	}
	p.joined[name] = key
	return controller.Enrolment{Node: name, User: user, Revision: uint64(10 + len(p.joined))}, nil
}

// enrolled returns the static key of the device that joined as the Node name, and how many devices joined.
func (p *portalController) enrolled(name string) ([]byte, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.joined[name], len(p.joined)
}

// wait puts the join token secret of the User user in the controller, and the error that the next join
// with a token that waits is refused with, nil for none.
func (p *portalController) wait(secret, user string, refuse error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[secret] = user
	p.refuse = refuse
}

// portalTokens are the fake tokens of the tests of the portal: they also give a token of the self scope.
type portalTokens struct {
	*fakeTokens
	self map[string]rbac.UserToken
}

func (p *portalTokens) IssueSelfToken(_ context.Context, name string, expires time.Time) (rbac.UserToken, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tok := rbac.UserToken{Token: rbac.Token{Name: "user:" + name, Role: rbac.Self, User: name}, Secret: fmt.Sprintf("ranz_s_%d", len(p.self)), Expires: expires}
	p.self[tok.Secret] = tok
	return tok, nil
}

// portalEnv is a Server of the fakes of the portal behind a test server, with its clock.
type portalEnv struct {
	c      *portalController
	tokens *portalTokens
	srv    *httptest.Server
	client *Client

	mu  sync.Mutex
	now time.Time
}

func newPortalEnv(t *testing.T) *portalEnv {
	e := &portalEnv{
		c: &portalController{fakeController: newFakeController(), tokens: map[string]string{joinSecret: "alice"}, joined: map[string][]byte{}},
		tokens: &portalTokens{fakeTokens: &fakeTokens{roles: map[string]rbac.Role{"alice": rbac.Admin}, issued: map[string]rbac.UserToken{}},
			self: map[string]rbac.UserToken{}},
		now: time.Date(2026, time.October, 29, 9, 0, 0, 0, time.UTC),
	}
	s := New(Config{Controller: e.c, Tokens: e.tokens, Fingerprint: func() string { return strings.Repeat("ab", 32) }})
	s.now = e.clock
	e.srv = httptest.NewServer(s)
	t.Cleanup(e.srv.Close)
	e.client = &Client{URL: e.srv.URL}
	return e
}

func (e *portalEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *portalEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// keyOf returns a static key of 32 bytes that begins with b.
func keyOf(b byte) []byte {
	k := make([]byte, 32)
	k[0] = b
	return k
}

// A password login that asks for the scope self gives a token of that scope to any User that has a password,
// with or without an API role, that lasts the life of the Config and no longer than the User; a wrong password
// is refused as for any login, and a scope that the controller does not know is a bad request.
func TestSignInForThePortal(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	in, err := e.client.SignInSelf(ctx, "bob", "the password of bob")
	if err != nil {
		t.Fatal(err)
	}
	if in.Role != rbac.Self || in.User != "bob" || in.Name != "user:bob" || !strings.HasPrefix(in.Secret, "ranz_s_") || !in.Expires.Equal(e.clock().Add(DefaultTokenLife)) {
		t.Errorf("the login of bob, who holds no API role, gave %+v", in)
	}
	// A User that holds a role gets the scope that it asked for, and no more
	if in, err = e.client.SignInSelf(ctx, "alice", "the password of alice"); err != nil || in.Role != rbac.Self || in.User != "alice" {
		t.Errorf("the login of alice, who holds the role admin, for the scope self: %+v, %v", in, err)
	}
	// A token never outlives its User
	e.c.change(func(f *fakeController) { f.expires["bob"] = e.clock().Add(time.Hour) })
	if in, err = e.client.SignInSelf(ctx, "bob", "the password of bob"); err != nil || !in.Expires.Equal(e.clock().Add(time.Hour)) {
		t.Errorf("the token of a User that expires in an hour: %+v, %v", in, err)
	}
	if _, err := e.client.SignInSelf(ctx, "bob", "wrong"); errorStatus(err) != http.StatusUnauthorized || errorCode(err) != controller.ErrBadCredentials.Error() {
		t.Errorf("a wrong password for the scope self: %v, want 401 and the one refusal of wrong credentials", err)
	}
	resp, err := http.Post(e.srv.URL+Root, "application/json", strings.NewReader(`{"user": "bob", "password": "the password of bob", "scope": "admin"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a scope that the controller does not know: %d, want 400", resp.StatusCode)
	}
	logins := e.c.recorded(audit.Login)
	if len(logins) != 3 || logins[0].Actor != "user:bob" || logins[0].Outcome != audit.Success || !strings.Contains(logins[0].Message, "scope self") {
		t.Errorf("the records of the logins are %+v", logins)
	}
	if failed := e.c.recorded(audit.AuthFailed); len(failed) != 1 || failed[0].Actor != "user:bob" {
		t.Errorf("the records of the failed logins are %+v", failed)
	}
}

// A controller whose token store gives no token of the self scope answers 501 to a login that asks for it, so
// that a login of a test without the portal does not go wrong in silence.
func TestAScopeNeedsATokenStoreThatGivesIt(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.client.SignInSelf(context.Background(), "alice", "the password of alice"); errorStatus(err) != http.StatusNotImplemented {
		t.Errorf("a login for the scope self at a controller that gives none: %v, want 501", err)
	}
}

// The join of a device with a join token (SDN-58): the Node of the device is made for the User of the token
// and answered with the keys of the controller; the token is used once; each way to be refused is a refusal
// of its own and is in the audit log, with the User of the token as its actor when the token was valid.
func TestJoinWithAJoinToken(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	key := keyOf(7)
	res, err := e.client.Join(ctx, joinSecret, Device{Key: key, Name: "alice-nas"})
	if err != nil {
		t.Fatal(err)
	}
	if res.User != "alice" || res.Node != "alice-nas" || res.Revision != 11 || res.Controller == nil || res.Controller.PublicKey != keyText(make([]byte, 32)) ||
		res.Controller.TLSFingerprint != strings.Repeat("ab", 32) || res.AccessToken != "" {
		t.Errorf("the join gave %+v (%+v)", res, res.Controller)
	}
	if got, n := e.c.enrolled("alice-nas"); !bytes.Equal(got, key) || n != 1 {
		t.Errorf("the controller enrolled %d devices, and the key of alice-nas is %v", n, got)
	}
	recs := e.c.recorded(audit.Enrolment)
	if len(recs) != 1 || recs[0].Actor != "user:alice" || recs[0].Outcome != audit.Success || recs[0].Source != "127.0.0.1" ||
		!strings.Contains(recs[0].Message, "alice-nas") || !strings.Contains(recs[0].Message, keyText(key)) || strings.Contains(recs[0].Message, joinSecret) {
		t.Errorf("the record of the join is %+v", recs)
	}

	// The token was used, so a second device with it is refused, and so is the same one again: 401, in the
	// one words for every secret that is no token, and recorded with no actor
	for _, d := range []Device{{Key: keyOf(8)}, {Key: key}} {
		_, err := e.client.Join(ctx, joinSecret, d)
		if errorStatus(err) != http.StatusUnauthorized || errorCode(err) != controller.ErrBadJoinToken.Error() {
			t.Errorf("a second join with the token: %v, want 401", err)
		}
	}
	failed := e.c.recorded(audit.AuthFailed)
	if len(failed) != 2 || failed[0].Actor != audit.ActorUnknown || failed[0].Outcome != audit.Failure || failed[0].Source != "127.0.0.1" {
		t.Errorf("the records of the refused joins are %+v", failed)
	}
	if _, n := e.c.enrolled(""); n != 1 {
		t.Errorf("a token that was used enrolled another device: %d devices joined", n)
	}

	// A request that is not a join is refused before the token is looked at
	other := controller.JoinTokenPrefix + strings.Repeat("B", 26)
	for _, f := range []url.Values{
		{"token": {"not a token"}, "node_key": {keyText(key)}},
		{"token": {joinSecret}},
		{"token": {joinSecret}, "node_key": {"not base64"}},
		{"token": {joinSecret}, "node_key": {keyText(key)}, "node_name": {"Not A Name"}},
		{"token": {joinSecret, joinSecret}, "node_key": {keyText(key)}},
	} {
		resp, err := http.PostForm(e.srv.URL+JoinPath, f)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("the join %v: %d, want 400", f, resp.StatusCode)
		}
	}
	resp, err := http.Get(e.srv.URL + JoinPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a GET of the join: %d, want 405", resp.StatusCode)
	}
	if resp, err = http.Post(e.srv.URL+JoinPath, "application/x-www-form-urlencoded", strings.NewReader("token=%zz")); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a body that is no form: %d, want 400", resp.StatusCode)
	}

	// A device that the controller refuses leaves the token with its User: the record names the User, and the
	// refusal has the status of its kind
	for _, c := range []struct {
		refuse error
		status int
	}{
		{fmt.Errorf("%w: the maximum is 1", intent.ErrInvalid), http.StatusBadRequest},
		{fmt.Errorf("%w: a Node named %q exists", controller.ErrConflict, "x"), http.StatusConflict},
		{controller.ErrUserBanned, http.StatusForbidden},
		{controller.ErrUserExpired, http.StatusForbidden},
	} {
		e.c.wait(other, "alice", c.refuse)
		if _, err := e.client.Join(ctx, other, Device{Key: keyOf(9)}); errorStatus(err) != c.status {
			t.Errorf("a join refused with %v: %v, want %d", c.refuse, err, c.status)
		}
	}
	refused := e.c.recorded(audit.Enrolment)
	if len(refused) != 5 || refused[1].Actor != "user:alice" || refused[1].Outcome != audit.Failure || !strings.Contains(refused[1].Message, "the maximum is 1") {
		t.Errorf("the records of the refused devices are %+v", refused)
	}
	// ... and the token was not spent: the device joins when the refusal is gone
	if res, err := e.client.Join(ctx, other, Device{Key: keyOf(9)}); err != nil || res.User != "alice" {
		t.Errorf("the join after the refusals: %+v, %v", res, err)
	}
}

// A source that presents secrets that are no join token is throttled as one that gives wrong passwords is: five
// in a row, and the next join is refused at once with 429 and Retry-After, even with a token that is good,
// until a try came back.
func TestJoinsAreThrottledBySource(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	wrong := controller.JoinTokenPrefix + strings.Repeat("C", 26)
	for i := range tries {
		if _, err := e.client.Join(ctx, wrong, Device{Key: keyOf(byte(i))}); errorStatus(err) != http.StatusUnauthorized {
			t.Fatalf("the wrong token %d: %v", i, err)
		}
	}
	resp, err := http.PostForm(e.srv.URL+JoinPath, url.Values{"token": {joinSecret}, "node_key": {keyText(keyOf(1))}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "60" {
		t.Fatalf("a good token after %d wrong ones: %d, Retry-After %q, want 429 and 60", tries, resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if _, n := e.c.enrolled(""); n != 0 {
		t.Errorf("a throttled join enrolled %d devices", n)
	}
	if r := e.c.recorded(audit.AuthFailed); !strings.Contains(r[len(r)-1].Message, "the join token was not checked") {
		t.Errorf("the record of the throttled join is %+v", r[len(r)-1])
	}
	e.advance(tryBack)
	if _, err := e.client.Join(ctx, joinSecret, Device{Key: keyOf(1)}); err != nil {
		t.Errorf("the good token a minute later: %v", err)
	}
}

// A controller that takes no join of a device answers 501 to one, so that it is no silence.
func TestAControllerThatTakesNoJoinAnswers501(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.client.Join(context.Background(), joinSecret, Device{Key: keyOf(1)}); errorStatus(err) != http.StatusNotImplemented {
		t.Errorf("a join at a controller that takes none: %v, want 501", err)
	}
}

// ParseJoin takes the form of a join and refuses what is not one, with an error that wraps ErrInvalid.
func TestParseJoin(t *testing.T) {
	key := keyText(keyOf(3))
	good := func(mod func(url.Values)) url.Values {
		v := url.Values{"token": {joinSecret}, "node_key": {key}, "node_name": {"pc-1"}}
		if mod != nil {
			mod(v)
		}
		return v
	}
	req, err := ParseJoin(good(nil))
	if err != nil || req.Token != joinSecret || !bytes.Equal(req.Device.Key, keyOf(3)) || req.Device.Name != "pc-1" {
		t.Fatalf("a good join: %+v, %v", req, err)
	}
	if req, err := ParseJoin(good(func(v url.Values) { v.Del("node_name") })); err != nil || req.Device.Name != "" {
		t.Errorf("a join without a name: %+v, %v", req, err)
	}
	for what, v := range map[string]url.Values{
		"no token":          good(func(v url.Values) { v.Del("token") }),
		"a token of an API": good(func(v url.Values) { v.Set("token", "ranz_"+strings.Repeat("A", 26)) }),
		"a short token":     good(func(v url.Values) { v.Set("token", controller.JoinTokenPrefix+"AAAA") }),
		"lower case":        good(func(v url.Values) { v.Set("token", controller.JoinTokenPrefix+strings.Repeat("a", 26)) }),
		"two tokens":        good(func(v url.Values) { v.Add("token", joinSecret) }),
		"no key":            good(func(v url.Values) { v.Del("node_key") }),
		"a key that is not": good(func(v url.Values) { v.Set("node_key", base64.StdEncoding.EncodeToString([]byte("short"))) }),
		"a bad name":        good(func(v url.Values) { v.Set("node_name", "Pc 1") }),
	} {
		if _, err := ParseJoin(v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", what, err)
		}
	}
}

// FuzzParseJoin runs ParseJoin on any query: it must not panic, a join that it takes has the secret of a join
// token and a static key of 32 bytes, and it takes again what it took, from its own parameters.
func FuzzParseJoin(f *testing.F) {
	f.Add(url.Values{"token": {joinSecret}, "node_key": {keyText(keyOf(1))}, "node_name": {"pc-1"}}.Encode())
	f.Add("token=ranz_j_&node_key=")
	f.Add("token=a&token=b&node_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D")
	f.Fuzz(func(t *testing.T, query string) {
		v, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		req, err := ParseJoin(v)
		if err != nil {
			return
		}
		if !controller.ValidJoinToken(req.Token) || len(req.Device.Key) != 32 {
			t.Fatalf("ParseJoin(%v) took the token %q and a key of %d bytes", v, req.Token, len(req.Device.Key))
		}
		again := url.Values{"token": {req.Token}, "node_key": {keyText(req.Device.Key)}}
		if req.Device.Name != "" {
			again.Set("node_name", req.Device.Name)
		}
		got, err := ParseJoin(again)
		if err != nil || got.Token != req.Token || !bytes.Equal(got.Device.Key, req.Device.Key) || got.Device.Name != req.Device.Name {
			t.Fatalf("ParseJoin(%v) = %+v, and its own parameters give %+v, %v", v, req, got, err)
		}
	})
}
