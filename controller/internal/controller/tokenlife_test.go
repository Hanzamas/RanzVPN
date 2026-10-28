// Controller conformance for the life of an API token (AUD1-DT-13, #461), with the harness of
// conformance_test.go: a token that is made with an expiry is refused with 401 after it, is listed as
// expired, and an admin can still delete it; the last use of each token is kept, at most once a
// minute, and the list shows it. A clock that the test moves stands in for the time, so that nothing
// waits; the API is the one of ranz-controller, the Guard in front of the routes.
package controller_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// lifeClock is the time of the tokens of a lifeAPI, which a test moves.
type lifeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lifeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lifeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// lifeAPI serves the API of the controller of h behind the Guard, as ranz-controller does, with
// tokens that read the time from the clock that it returns, which starts at a whole second.
func (h *harness) lifeAPI() (*lifeClock, *httptest.Server) {
	h.t.Helper()
	clk := &lifeClock{now: time.Now().UTC().Truncate(time.Second)}
	tokens := rbac.New(h.st).WithClock(clk.Now)
	srv := httptest.NewTLSServer(api.Handler(h.c, tokens, api.Status{}))
	h.t.Cleanup(srv.Close)
	return clk, srv
}

// clientOf returns a client of the API on srv that calls with the token secret.
func clientOf(srv *httptest.Server, secret string) *api.Client {
	c := api.NewClient(srv.URL)
	c.Token = secret
	return c
}

// findToken returns the token name of the list that c reads, and fails when it is not there.
func findToken(t *testing.T, c *api.Client, name string) rbac.Token {
	t.Helper()
	tokens, err := c.Tokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range tokens {
		if tok.Name == name {
			return tok
		}
	}
	t.Fatalf("the tokens are %+v, and none is named %q", tokens, name)
	return rbac.Token{}
}

// TestATokenWithAnExpiryIsRefusedAfterIt is the first criterion of AUD1-DT-13 (#461): a token that is
// made with an expiry is refused with 401 after it, is shown as expired, and an admin can still
// delete it.
func TestATokenWithAnExpiryIsRefusedAfterIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	clk, srv := h.lifeAPI()
	admin := clientOf(srv, h.admin)

	// An expiry that is not in the future makes no token
	for _, expires := range []time.Time{clk.Now(), clk.Now().Add(-time.Hour)} {
		if _, err := admin.CreateTokenRequest(ctx, api.TokenRequest{Name: "ci", Role: rbac.Operator, Expires: expires}); httpStatus(err) != http.StatusBadRequest {
			t.Errorf("a token that expires at %v, with the time at %v, gave %v, want 400", expires, clk.Now(), err)
		}
	}

	expires := clk.Now().Add(time.Hour)
	ci, err := admin.CreateTokenRequest(ctx, api.TokenRequest{Name: "ci", Role: rbac.Operator, Expires: expires})
	if err != nil {
		t.Fatal(err)
	}
	if ci.Name != "ci" || ci.Role != rbac.Operator || !ci.Expires.Equal(expires) || ci.Expired || ci.Secret == "" {
		t.Errorf("the created token is %+v, want ci, an operator token that expires at %v", ci, expires)
	}
	forever, err := admin.CreateToken(ctx, "forever", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	if !forever.Expires.IsZero() {
		t.Errorf("a token made with no expiry expires at %v", forever.Expires)
	}

	// Before the expiry it works, with the role it was made with
	if who, err := clientOf(srv, ci.Secret).Whoami(ctx); err != nil || who.Name != "ci" || who.Role != rbac.Operator || !who.Expires.Equal(expires) || who.Expired {
		t.Fatalf("whoami of the token before its expiry gave %+v, %v", who, err)
	}
	if _, err := clientOf(srv, ci.Secret).Apply(ctx, labVRF); err != nil {
		t.Errorf("the operator token could not apply before its expiry: %v", err)
	}

	// From the instant of the expiry on, every call is refused with 401, and it says when the token ended
	clk.Advance(time.Hour)
	expired := clientOf(srv, ci.Secret)
	for name, call := range map[string]func() error{
		"whoami":  func() error { _, err := expired.Whoami(ctx); return err },
		"status":  func() error { _, err := expired.Status(ctx); return err },
		"nodes":   func() error { _, err := expired.Nodes(ctx); return err },
		"apply":   func() error { _, err := expired.Apply(ctx, labVRF); return err },
		"tokens":  func() error { _, err := expired.Tokens(ctx); return err },
		"licence": func() error { _, err := expired.Licence(ctx); return err },
	} {
		err := call()
		if httpStatus(err) != http.StatusUnauthorized {
			t.Errorf("%s with the expired token gave %v, want 401", name, err)
			continue
		}
		if !strings.Contains(err.Error(), "expired at "+expires.Format(time.RFC3339)) || strings.Contains(err.Error(), `"ci"`) {
			t.Errorf("%s with the expired token says %q, want when the token expired and not its name", name, err)
		}
	}
	// The challenge is the one of RFC 6750, section 3, for a token that expired
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ci.Secret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if challenge := resp.Header.Get("WWW-Authenticate"); resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(challenge, `error="invalid_token"`) || !strings.Contains(challenge, `error_description="the token expired"`) {
		t.Errorf("the expired token got %d with the challenge %q, want 401 and invalid_token that says it expired", resp.StatusCode, challenge)
	}
	// The time of one token is not the time of another
	if _, err := clientOf(srv, forever.Secret).Whoami(ctx); err != nil {
		t.Errorf("a token with no expiry was refused at the time of the other: %v", err)
	}
	if _, err := admin.Status(ctx); err != nil {
		t.Errorf("the admin token was refused at the time of the other: %v", err)
	}

	// An admin lists it, as expired and with its expiry and its role, and deletes it
	listed := findToken(t, admin, "ci")
	if !listed.Expired || !listed.Expires.Equal(expires) || listed.Role != rbac.Operator {
		t.Errorf("the list shows the expired token as %+v, want it expired, with its expiry and its role", listed)
	}
	if other := findToken(t, admin, "forever"); other.Expired || !other.Expires.IsZero() {
		t.Errorf("the list shows the token with no expiry as %+v", other)
	}
	gone, err := admin.DeleteToken(ctx, "ci")
	if err != nil || gone.Name != "ci" || !gone.Expired {
		t.Fatalf("deleting the expired token gave %+v, %v", gone, err)
	}
	tokens, err := admin.Tokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range tokens {
		if tok.Name == "ci" {
			t.Errorf("the deleted token is still listed: %+v", tok)
		}
	}
	if _, err := clientOf(srv, ci.Secret).Whoami(ctx); httpStatus(err) != http.StatusUnauthorized || strings.Contains(err.Error(), "expired") {
		t.Errorf("the secret of the deleted token gave %v, want the 401 of a token that the controller does not know", err)
	}
}

// TestTheLastUseOfATokenIsKeptAndListed is the second criterion of AUD1-DT-13 (#461), where the API
// answers it: the list shows when each token was last used, a token that was never used shows none,
// and a token that is used again within a minute does not move the use that was stored.
func TestTheLastUseOfATokenIsKeptAndListed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	clk, srv := h.lifeAPI()
	admin := clientOf(srv, h.admin)

	reader, err := admin.CreateToken(ctx, "reader", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	if listed := findToken(t, admin, "reader"); !listed.LastUsed.IsZero() {
		t.Fatalf("a token that was never used is listed with the last use %v", listed.LastUsed)
	}
	if listed := findToken(t, admin, rbac.FirstAdmin); listed.LastUsed.IsZero() || listed.LastUsed.After(clk.Now()) {
		t.Errorf("the admin token, which made these calls, is listed with the last use %v, want a time up to %v", listed.LastUsed, clk.Now())
	}

	first := clk.Now()
	if _, err := clientOf(srv, reader.Secret).Status(ctx); err != nil {
		t.Fatal(err)
	}
	if listed := findToken(t, admin, "reader"); !listed.LastUsed.Equal(first) {
		t.Fatalf("the first use is listed as %v, want %v", listed.LastUsed, first)
	}

	clk.Advance(30 * time.Second)
	for range 3 {
		if _, err := clientOf(srv, reader.Secret).Nodes(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if listed := findToken(t, admin, "reader"); !listed.LastUsed.Equal(first) {
		t.Errorf("uses within a minute of the first moved the last use to %v, want it kept at %v", listed.LastUsed, first)
	}

	// A call that the role of the token refuses is a use of the token all the same
	clk.Advance(31 * time.Second)
	if _, err := clientOf(srv, reader.Secret).Apply(ctx, labVRF); httpStatus(err) != http.StatusForbidden {
		t.Fatalf("a viewer applied: %v", err)
	}
	if listed := findToken(t, admin, "reader"); !listed.LastUsed.Equal(clk.Now()) {
		t.Errorf("a use after a minute is listed as %v, want %v", listed.LastUsed, clk.Now())
	}
	// A call with a token that the controller does not know is the use of no token
	before := findToken(t, admin, "reader").LastUsed
	clk.Advance(2 * time.Minute)
	if _, err := clientOf(srv, "ranz_NOTATOKENOFTHISCONTROLLER").Status(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with an unknown token gave %v", err)
	}
	if listed := findToken(t, admin, "reader"); !listed.LastUsed.Equal(before) {
		t.Errorf("a call with an unknown token changed the last use of reader from %v to %v", before, listed.LastUsed)
	}
}
