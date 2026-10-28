package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// tokenAPI serves the tokens of a controller from list on a TLS test server, and returns a client of it with a
// function that gives the bodies of the POSTs that the server got. A token that is made is the token ci, an
// operator's, with the secret ranz_NEW; a delete answers with the token old, expired.
func tokenAPI(t *testing.T, list []rbac.Token) (*api.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tokens":
			api.Reply(w, http.StatusOK, api.TokenList{Tokens: list})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tokens":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
			api.Reply(w, http.StatusOK, rbac.NewToken{Token: rbac.Token{Name: "ci", Role: rbac.Operator}, Secret: "ranz_NEW"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/tokens/old":
			api.Reply(w, http.StatusOK, rbac.Token{Name: "old", Role: rbac.Viewer, Expired: true})
		default:
			api.Reply(w, http.StatusNotFound, api.Problem{Error: "no such call"})
		}
	}))
	t.Cleanup(srv.Close)
	return &api.Client{URL: srv.URL, Token: "ranz_X", HTTP: srv.Client()}, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// TestTokenListShowsTheLastUseOfEachToken is the second criterion of AUD1-DT-13 (#461): ranz token list, and
// ranz tokens, show when each token was last used, and when it expires; the table has a line for each token.
func TestTokenListShowsTheLastUseOfEachToken(t *testing.T) {
	used := time.Date(2026, 10, 27, 8, 30, 0, 0, time.UTC)
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	c, _ := tokenAPI(t, []rbac.Token{
		{Name: "admin", Role: rbac.Admin, LastUsed: used},
		{Name: "ci", Role: rbac.Operator, Expires: expires, LastUsed: used.Add(-time.Hour)},
		{Name: "old", Role: rbac.Viewer, Expires: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Expired: true},
		{Name: "spare", Role: rbac.Viewer},
	})
	ctx := context.Background()

	// JSON is the answer of the API: the last use of the two tokens that were used, the expiry of the two that have one
	for _, args := range [][]string{{"token", "list"}, {"tokens"}, {"token", "list", "-o", "json"}} {
		var out bytes.Buffer
		if err := do(ctx, c, args, &out); err != nil {
			t.Fatalf("ranz %s: %v", strings.Join(args, " "), err)
		}
		var got api.TokenList
		if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Tokens) != 4 {
			t.Fatalf("ranz %s printed %q, %v, want the four tokens", strings.Join(args, " "), out.String(), err)
		}
		if !got.Tokens[0].LastUsed.Equal(used) || !got.Tokens[1].LastUsed.Equal(used.Add(-time.Hour)) || !got.Tokens[1].Expires.Equal(expires) ||
			!got.Tokens[2].Expired || !got.Tokens[3].LastUsed.IsZero() || !got.Tokens[3].Expires.IsZero() {
			t.Errorf("ranz %s printed the tokens %+v, want their expiry and last use as the API gave them", strings.Join(args, " "), got.Tokens)
		}
		if n := strings.Count(out.String(), `"lastUsed"`); n != 2 {
			t.Errorf("ranz %s printed %d last uses, want one for each of the two tokens that were used:\n%s", strings.Join(args, " "), n, out.String())
		}
	}

	// The table has the name, the role, when it expires and when it was last used, and "never" for what has none
	want := [][]string{
		{"NAME", "ROLE", "EXPIRES", "LAST", "USED"},
		{"admin", "admin", "never", "2026-10-27T08:30:00Z"},
		{"ci", "operator", "2026-12-31T23:59:59Z", "2026-10-27T07:30:00Z"},
		{"old", "viewer", "2026-10-01T00:00:00Z", "(expired)", "never"},
		{"spare", "viewer", "never", "never"},
	}
	for _, args := range [][]string{{"token", "list", "-o", "table"}, {"tokens", "-o", "table"}} {
		var out bytes.Buffer
		if err := do(ctx, c, args, &out); err != nil {
			t.Fatalf("ranz %s: %v", strings.Join(args, " "), err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != len(want) {
			t.Fatalf("ranz %s printed %d lines, want %d:\n%s", strings.Join(args, " "), len(lines), len(want), out.String())
		}
		for i, line := range lines {
			if fields := strings.Fields(line); !reflect.DeepEqual(fields, want[i]) {
				t.Errorf("ranz %s: line %d is %q, want the fields %q", strings.Join(args, " "), i+1, fields, want[i])
			}
		}
	}

	// A controller that answers with an error is told as it answers
	elsewhere := &api.Client{URL: c.URL + "/none", Token: c.Token, HTTP: c.HTTP}
	var refused *api.Error
	if err := do(ctx, elsewhere, []string{"tokens"}, io.Discard); !errors.As(err, &refused) || refused.Status != http.StatusNotFound {
		t.Errorf("ranz tokens against a call that is not there gave %v, want 404", err)
	}
}

// The token commands print the usage for what they do not take.
func TestTokenCommandsUsage(t *testing.T) {
	for _, args := range [][]string{
		{"token"},
		{"token", "unknown"},
		{"token", "list", "extra"},
		{"token", "list", "-o", "xml"},
		{"token", "list", "-bogus"},
		{"tokens", "extra"},
		{"tokens", "list"},
		{"token", "create"},
		{"token", "create", "-role", "viewer"},
		{"token", "create", "-role", "viewer", "a", "b"},
		{"token", "create", "a"},
		{"token", "delete"},
		{"token", "delete", "a", "b"},
	} {
		if err := do(context.Background(), &api.Client{}, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}

// A token is made with the expiry that -expires names, an RFC 3339 time or a time from now; with none it is made
// with no expiry; an expiry that is neither is refused before any call is made. A delete prints the token that
// was deleted, expired or not.
func TestTokenCreateTakesAnExpiry(t *testing.T) {
	c, bodies := tokenAPI(t, nil)
	ctx := context.Background()
	create := func(args ...string) error {
		var out bytes.Buffer
		err := do(ctx, c, append([]string{"token", "create"}, args...), &out)
		if err == nil && !strings.Contains(out.String(), "ranz_NEW") {
			t.Errorf("ranz token create %s printed %q, want the answer with the secret", strings.Join(args, " "), out.String())
		}
		return err
	}
	request := func(i int) api.TokenRequest {
		t.Helper()
		all := bodies()
		if len(all) <= i {
			t.Fatalf("the server got %d requests, want one more", len(all))
		}
		var req api.TokenRequest
		if err := json.Unmarshal([]byte(all[i]), &req); err != nil {
			t.Fatalf("the body %q: %v", all[i], err)
		}
		return req
	}

	at := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	if err := create("-role", "operator", "-expires", "2026-12-31T23:59:59Z", "ci"); err != nil {
		t.Fatal(err)
	}
	if req := request(0); req.Name != "ci" || req.Role != rbac.Operator || !req.Expires.Equal(at) {
		t.Errorf("a token with an RFC 3339 expiry asked for %+v, want ci, an operator's, that expires at %v", req, at)
	}

	before := time.Now()
	if err := create("-role", "viewer", "-expires", "720h", "ci"); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	if req := request(1); req.Expires.Before(before.Add(720*time.Hour)) || req.Expires.After(after.Add(720*time.Hour)) {
		t.Errorf("a token with the expiry 720h asked for %v, want a time between %v and %v", req.Expires, before.Add(720*time.Hour), after.Add(720*time.Hour))
	}

	if err := create("-role", "viewer", "ci"); err != nil {
		t.Fatal(err)
	}
	if all := bodies(); strings.Contains(all[2], "expires") {
		t.Errorf("a token with no expiry asked for %s, want no expires", all[2])
	}

	for _, bad := range []string{"tomorrow", "2026-12-31", "0s", "-5m", "720"} {
		err := create("-role", "viewer", "-expires", bad, "ci")
		if err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), "-expires") {
			t.Errorf("-expires %s gave %v, want a refusal that names the flag", bad, err)
		}
	}
	if n := len(bodies()); n != 3 {
		t.Errorf("the server got %d requests, want the 3 that were valid", n)
	}

	var out bytes.Buffer
	if err := do(ctx, c, []string{"token", "delete", "old"}, &out); err != nil || !strings.Contains(out.String(), `"expired": true`) {
		t.Errorf("deleting an expired token printed %q, %v, want the token and that it is expired", out.String(), err)
	}
}
