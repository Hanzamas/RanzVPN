package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// Every call of the API needs a role: admin for the tokens and the admin source allowlist, viewer
// for any other read, and operator for any other change, also for an endpoint that has no rule of
// its own.
func TestNeeds(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         rbac.Role
	}{
		{http.MethodGet, "/api/v1/status", rbac.Viewer},
		{http.MethodGet, "/api/v1/whoami", rbac.Viewer},
		{http.MethodGet, "/api/v1/resources", rbac.Viewer},
		{http.MethodGet, "/api/v1/nodes", rbac.Viewer},
		{http.MethodHead, "/api/v1/nodes", rbac.Viewer},
		{http.MethodPost, "/api/v1/apply", rbac.Operator},
		{http.MethodDelete, "/api/v1/resources/VRF/corp", rbac.Operator},
		{http.MethodGet, "/api/v1/revisions", rbac.Viewer},
		{http.MethodGet, "/api/v1/revisions/2", rbac.Viewer},
		{http.MethodGet, "/api/v1/diff", rbac.Viewer},
		{http.MethodGet, "/api/v1/events", rbac.Viewer},
		{http.MethodPost, "/api/v1/revisions/2/confirm", rbac.Operator},
		{http.MethodPost, "/api/v1/rollback", rbac.Operator},
		{http.MethodGet, "/api/v1/licence", rbac.Viewer},
		{http.MethodPut, "/api/v1/licence", rbac.Operator},
		{http.MethodDelete, "/api/v1/licence", rbac.Operator},
		{http.MethodPut, "/api/v1/not-yet", rbac.Operator},
		{http.MethodGet, "/api/v1/tokens", rbac.Admin},
		{http.MethodPost, "/api/v1/tokens", rbac.Admin},
		{http.MethodDelete, "/api/v1/tokens/ci", rbac.Admin},
		{http.MethodGet, "/api/v1/tokens/", rbac.Admin},
		{http.MethodGet, "/api/v1/x/../tokens", rbac.Admin},
		{http.MethodGet, "//api/v1//tokens", rbac.Admin},
		{http.MethodGet, "/api/v1/tokensx", rbac.Viewer},
		{http.MethodGet, "/api/v1/admin-sources", rbac.Admin},
		{http.MethodPut, "/api/v1/admin-sources", rbac.Admin},
		{http.MethodGet, "/api/v1/admin-sources/", rbac.Admin},
		{http.MethodGet, "/api/v1/admin-sourcesx", rbac.Viewer},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestBearer(t *testing.T) {
	for _, c := range []struct {
		header string
		token  string
		ok     bool
	}{
		{"Bearer ranz_abc", "ranz_abc", true},
		{"bearer ranz_abc", "ranz_abc", true},
		{"Bearer  ranz_abc ", "ranz_abc", true},
		{"Bearer ", "", false},
		{"Basic dXNlcjpwYXNz", "", false},
		{"", "", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://ctl.example/api/v1/status", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		token, ok := bearer(r)
		if ok != c.ok || (ok && token != c.token) {
			t.Errorf("Authorization %q gave %q, %v; want %q, %v", c.header, token, ok, c.token, c.ok)
		}
	}
}

func TestNewClientTrustsOnlyLoopbackWithoutChecking(t *testing.T) {
	for _, c := range []struct {
		url      string
		insecure bool
	}{
		{"https://127.0.0.1", true},
		{"https://[::1]:7443", true},
		{"https://localhost", true},
		{"https://ctl.example", false},
		{"http://127.0.0.1:7080", false},
	} {
		cl := NewClient(c.url)
		got := cl.HTTP != nil
		if got != c.insecure {
			t.Errorf("%s: skips the certificate check %v, want %v", c.url, got, c.insecure)
		}
	}
}

// A pinned client accepts the certificate with the fingerprint it was given and no other, and
// sends its token. The test server's certificate comes from a CA that no client trusts, so only
// the pin lets it pass.
func TestPin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ranz_secret" {
			reply(w, http.StatusUnauthorized, Problem{Error: "no token"})
			return
		}
		reply(w, http.StatusOK, rbac.Token{Name: "ci", Role: rbac.Viewer})
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	right := hex.EncodeToString(sum[:])

	if _, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).Whoami(context.Background()); err == nil {
		t.Fatal("a client without the pin accepted the test certificate")
	}
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	if err := c.Pin(strings.ToUpper(right)); err != nil {
		t.Fatal(err)
	}
	tok, err := c.Whoami(context.Background())
	if err != nil {
		t.Fatalf("with the right fingerprint: %v", err)
	}
	if tok.Name != "ci" || tok.Role != rbac.Viewer {
		t.Errorf("whoami gave %+v", tok)
	}

	wrong := &Client{URL: srv.URL, Token: "ranz_secret"}
	if err := wrong.Pin(strings.Repeat("00", sha256.Size)); err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Whoami(context.Background()); err == nil || !strings.Contains(err.Error(), "TLS fingerprint") {
		t.Errorf("with a wrong fingerprint: %v, want a refusal of the certificate", err)
	}
	for _, bad := range []string{"", "xyz", "00"} {
		if err := (&Client{}).Pin(bad); err == nil {
			t.Errorf("Pin(%q) took a fingerprint that is not a SHA-256", bad)
		}
	}
}
