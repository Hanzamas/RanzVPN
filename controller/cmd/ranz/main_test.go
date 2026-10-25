package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// lab is an intent document with a VRF that no node joins, so applying and deleting it changes
// no node and gives the same answer each time.
const lab = `{"resources": [{"kind": "VRF", "name": "lab", "spec": {"id": 99, "ula": "fd99:1:2::/48"}}]}`

// labs is lab and a second VRF that no node joins, neither of them with a route target, so
// connecting them (SDN-7) gives the same answer each time.
const labs = `{"resources": [{"kind": "VRF", "name": "lab", "spec": {"id": 99, "ula": "fd99:1:2::/48"}},
  {"kind": "VRF", "name": "lab-2", "spec": {"id": 98, "ula": "fd98:1:2::/48"}}]}`

// TestCLIGetsTheSameAnswersAsTheAPI is the second criterion of SDN-14 (#190): every command of
// ranz, run with each role and with no token, gets the answer that the same call made directly
// over HTTP gets: the same JSON when the call is allowed, the same status and error when it is
// refused. The roles live in the API only, so no client can answer differently.
func TestCLIGetsTheSameAnswersAsTheAPI(t *testing.T) {
	ctx := context.Background()
	srv, tokens, admin := startController(t)
	dir := t.TempDir()
	labFile := filepath.Join(dir, "lab.json")
	if err := os.WriteFile(labFile, []byte(lab), 0o600); err != nil {
		t.Fatal(err)
	}
	adminClient := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}

	calls := []struct {
		args         []string
		method, path string
		body         string
		setup        func() // with the admin token, before the command and before the direct call
	}{
		{[]string{"status"}, http.MethodGet, "/api/v1/status", "", nil},
		{[]string{"whoami"}, http.MethodGet, "/api/v1/whoami", "", nil},
		{[]string{"get", "resources"}, http.MethodGet, "/api/v1/resources", "", nil},
		{[]string{"get", "nodes"}, http.MethodGet, "/api/v1/nodes", "", nil},
		{[]string{"apply", "-f", labFile}, http.MethodPost, "/api/v1/apply", lab, nil},
		{[]string{"delete", "VRF", "lab"}, http.MethodDelete, "/api/v1/resources/VRF/lab", "", func() {
			if _, err := adminClient.Apply(ctx, mustDocument(t, lab)); err != nil {
				t.Fatal(err)
			}
		}},
		{[]string{"connect", "vrf", "lab", "lab-2"}, http.MethodPost, "/api/v1/connect", `{"vrfs": ["lab", "lab-2"]}`, func() {
			if _, err := adminClient.Apply(ctx, mustDocument(t, labs)); err != nil {
				t.Fatal(err)
			}
		}},
		{[]string{"export"}, http.MethodGet, "/api/v1/export", "", nil},
		{[]string{"import", "-f", labFile}, http.MethodPost, "/api/v1/import", lab, nil},
		{[]string{"rollback", "0"}, http.MethodPost, "/api/v1/rollback", `{"revision": 0}`, nil},
		{[]string{"get", "revisions"}, http.MethodGet, "/api/v1/revisions", "", nil},
		{[]string{"get", "revision", "1"}, http.MethodGet, "/api/v1/revisions/1", "", nil},
		{[]string{"diff"}, http.MethodGet, "/api/v1/diff", "", nil},
		{[]string{"get", "events"}, http.MethodGet, "/api/v1/events", "", nil},
		{[]string{"admin-sources", "list"}, http.MethodGet, "/api/v1/admin-sources", "", nil},
		{[]string{"admin-sources", "set", "192.0.2.0/24", "2001:db8::10"}, http.MethodPut, "/api/v1/admin-sources", `{"prefixes": ["192.0.2.0/24", "2001:db8::10"]}`, nil},
		{[]string{"admin-sources", "clear"}, http.MethodPut, "/api/v1/admin-sources", `{"prefixes": []}`, nil},
		{[]string{"get", "ipam"}, http.MethodGet, "/api/v1/ipam", "", nil},
		{[]string{"get", "leases"}, http.MethodGet, "/api/v1/ipam/leases", "", nil},
		{[]string{"get", "devices"}, http.MethodGet, "/api/v1/devices", "", nil},
		{[]string{"get", "licence"}, http.MethodGet, "/api/v1/licence", "", nil},
		{[]string{"licence", "-remove"}, http.MethodDelete, "/api/v1/licence", "", nil},
		{[]string{"token", "list"}, http.MethodGet, "/api/v1/tokens", "", nil},
		{[]string{"token", "create", "-role", "viewer", "spare"}, http.MethodPost, "/api/v1/tokens", `{"name": "spare", "role": "viewer"}`, func() {
			if _, err := tokens.Delete(ctx, "spare"); err != nil && !errors.Is(err, rbac.ErrNotFound) {
				t.Fatal(err)
			}
		}},
		{[]string{"token", "delete", "spare"}, http.MethodDelete, "/api/v1/tokens/spare", "", func() {
			if _, err := tokens.Delete(ctx, "spare"); err != nil && !errors.Is(err, rbac.ErrNotFound) {
				t.Fatal(err)
			}
			if _, err := tokens.Create(ctx, "spare", rbac.Operator); err != nil {
				t.Fatal(err)
			}
		}},
	}
	callers := []struct {
		name   string
		secret string
	}{
		{"no token", ""},
		{"viewer", createToken(t, tokens, "viewer-1", rbac.Viewer)},
		{"operator", createToken(t, tokens, "operator-1", rbac.Operator)},
		{"admin", admin},
	}
	for _, who := range callers {
		tokenFile := ""
		if who.secret != "" {
			tokenFile = filepath.Join(dir, who.name+".token")
			if err := os.WriteFile(tokenFile, []byte(who.secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cli, err := newClient(srv.URL, tokenFile, "", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range calls {
			name := who.name + ": ranz " + strings.Join(call.args, " ")
			if call.setup != nil {
				call.setup()
			}
			var out bytes.Buffer
			cliErr := do(ctx, cli, call.args, &out)

			if call.setup != nil {
				call.setup()
			}
			code, body := direct(t, srv, who.secret, call.method, call.path, call.body)
			if who.name == "admin" && code != http.StatusOK {
				t.Errorf("%s: the direct call answered %d for the admin: %s", name, code, body)
			}
			if code == http.StatusOK {
				if cliErr != nil {
					t.Errorf("%s: %v, but the direct call answered 200", name, cliErr)
					continue
				}
				if got, want := answer(t, out.Bytes()), answer(t, body); !reflect.DeepEqual(got, want) {
					t.Errorf("%s: printed\n%s\nbut the direct call answered\n%s", name, out.Bytes(), body)
				}
				continue
			}
			var p api.Problem
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatalf("%s: the direct call answered %d with %q", name, code, body)
			}
			var e *api.Error
			if !errors.As(cliErr, &e) || e.Status != code || e.Message != p.Error {
				t.Errorf("%s: %v, but the direct call answered %d %q", name, cliErr, code, p.Error)
				continue
			}
			t.Logf("%s: %d %s", name, code, p.Error)
		}
	}
}

// A token file wins over RANZ_TOKEN, and its line end does not count.
func TestNewClientToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(file, []byte("ranz_FROMFILE\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file, env, want string
	}{
		{"", "ranz_FROMENV", "ranz_FROMENV"},
		{file, "ranz_FROMENV", "ranz_FROMFILE"},
		{"", "", ""},
	} {
		cl, err := newClient("https://127.0.0.1", c.file, c.env, "")
		if err != nil {
			t.Fatal(err)
		}
		if cl.Token != c.want {
			t.Errorf("file %q, RANZ_TOKEN %q: the token is %q, want %q", c.file, c.env, cl.Token, c.want)
		}
	}
	if _, err := newClient("https://127.0.0.1", filepath.Join(t.TempDir(), "none"), "", ""); err == nil {
		t.Error("a missing token file was not an error")
	}
	if _, err := newClient("https://127.0.0.1", "", "", "not hex"); err == nil {
		t.Error("a TLS fingerprint that is not hex was not an error")
	}
}

// The admin-sources commands take the arguments they can and print the usage for the others: no
// subcommand, a set with no prefix (clear says what it does), and a command with more than it
// takes.
func TestAdminSourcesUsage(t *testing.T) {
	for _, args := range [][]string{
		{"admin-sources"},
		{"admin-sources", "set"},
		{"admin-sources", "unknown"},
		{"admin-sources", "list", "extra"},
		{"admin-sources", "clear", "extra"},
	} {
		if err := do(context.Background(), &api.Client{}, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}

// startController runs a controller on its own rqlite with its API on a TLS test server, and
// returns the server, the controller's tokens and the secret of its admin token.
func startController(t *testing.T) (*httptest.Server, *rbac.Tokens, string) {
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
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { admin = s; return nil }); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(api.Handler(c, tokens, api.Status{ControlAddress: "127.0.0.1:443"}))
	t.Cleanup(srv.Close)
	return srv, tokens, admin
}

func createToken(t *testing.T, tokens *rbac.Tokens, name string, role rbac.Role) string {
	t.Helper()
	tok, err := tokens.Create(context.Background(), name, role)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Secret
}

// direct makes a call of the API over HTTP, as any client would, and returns the status and the
// body of the answer.
func direct(t *testing.T, srv *httptest.Server, secret, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// answer decodes the JSON answer b, with the secret of a created token replaced, since each
// creation draws a new one, and the revision of a change of the intent, since each change makes
// the next one.
func answer(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["token"].(string); ok && strings.HasPrefix(s, "ranz_") {
			m["token"] = "a new secret"
		}
		if _, ok := m["revision"].(float64); ok {
			m["revision"] = "the next revision"
		}
	}
	return v
}

func mustDocument(t *testing.T, s string) intent.Document {
	t.Helper()
	var doc intent.Document
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
