package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The Client makes each call of the live operations with the method, the path, the query and the body that
// the routes expect, and gives the answer of the API.
func TestOperationsClientCalls(t *testing.T) {
	type call struct{ method, path, query, body string }
	calls := make(chan call, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(body)}
		switch {
		case strings.HasSuffix(r.URL.Path, "/mac-table"), strings.HasSuffix(r.URL.Path, "/ip-table"):
			reply(w, http.StatusOK, controller.TableResult{Network: "corp-dmz", Table: controller.TableMAC, Nodes: []controller.NodeTable{{Node: "branch-1", Status: controller.TableOK, Total: 1}}})
		case strings.HasSuffix(r.URL.Path, "/disconnect") && strings.Contains(r.URL.Path, "/sessions/b-and-c"):
			reply(w, http.StatusOK, SessionList{Sessions: []controller.Session{{ID: "b"}, {ID: "c"}}})
		case strings.HasSuffix(r.URL.Path, "/disconnect"), r.URL.Path == operationsPath+"/sessions":
			reply(w, http.StatusOK, SessionList{Sessions: []controller.Session{{ID: "0123456789abcdef", Node: "alice-laptop", User: "alice"}}})
		case r.URL.Path == operationsPath+"/bans" && r.Method == http.MethodGet:
			reply(w, http.StatusOK, BanList{Bans: []store.Ban{{User: "alice", By: "token:ops"}}})
		case r.Method == http.MethodPut:
			reply(w, http.StatusOK, controller.BanResult{Ban: store.Ban{User: "alice", Reason: "stolen"}, Disconnected: []controller.Session{{ID: "x"}}})
		default:
			reply(w, http.StatusOK, store.Ban{User: "alice"})
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	ctx := context.Background()
	expect := func(what, method, path, query, body string) {
		t.Helper()
		if got := <-calls; got != (call{method, path, query, body}) {
			t.Errorf("%s called %+v, want %+v", what, got, call{method, path, query, body})
		}
	}

	if l, err := c.Sessions(ctx, "", ""); err != nil || len(l) != 1 || l[0].Node != "alice-laptop" {
		t.Errorf("Sessions gave %+v, %v", l, err)
	}
	expect("Sessions", http.MethodGet, "/api/v1/operations/sessions", "", "")
	if _, err := c.Sessions(ctx, "alice", "files"); err != nil {
		t.Error(err)
	}
	expect("Sessions of a user and a node", http.MethodGet, "/api/v1/operations/sessions", "node=files&user=alice", "")
	if s, err := c.Disconnect(ctx, "0123456789abcdef"); err != nil || s.ID != "0123456789abcdef" || s.User != "alice" {
		t.Errorf("Disconnect gave %+v, %v", s, err)
	}
	expect("Disconnect", http.MethodPost, "/api/v1/operations/sessions/0123456789abcdef/disconnect", "", "")
	if _, err := c.Disconnect(ctx, "a/b"); err != nil {
		t.Error(err)
	}
	expect("Disconnect of an id that needs escaping", http.MethodPost, "/api/v1/operations/sessions/a%2Fb/disconnect", "", "")
	if _, err := c.Disconnect(ctx, "b-and-c"); err == nil {
		t.Error("Disconnect took an answer of two sessions for the one that it asked to end")
	}
	expect("Disconnect with an answer of two sessions", http.MethodPost, "/api/v1/operations/sessions/b-and-c/disconnect", "", "")
	if l, err := c.DisconnectUser(ctx, "alice"); err != nil || len(l) != 1 {
		t.Errorf("DisconnectUser gave %+v, %v", l, err)
	}
	expect("DisconnectUser", http.MethodPost, "/api/v1/operations/users/alice/disconnect", "", "")

	if l, err := c.Bans(ctx); err != nil || len(l) != 1 || l[0].User != "alice" {
		t.Errorf("Bans gave %+v, %v", l, err)
	}
	expect("Bans", http.MethodGet, "/api/v1/operations/bans", "", "")
	if res, err := c.Ban(ctx, "alice", "stolen"); err != nil || res.User != "alice" || res.Reason != "stolen" || len(res.Disconnected) != 1 {
		t.Errorf("Ban gave %+v, %v", res, err)
	}
	expect("Ban", http.MethodPut, "/api/v1/operations/bans/alice", "", `{"reason":"stolen"}`)
	if _, err := c.Ban(ctx, "alice", ""); err != nil {
		t.Error(err)
	}
	expect("Ban with no reason", http.MethodPut, "/api/v1/operations/bans/alice", "", `{}`)
	if ban, err := c.Unban(ctx, "alice"); err != nil || ban.User != "alice" {
		t.Errorf("Unban gave %+v, %v", ban, err)
	}
	expect("Unban", http.MethodDelete, "/api/v1/operations/bans/alice", "", "")

	for _, k := range []struct {
		what, method, path, query string
		do                        func() (controller.TableResult, error)
	}{
		{"MACTable", http.MethodGet, "mac-table", "", func() (controller.TableResult, error) { return c.MACTable(ctx, "corp-dmz", "") }},
		{"MACTable on a node", http.MethodGet, "mac-table", "node=branch-1", func() (controller.TableResult, error) { return c.MACTable(ctx, "corp-dmz", "branch-1") }},
		{"ClearMACTable", http.MethodDelete, "mac-table", "", func() (controller.TableResult, error) { return c.ClearMACTable(ctx, "corp-dmz", "", "") }},
		{"ClearMACTable of one entry", http.MethodDelete, "mac-table", "mac=02%3A00%3A5e%3A10%3A00%3A01&node=branch-1",
			func() (controller.TableResult, error) { return c.ClearMACTable(ctx, "corp-dmz", "branch-1", "02:00:5e:10:00:01") }},
		{"IPTable", http.MethodGet, "ip-table", "", func() (controller.TableResult, error) { return c.IPTable(ctx, "corp-dmz", "") }},
		{"ClearIPTable of one entry", http.MethodDelete, "ip-table", "address=10.20.0.9",
			func() (controller.TableResult, error) { return c.ClearIPTable(ctx, "corp-dmz", "", "10.20.0.9") }},
	} {
		res, err := k.do()
		if err != nil || res.Network != "corp-dmz" || len(res.Nodes) != 1 || res.Nodes[0].Status != controller.TableOK {
			t.Errorf("%s gave %+v, %v", k.what, res, err)
		}
		expect(k.what, k.method, "/api/v1/operations/networks/corp-dmz/"+k.path, k.query, "")
	}
}

// The routes refuse what is not a call of theirs with 400 Bad Request, before they ask the controller: a
// parameter that the call does not take (so that a misspelt narrowing does not widen it), a MAC address or
// an address that is none, and a body that is not a ban.
func TestOperationsRoutesRefuseBadInput(t *testing.T) {
	mux := http.NewServeMux()
	for _, rt := range routes {
		handle := rt.Handle
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
			handle(routeDeps{}, w, r)
		})
	}
	const tables = "/api/v1/operations/networks/corp-dmz/"
	for _, c := range []struct{ name, method, target, body, want string }{
		{"a parameter that sessions do not take", http.MethodGet, "/api/v1/operations/sessions?colour=red", "", `the query has the parameter "colour"`},
		{"a parameter, with what the call takes", http.MethodGet, "/api/v1/operations/sessions?user=alice&nod=files", "", `which this call does not take (it takes: user, node)`},
		{"a parameter that the list of bans does not take", http.MethodGet, "/api/v1/operations/bans?user=alice", "", "(it takes: none)"},
		{"a MAC address on a read", http.MethodGet, tables + "mac-table?mac=02:00:5e:10:00:01", "", `the query has the parameter "mac"`},
		{"an address on a read", http.MethodGet, tables + "ip-table?address=10.0.0.1", "", `the query has the parameter "address"`},
		{"an address on the MAC table", http.MethodDelete, tables + "mac-table?address=10.0.0.1", "", `the query has the parameter "address"`},
		{"a MAC address on the IP table", http.MethodDelete, tables + "ip-table?mac=02:00:5e:10:00:01", "", `the query has the parameter "mac"`},
		{"a MAC address that is none", http.MethodDelete, tables + "mac-table?mac=zz", "", `the mac "zz" is no MAC address of 6 bytes`},
		{"a MAC address of 8 bytes", http.MethodDelete, tables + "mac-table?mac=02:00:5e:10:00:01:02:03", "", "is no MAC address of 6 bytes"},
		{"an address that is none", http.MethodDelete, tables + "ip-table?address=10.0.0", "", `the address "10.0.0" is no IP address`},
		{"a ban with a field that it has not", http.MethodPut, "/api/v1/operations/bans/alice", `{"colour":"red"}`, "the body is not a ban"},
		{"a ban that is no JSON", http.MethodPut, "/api/v1/operations/bans/alice", `not json`, "the body is not a ban"},
		{"a ban with a reason that is no text", http.MethodPut, "/api/v1/operations/bans/alice", `{"reason": 5}`, "the body is not a ban"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(c.method, c.target, strings.NewReader(c.body)))
		var p Problem
		if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &p) != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("%s: the answer is %d %s, want 400 that says %q", c.name, w.Code, w.Body.String(), c.want)
		}
	}
}

// Every call under /api/v1/operations needs the role operator, the reads too, however the path is written,
// and the controller records each of them in the audit log itself, so AuditCalls does not.
func TestOperationsNeedTheOperatorAndAreAuditedByTheController(t *testing.T) {
	seg := regexp.MustCompile(`\{[^}]*\}`)
	found := 0
	for _, rt := range routes {
		if !strings.HasPrefix(rt.Pattern, operationsPath+"/") {
			continue
		}
		found++
		concrete := seg.ReplaceAllString(rt.Pattern, "x")
		if got := Needs(rt.Method, concrete); got != rbac.Operator || rt.Role != rbac.Operator {
			t.Errorf("%s %s needs %s and is registered for %s, want operator", rt.Method, rt.Pattern, got, rt.Role)
		}
		if !selfAudited(concrete) {
			t.Errorf("%s %s is not self-audited: AuditCalls would record it a second time", rt.Method, rt.Pattern)
		}
	}
	if found != 10 {
		t.Errorf("%d routes are registered under %s, want the 10 that the operations have", found, operationsPath)
	}
	for _, c := range []struct {
		method, path string
		want         rbac.Role
		self         bool
	}{
		{http.MethodGet, "/api/v1/operations/sessions", rbac.Operator, true},
		{http.MethodGet, "/api/v1/operations", rbac.Operator, false},
		{http.MethodGet, "/api/v1/operations/anything/new", rbac.Operator, true},
		{http.MethodHead, "/api/v1/operations/bans", rbac.Operator, true},
		{http.MethodGet, "//api/v1//operations/bans", rbac.Operator, true},
		{http.MethodGet, "/api/v1/x/../operations/bans", rbac.Operator, true},
		{http.MethodGet, "/api/v1/operations/../status", rbac.Viewer, false},
		{http.MethodGet, "/api/v1/operationsx", rbac.Viewer, false},
		{http.MethodGet, "/api/v1/users", rbac.Viewer, false},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
		if got := selfAudited(c.path); got != c.self {
			t.Errorf("%s is self-audited: %v, want %v", c.path, got, c.self)
		}
	}

	// A call under /api/v1/operations carries its origin to the controller and is no record of AuditCalls, whatever
	// its outcome; a call elsewhere that changes something still is
	for _, c := range []struct {
		method, target string
		status         int
		recorded       bool
	}{
		{http.MethodPut, "/api/v1/operations/bans/alice", http.StatusOK, false},
		{http.MethodPost, "/api/v1/operations/sessions/0123456789abcdef/disconnect", http.StatusNotFound, false},
		{http.MethodDelete, "/api/v1/operations/networks/corp-dmz/mac-table", http.StatusBadRequest, false},
		{http.MethodGet, "/api/v1/operations/sessions", http.StatusOK, false},
		{http.MethodPut, "/api/v1/targets/slack", http.StatusOK, true},
	} {
		f := &fakeAuditor{}
		var seen audit.Origin
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = audit.FromContext(r.Context())
			w.WriteHeader(c.status)
		})
		req := httptest.NewRequest(c.method, c.target, nil)
		req.RemoteAddr = "192.0.2.7:51234"
		req = req.WithContext(context.WithValue(req.Context(), callerKey{}, rbac.Token{Name: "ci", Role: rbac.Operator}))
		AuditCalls(f, inner).ServeHTTP(httptest.NewRecorder(), req)
		if want := (audit.Origin{Actor: "token:ci", Source: "192.0.2.7"}); seen != want {
			t.Errorf("%s %s: the call carried the origin %+v, want %+v", c.method, c.target, seen, want)
		}
		if (len(f.recs) == 1) != c.recorded || len(f.recs) > 1 {
			t.Errorf("%s %s answered %d: AuditCalls recorded %+v, want a record: %v", c.method, c.target, c.status, f.recs, c.recorded)
		}
	}
}
