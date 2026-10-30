package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// Every call under /api/v1/self needs the role Self, the least role there is, whatever its method, and no
// path that only looks like it does: TestRegisteredRolesMatchNeeds holds the routes to the same answer.
func TestSelfCallsNeedTheSelfRole(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         rbac.Role
	}{
		{http.MethodGet, "/api/v1/self", rbac.Self},
		{http.MethodGet, "/api/v1/self/devices", rbac.Self},
		{http.MethodPost, "/api/v1/self/devices", rbac.Self},
		{http.MethodDelete, "/api/v1/self/devices/Node/alice-1", rbac.Self},
		{http.MethodGet, "/api/v1/self/join-tokens", rbac.Self},
		{http.MethodPost, "/api/v1/self/join-tokens", rbac.Self},
		{http.MethodDelete, "/api/v1/self/join-tokens/0123456789abcdef", rbac.Self},
		{http.MethodGet, "/api/v1/self/", rbac.Self},
		{http.MethodGet, "//api/v1//self/devices", rbac.Self},
		{http.MethodGet, "/api/v1/self/../tokens", rbac.Admin},
		{http.MethodGet, "/api/v1/self/../whoami", rbac.Viewer},
		{http.MethodGet, "/api/v1/selfish", rbac.Viewer},
		{http.MethodPost, "/api/v1/selfish", rbac.Operator},
		{http.MethodGet, "/api/v1/x/self", rbac.Viewer},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

// A self call is for the User of a token of a login: an API token names none, so every self call refuses it
// with 403 Forbidden before it asks the controller, and the answer names the token.
func TestSelfCallsRefuseAnAPIToken(t *testing.T) {
	found := 0
	for _, rt := range routes {
		if rt.Pattern != selfPath && !strings.HasPrefix(rt.Pattern, selfPath+"/") {
			continue
		}
		found++
		r := httptest.NewRequest(rt.Method, "/api/v1/self", strings.NewReader(`{}`))
		r = r.WithContext(context.WithValue(r.Context(), callerKey{}, rbac.Token{Name: "ops", Role: rbac.Admin}))
		w := httptest.NewRecorder()
		rt.Handle(routeDeps{}, w, r)
		var p Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusForbidden || err != nil || !strings.Contains(p.Error, `"ops"`) ||
			!strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
			t.Errorf("%s %s with an API token: %d %s (%v), want 403 that names the token", rt.Method, rt.Pattern, w.Code, w.Body.Bytes(), err)
		}
	}
	if found != 7 {
		t.Errorf("%d routes are registered under %s, want the 7 of the portal", found, selfPath)
	}
}

// The self calls refuse what is not a call of theirs with 400 Bad Request before they ask the controller: a body
// that is not what they take, and a static key that is none.
func TestSelfCallsRefuseBadBodies(t *testing.T) {
	user := rbac.Token{Name: "user:alice", Role: rbac.Self, User: "alice"}
	for _, c := range []struct{ method, pattern, body, want string }{
		{http.MethodPost, selfPath + "/devices", `{"colour": "red"}`, "the body is not a device"},
		{http.MethodPost, selfPath + "/devices", `not json`, "the body is not a device"},
		{http.MethodPost, selfPath + "/devices", `{"publicKey": 5}`, "the body is not a device"},
		{http.MethodPost, selfPath + "/devices", `{"publicKey": "not base64"}`, "is not the base64"},
		{http.MethodPost, selfPath + "/devices", `{"name": "phone"}`, "is not the base64"},
		{http.MethodPost, selfPath + "/join-tokens", `{"colour": "red"}`, "the body is not a join token request"},
		{http.MethodPost, selfPath + "/join-tokens", `[1]`, "the body is not a join token request"},
	} {
		var handle func(routeDeps, http.ResponseWriter, *http.Request)
		for _, rt := range routes {
			if rt.Method == c.method && rt.Pattern == c.pattern {
				handle = rt.Handle
			}
		}
		if handle == nil {
			t.Fatalf("%s %s is not registered", c.method, c.pattern)
		}
		r := httptest.NewRequest(c.method, "/api/v1/self", strings.NewReader(c.body))
		r = r.WithContext(context.WithValue(r.Context(), callerKey{}, user))
		w := httptest.NewRecorder()
		handle(routeDeps{}, w, r)
		var p Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusBadRequest || err != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("%s %s with %s: %d %s, want 400 Bad Request that says %q", c.method, c.pattern, c.body, w.Code, w.Body.Bytes(), c.want)
		}
	}
}

// The Client makes each self call with the method, the path and the body that the routes expect, and gives the
// answer of the API.
func TestSelfClientCalls(t *testing.T) {
	type call struct{ method, path, body string }
	calls := make(chan call, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.Path, string(body)}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/self":
			reply(w, http.StatusOK, controller.SelfInfo{Name: "alice", Devices: 1})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/self/devices":
			reply(w, http.StatusOK, SelfDeviceList{Devices: []controller.SelfDevice{{Kind: "Node", Name: "alice-1", State: controller.DeviceOffline}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/self/devices":
			reply(w, http.StatusOK, controller.Enrolment{Node: "alice-2", User: "alice", Revision: 7})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/self/devices/"):
			reply(w, http.StatusOK, controller.ApplyResult{Revision: 8})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/self/join-tokens":
			reply(w, http.StatusOK, JoinTokenList{Tokens: []controller.JoinTokenInfo{{ID: "0123456789abcdef", Name: "nas"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/self/join-tokens":
			reply(w, http.StatusOK, controller.NewJoinToken{JoinTokenInfo: controller.JoinTokenInfo{ID: "0123456789abcdef", Name: "nas"}, Token: "ranz_j_SECRET"})
		default:
			reply(w, http.StatusOK, controller.JoinTokenInfo{ID: "0123456789abcdef"})
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_s_secret"}
	ctx := context.Background()
	expect := func(what, method, path, body string) {
		t.Helper()
		if got := <-calls; got != (call{method, path, body}) {
			t.Errorf("%s called %+v, want %+v", what, got, call{method, path, body})
		}
	}

	if info, err := c.Self(ctx); err != nil || info.Name != "alice" || info.Devices != 1 {
		t.Errorf("Self gave %+v, %v", info, err)
	}
	expect("Self", http.MethodGet, "/api/v1/self", "")
	if ds, err := c.SelfDevices(ctx); err != nil || len(ds) != 1 || ds[0].Name != "alice-1" || ds[0].State != controller.DeviceOffline {
		t.Errorf("SelfDevices gave %+v, %v", ds, err)
	}
	expect("SelfDevices", http.MethodGet, "/api/v1/self/devices", "")
	if e, err := c.AddSelfDevice(ctx, "phone", "AAAA"); err != nil || e.Node != "alice-2" || e.Revision != 7 {
		t.Errorf("AddSelfDevice gave %+v, %v", e, err)
	}
	expect("AddSelfDevice", http.MethodPost, "/api/v1/self/devices", `{"publicKey":"AAAA","name":"phone"}`)
	if _, err := c.AddSelfDevice(ctx, "", "AAAA"); err != nil {
		t.Errorf("AddSelfDevice without a name: %v", err)
	}
	expect("AddSelfDevice without a name", http.MethodPost, "/api/v1/self/devices", `{"publicKey":"AAAA"}`)
	if res, err := c.RemoveSelfDevice(ctx, "Node", "alice 2"); err != nil || res.Revision != 8 {
		t.Errorf("RemoveSelfDevice gave %+v, %v", res, err)
	}
	expect("RemoveSelfDevice", http.MethodDelete, "/api/v1/self/devices/Node/alice 2", "")
	if ts, err := c.JoinTokens(ctx); err != nil || len(ts) != 1 || ts[0].Name != "nas" {
		t.Errorf("JoinTokens gave %+v, %v", ts, err)
	}
	expect("JoinTokens", http.MethodGet, "/api/v1/self/join-tokens", "")
	if tok, err := c.MakeJoinToken(ctx, "nas"); err != nil || tok.Token != "ranz_j_SECRET" || tok.Name != "nas" {
		t.Errorf("MakeJoinToken gave %+v, %v", tok, err)
	}
	expect("MakeJoinToken", http.MethodPost, "/api/v1/self/join-tokens", `{"name":"nas"}`)
	if tok, err := c.RevokeJoinToken(ctx, "0123456789abcdef"); err != nil || tok.ID != "0123456789abcdef" {
		t.Errorf("RevokeJoinToken gave %+v, %v", tok, err)
	}
	expect("RevokeJoinToken", http.MethodDelete, "/api/v1/self/join-tokens/0123456789abcdef", "")
}
