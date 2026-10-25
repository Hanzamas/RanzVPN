package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The Client makes each call of the users and the groups with the method, the path and the body that
// the routes expect, and gives the answer of the API.
func TestUsersClientCalls(t *testing.T) {
	type call struct{ method, path, body string }
	calls := make(chan call, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.Path, string(body)}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users":
			reply(w, http.StatusOK, UserList{Users: []controller.UserInfo{{Name: "alice", HasPassword: true}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/groups":
			reply(w, http.StatusOK, GroupList{Groups: []controller.GroupInfo{{Name: "staff", Members: []string{"alice"}}}})
		case strings.HasSuffix(r.URL.Path, "/password"):
			reply(w, http.StatusOK, PasswordResult{User: "alice", Set: true})
		default:
			reply(w, http.StatusOK, controller.ApplyResult{Revision: 7})
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	ctx := context.Background()
	expect := func(what, method, path, body string) {
		t.Helper()
		if got := <-calls; got != (call{method, path, body}) {
			t.Errorf("%s called %+v, want %+v", what, got, call{method, path, body})
		}
	}

	users, err := c.Users(ctx)
	if err != nil || len(users) != 1 || users[0].Name != "alice" || !users[0].HasPassword {
		t.Errorf("Users gave %+v, %v", users, err)
	}
	expect("Users", http.MethodGet, "/api/v1/users", "")
	groups, err := c.Groups(ctx)
	if err != nil || len(groups) != 1 || groups[0].Name != "staff" || len(groups[0].Members) != 1 {
		t.Errorf("Groups gave %+v, %v", groups, err)
	}
	expect("Groups", http.MethodGet, "/api/v1/groups", "")

	user := intent.User{DisplayName: "Alice", Groups: []string{"staff"}, Expires: time.Date(2031, time.January, 2, 3, 4, 5, 0, time.UTC), MaxDevices: 2}
	if res, err := c.PutUser(ctx, "alice", user); err != nil || res.Revision != 7 {
		t.Errorf("PutUser gave %+v, %v", res, err)
	}
	expect("PutUser", http.MethodPut, "/api/v1/users/alice", `{"displayName":"Alice","groups":["staff"],"expires":"2031-01-02T03:04:05Z","maxDevices":2}`)
	if res, err := c.DeleteUser(ctx, "alice"); err != nil || res.Revision != 7 {
		t.Errorf("DeleteUser gave %+v, %v", res, err)
	}
	expect("DeleteUser", http.MethodDelete, "/api/v1/users/alice", "")
	if res, err := c.SetUserPassword(ctx, "alice", "a good password"); err != nil || res.User != "alice" || !res.Set {
		t.Errorf("SetUserPassword gave %+v, %v", res, err)
	}
	expect("SetUserPassword", http.MethodPut, "/api/v1/users/alice/password", `{"password":"a good password"}`)
	if res, err := c.PutGroup(ctx, "staff", intent.Group{DisplayName: "Staff"}); err != nil || res.Revision != 7 {
		t.Errorf("PutGroup gave %+v, %v", res, err)
	}
	expect("PutGroup", http.MethodPut, "/api/v1/groups/staff", `{"displayName":"Staff"}`)
	if res, err := c.DeleteGroup(ctx, "staff"); err != nil || res.Revision != 7 {
		t.Errorf("DeleteGroup gave %+v, %v", res, err)
	}
	expect("DeleteGroup", http.MethodDelete, "/api/v1/groups/staff", "")
}

// The routes refuse a body that is not what they take with 400 Bad Request, before they ask the
// controller, so the password of a request that does not parse is never looked at.
func TestUsersRoutesRefuseBadBodies(t *testing.T) {
	find := func(method, pattern string) func(routeDeps, http.ResponseWriter, *http.Request) {
		t.Helper()
		for _, rt := range routes {
			if rt.Method == method && rt.Pattern == pattern {
				return rt.Handle
			}
		}
		t.Fatalf("%s %s is not registered", method, pattern)
		return nil
	}
	for _, c := range []struct {
		method  string
		pattern string
		body    string
		want    string
	}{
		{http.MethodPut, "/api/v1/users/{name}", `{"colour": "red"}`, "the body is not a user"},
		{http.MethodPut, "/api/v1/users/{name}", `{"maxDevices": -1}`, "the body is not a user"},
		{http.MethodPut, "/api/v1/users/{name}", `not json`, "the body is not a user"},
		{http.MethodPut, "/api/v1/users/{name}/password", `{"secret": "a good password"}`, "the body is not a password"},
		{http.MethodPut, "/api/v1/users/{name}/password", `"a good password"`, "the body is not a password"},
		{http.MethodPut, "/api/v1/groups/{name}", `{"displayName": 5}`, "the body is not a group"},
	} {
		w := httptest.NewRecorder()
		find(c.method, c.pattern)(routeDeps{}, w, httptest.NewRequest(c.method, "/api/v1/x", strings.NewReader(c.body)))
		var p Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusBadRequest || err != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("%s %s with %s: %d %s, want 400 Bad Request that says %q", c.method, c.pattern, c.body, w.Code, w.Body.Bytes(), c.want)
		}
		if strings.Contains(w.Body.String(), "a good password") {
			t.Errorf("%s %s answered with the password: %s", c.method, c.pattern, w.Body.Bytes())
		}
	}
}

// Reading the users and the groups needs the role viewer, as every read does, and every change of them
// and of a password needs operator.
func TestUsersRoutesNeedTheirRoles(t *testing.T) {
	for _, c := range []struct {
		method string
		path   string
		want   rbac.Role
	}{
		{http.MethodGet, "/api/v1/users", rbac.Viewer},
		{http.MethodGet, "/api/v1/groups", rbac.Viewer},
		{http.MethodPut, "/api/v1/users/alice", rbac.Operator},
		{http.MethodDelete, "/api/v1/users/alice", rbac.Operator},
		{http.MethodPut, "/api/v1/users/alice/password", rbac.Operator},
		{http.MethodPut, "/api/v1/groups/staff", rbac.Operator},
		{http.MethodDelete, "/api/v1/groups/staff", rbac.Operator},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
	}
}
