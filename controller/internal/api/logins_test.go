package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The paths of the logins go to the logins in front of the Guard, and every other path, one that only
// starts with the same letters or leaves the logins with .. included, goes to the API behind it.
func TestWithLoginsSendsOnlyTheLoginsPastTheGuard(t *testing.T) {
	logins := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	h := WithLogins(logins, guarded)
	for target, want := range map[string]int{
		"/api/v1/login":                 http.StatusTeapot,
		"/api/v1/login/token":           http.StatusTeapot,
		"/api/v1/login/device/code":     http.StatusTeapot,
		"/api/v1/logins":                http.StatusUnauthorized,
		"/api/v1/login/../tokens":       http.StatusUnauthorized,
		"/api/v1/tokens":                http.StatusUnauthorized,
		"/api/v1/whoami?next=/api/v1/l": http.StatusUnauthorized,
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "http://controller.example/", nil)
		r.URL.Path = target
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s went to %d, want %d", target, w.Code, want)
		}
	}
}

// The calls of the API roles of users need admin, as everything under /api/v1/tokens does, and the
// Client makes each with the method, the path and the body that the routes expect.
func TestUserRoleCalls(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tokens/users"},
		{http.MethodPut, "/api/v1/tokens/users/alice"},
		{http.MethodDelete, "/api/v1/tokens/users/alice"},
	} {
		if got := Needs(c.method, c.path); got != rbac.Admin {
			t.Errorf("%s %s needs %s, want admin", c.method, c.path, got)
		}
	}
	type call struct{ method, path, body string }
	calls := make(chan call, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.Path, string(body)}
		if r.Method == http.MethodGet {
			reply(w, http.StatusOK, UserRoleList{Roles: []rbac.UserRole{{User: "alice", Role: rbac.Operator}}})
			return
		}
		reply(w, http.StatusOK, rbac.UserRole{User: "alice", Role: rbac.Operator})
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
	if rs, err := c.UserRoles(ctx); err != nil || len(rs) != 1 || rs[0].User != "alice" {
		t.Errorf("UserRoles gave %+v, %v", rs, err)
	}
	expect("UserRoles", http.MethodGet, "/api/v1/tokens/users", "")
	if ur, err := c.SetUserRole(ctx, "alice", rbac.Operator); err != nil || ur.Role != rbac.Operator {
		t.Errorf("SetUserRole gave %+v, %v", ur, err)
	}
	expect("SetUserRole", http.MethodPut, "/api/v1/tokens/users/alice", `{"role":"operator"}`)
	if ur, err := c.DeleteUserRole(ctx, "alice"); err != nil || ur.User != "alice" {
		t.Errorf("DeleteUserRole gave %+v, %v", ur, err)
	}
	expect("DeleteUserRole", http.MethodDelete, "/api/v1/tokens/users/alice", "")
}
