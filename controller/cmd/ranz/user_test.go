package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// userDecode decodes the JSON that a command printed.
func userDecode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return v
}

// TestUserAndGroupCommands runs the commands of the users and the groups (SDN-31, #225) against a
// controller: a group and a user are made, listed and changed one field at a time, the password comes
// from a file, and a delete takes each away. What a flag leaves out keeps its value.
func TestUserAndGroupCommands(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	run := func(args ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := do(ctx, cli, args, &out); err != nil {
			t.Fatalf("ranz %s: %v", strings.Join(args, " "), err)
		}
		return out.Bytes()
	}
	listed := func() api.UserList {
		t.Helper()
		return userDecode[api.UserList](t, run("user", "list"))
	}

	run("group", "set", "-display", "Staff", "staff")
	run("group", "set", "-display", "Operations", "ops")
	groups := userDecode[api.GroupList](t, run("group", "list")).Groups
	if len(groups) != 2 || groups[0].Name != "ops" || groups[0].DisplayName != "Operations" || groups[1].Name != "staff" || groups[1].DisplayName != "Staff" {
		t.Errorf("the groups are %+v, want ops and staff with their display names", groups)
	}
	run("group", "set", "ops")
	if again := userDecode[api.GroupList](t, run("group", "list")).Groups; len(again) != 2 || again[0].DisplayName != "Operations" {
		t.Errorf("the groups are %+v after ops was set again with no flag, want its display name kept", again)
	}

	run("user", "set", "-display", "Alice", "-groups", "staff, ops", "-expires", "2031-01-02T03:04:05Z", "-max-devices", "2", "-no-saved-password", "alice")
	expires := time.Date(2031, time.January, 2, 3, 4, 5, 0, time.UTC)
	users := listed().Users
	if len(users) != 1 {
		t.Fatalf("the users are %+v, want alice alone", users)
	}
	if u := users[0]; u.Name != "alice" || u.DisplayName != "Alice" || !slices.Equal(u.Groups, []string{"ops", "staff"}) || !u.Expires.Equal(expires) || u.MaxDevices != 2 ||
		!u.NoSavedPassword || !u.CanChangePassword() || u.HasPassword {
		t.Errorf("alice is %+v", u)
	}
	if gs := userDecode[api.GroupList](t, run("group", "list")).Groups; !slices.Equal(gs[0].Members, []string{"alice"}) || !slices.Equal(gs[1].Members, []string{"alice"}) {
		t.Errorf("the members of the groups are %+v, want alice in both", gs)
	}

	// One flag changes one field
	run("user", "set", "-max-devices", "3", "alice")
	if u := listed().Users[0]; u.MaxDevices != 3 || u.DisplayName != "Alice" || len(u.Groups) != 2 || !u.Expires.Equal(expires) || !u.NoSavedPassword {
		t.Errorf("alice after -max-devices 3 is %+v, want everything else as it was", u)
	}
	run("user", "set", "-expires", "none", "-may-change-password=false", "-no-saved-password=false", "alice")
	if u := listed().Users[0]; !u.Expires.IsZero() || u.CanChangePassword() || u.NoSavedPassword || u.MaxDevices != 3 {
		t.Errorf("alice after -expires none and the two flags is %+v", u)
	}
	run("user", "set", "-groups", "", "-max-devices", "0", "alice")
	if u := listed().Users[0]; len(u.Groups) != 0 || u.MaxDevices != 0 || u.DisplayName != "Alice" {
		t.Errorf("alice after -groups \"\" and -max-devices 0 is %+v", u)
	}

	// The password comes from a file, one line, and is kept as a hash
	file := filepath.Join(t.TempDir(), "alice.password")
	if err := os.WriteFile(file, []byte("a good password\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := userDecode[api.PasswordResult](t, run("user", "password", "-f", file, "alice")); res.User != "alice" || !res.Set {
		t.Errorf("setting the password gave %+v", res)
	}
	if u := listed().Users[0]; !u.HasPassword {
		t.Errorf("alice has no password after ranz user password: %+v", u)
	}

	// The answers of the commands are the ones of the API
	for _, c := range []struct {
		args []string
		path string
	}{
		{[]string{"user", "list"}, "/api/v1/users"},
		{[]string{"group", "list"}, "/api/v1/groups"},
	} {
		code, body := direct(t, srv, admin, http.MethodGet, c.path, "")
		if code != http.StatusOK || !reflect.DeepEqual(answer(t, run(c.args...)), answer(t, body)) {
			t.Errorf("ranz %s printed something else than GET %s answered (%d): %s", strings.Join(c.args, " "), c.path, code, body)
		}
	}

	run("user", "delete", "alice")
	run("group", "delete", "ops")
	run("group", "delete", "staff")
	if got := listed().Users; len(got) != 0 {
		t.Errorf("the users after the delete are %+v", got)
	}
	if got := userDecode[api.GroupList](t, run("group", "list")).Groups; len(got) != 0 {
		t.Errorf("the groups after the delete are %+v", got)
	}
}

// A flag that is wrong, and an answer of the controller that refuses, are errors of their own: a
// time that is not RFC 3339 and a maximum that does not fit are refused before the call; a group that
// does not exist and a short password come back as the answer of the API, with its status.
func TestUserCommandsRefuse(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"user", "set", "-expires", "tomorrow", "alice"}, `-expires "tomorrow" is not an RFC 3339 time`},
		{[]string{"user", "set", "-expires", "2031-01-02", "alice"}, `-expires "2031-01-02" is not an RFC 3339 time`},
		{[]string{"user", "set", "-max-devices", "99999999999", "alice"}, "-max-devices 99999999999 is more than 4294967295"},
	} {
		if err := do(ctx, cli, c.args, io.Discard); err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ranz %s: %v, want an error that says %q", strings.Join(c.args, " "), err, c.want)
		}
	}
	for _, c := range []struct {
		args   []string
		status int
		want   string
	}{
		{[]string{"user", "set", "-groups", "ghost", "alice"}, http.StatusBadRequest, `Group "ghost" does not exist`},
		{[]string{"user", "delete", "ghost"}, http.StatusNotFound, "ghost"},
		{[]string{"group", "delete", "ghost"}, http.StatusNotFound, "ghost"},
	} {
		var e *api.Error
		if err := do(ctx, cli, c.args, io.Discard); !errors.As(err, &e) || e.Status != c.status || !strings.Contains(e.Message, c.want) {
			t.Errorf("ranz %s: %v, want %d with %q", strings.Join(c.args, " "), err, c.status, c.want)
		}
	}
	if _, err := cli.PutUser(ctx, "alice", intent.User{}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "short.password")
	if err := os.WriteFile(file, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var e *api.Error
	if err := do(ctx, cli, []string{"user", "password", "-f", file, "alice"}, io.Discard); !errors.As(err, &e) || e.Status != http.StatusBadRequest || !strings.Contains(e.Message, "at least 8 characters") {
		t.Errorf("ranz user password with a short password: %v, want 400 Bad Request", err)
	}
	if err := do(ctx, cli, []string{"user", "password", "-f", filepath.Join(t.TempDir(), "missing"), "alice"}, io.Discard); err == nil || errors.As(err, &e) {
		t.Errorf("ranz user password with a file that is not there: %v, want an error of the file", err)
	}
}

// The commands take the arguments they can and print the usage for the others.
func TestUserCommandsUsage(t *testing.T) {
	for _, args := range [][]string{
		{"user"},
		{"user", "list", "extra"},
		{"user", "set"},
		{"user", "set", "alice", "bob"},
		{"user", "set", "-bogus", "alice"},
		{"user", "password"},
		{"user", "password", "alice", "bob"},
		{"user", "delete"},
		{"user", "delete", "alice", "bob"},
		{"user", "frobnicate"},
		{"group"},
		{"group", "list", "extra"},
		{"group", "set"},
		{"group", "set", "-bogus", "staff"},
		{"group", "delete"},
		{"group", "frobnicate"},
	} {
		if err := do(context.Background(), &api.Client{}, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}

// Each role gets from the commands what the API gives it: a viewer lists and changes nothing, an
// operator changes, a call with no token is refused. The roles live in the API only.
func TestUserCommandsNeedRoles(t *testing.T) {
	ctx := context.Background()
	srv, tokens, admin := startController(t)
	file := filepath.Join(t.TempDir(), "alice.password")
	if err := os.WriteFile(file, []byte("a good password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adminClient := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	if err := do(ctx, adminClient, []string{"user", "set", "alice"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	viewer := &api.Client{URL: srv.URL, Token: createToken(t, tokens, "viewer-1", rbac.Viewer), HTTP: srv.Client()}
	operator := &api.Client{URL: srv.URL, Token: createToken(t, tokens, "operator-1", rbac.Operator), HTTP: srv.Client()}
	nobody := &api.Client{URL: srv.URL, HTTP: srv.Client()}

	for _, c := range []struct {
		who  string
		cli  *api.Client
		args []string
		want int
	}{
		{"viewer", viewer, []string{"user", "list"}, http.StatusOK},
		{"viewer", viewer, []string{"group", "list"}, http.StatusOK},
		{"viewer", viewer, []string{"user", "set", "-display", "x", "alice"}, http.StatusForbidden},
		{"viewer", viewer, []string{"user", "password", "-f", file, "alice"}, http.StatusForbidden},
		{"viewer", viewer, []string{"user", "delete", "alice"}, http.StatusForbidden},
		{"viewer", viewer, []string{"group", "set", "staff"}, http.StatusForbidden},
		{"viewer", viewer, []string{"group", "delete", "staff"}, http.StatusForbidden},
		{"nobody", nobody, []string{"user", "list"}, http.StatusUnauthorized},
		{"operator", operator, []string{"group", "set", "staff"}, http.StatusOK},
		{"operator", operator, []string{"user", "set", "-display", "Alice", "alice"}, http.StatusOK},
		{"operator", operator, []string{"user", "password", "-f", file, "alice"}, http.StatusOK},
		{"operator", operator, []string{"user", "delete", "alice"}, http.StatusOK},
		{"operator", operator, []string{"group", "delete", "staff"}, http.StatusOK},
	} {
		err := do(ctx, c.cli, c.args, io.Discard)
		got := http.StatusOK
		var e *api.Error
		if errors.As(err, &e) {
			got = e.Status
		} else if err != nil {
			t.Errorf("%s: ranz %s: %v, want an answer of the API", c.who, strings.Join(c.args, " "), err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: ranz %s got %d, want %d", c.who, strings.Join(c.args, " "), got, c.want)
		}
	}
}
