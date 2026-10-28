package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The API roles of users and the user tokens (SDN-32): a User holds no role until one is set, a user
// token is made only for a User that holds one, it authenticates with the role that the User holds when
// it is used, it ends at its end, and a logout and a delete of the role end it at once.
func TestUserRolesAndUserTokens(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t))
	if rs, err := tokens.UserRoles(ctx); err != nil || len(rs) != 0 {
		t.Fatalf("a new store holds the roles %+v (%v)", rs, err)
	}
	if _, err := tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour)); !errors.Is(err, ErrNoRole) {
		t.Errorf("a user token for a User that holds no role: %v, want ErrNoRole", err)
	}
	for _, c := range []struct {
		name string
		role Role
	}{{"Alice", Operator}, {"alice", "root"}} {
		if _, err := tokens.SetUserRole(ctx, c.name, c.role); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetUserRole(%q, %q) gave %v, want ErrInvalid", c.name, c.role, err)
		}
	}
	if ur, err := tokens.SetUserRole(ctx, "alice", Operator); err != nil || ur != (UserRole{User: "alice", Role: Operator}) {
		t.Fatalf("SetUserRole: %+v, %v", ur, err)
	}
	if _, err := tokens.SetUserRole(ctx, "bob", Viewer); err != nil {
		t.Fatal(err)
	}
	if rs, err := tokens.UserRoles(ctx); err != nil || len(rs) != 2 || rs[0].User != "alice" || rs[1].Role != Viewer {
		t.Errorf("the roles are %+v (%v), want alice and bob in that order", rs, err)
	}

	tok, err := tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := Token{Name: "user:alice", Role: Operator, User: "alice"}
	if tok.Token != want || !strings.HasPrefix(tok.Secret, userTokenPrefix) || tok.Actor() != "user:alice" {
		t.Errorf("the user token is %+v", tok)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("the user token authenticates as %+v, %v", got, err)
	}
	if (Token{Name: "ops", Role: Operator}).Actor() != "token:ops" {
		t.Error("the actor of an API token is not the token")
	}
	// The token carries the role that the User holds when it is used
	if _, err := tokens.SetUserRole(ctx, "alice", Admin); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got.Role != Admin {
		t.Errorf("after the change of the role the token authenticates as %+v, %v", got, err)
	}
	// A secret that is no user token, and a user token that ended
	for _, s := range []string{userTokenPrefix + "NOTATOKEN", userTokenPrefix} {
		if _, err := tokens.Authenticate(ctx, s); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) gave %v, want ErrUnauthenticated", s, err)
		}
	}
	ended, err := tokens.IssueUserToken(ctx, "bob", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(ctx, ended.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a user token past its end: %v, want ErrUnauthenticated", err)
	}

	// A logout ends the token, once
	if got, err := tokens.RevokeUserToken(ctx, tok.Secret); err != nil || got.User != "alice" {
		t.Errorf("the logout: %+v, %v", got, err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token after its logout: %v, want ErrUnauthenticated", err)
	}
	for _, s := range []string{tok.Secret, "ranz_ABCDEFGHIJKLMNOPQRSTUVWXYZ"} {
		if _, err := tokens.RevokeUserToken(ctx, s); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("RevokeUserToken(%q) gave %v, want ErrUnauthenticated", s, err)
		}
	}

	// A delete of the role ends the tokens of the User at once
	tok, err = tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ur, err := tokens.DeleteUserRole(ctx, "alice"); err != nil || ur.Role != Admin {
		t.Errorf("DeleteUserRole: %+v, %v", ur, err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token after the delete of the role: %v, want ErrUnauthenticated", err)
	}
	if _, err := tokens.DeleteUserRole(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a delete of a role that is not held: %v, want ErrNotFound", err)
	}
	if role, ok, err := tokens.UserRole(ctx, "bob"); err != nil || !ok || role != Viewer {
		t.Errorf("the role of bob is %q, %v, %v", role, ok, err)
	}
}
