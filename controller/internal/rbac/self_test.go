package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Self is the lowest role that Allows orders: it allows itself and none of the three API roles, each API
// role allows it, and it is no API role that an admin may give.
func TestSelfIsBelowTheAPIRoles(t *testing.T) {
	for _, c := range []struct {
		have, need Role
		want       bool
	}{
		{Self, Self, true}, {Self, Viewer, false}, {Self, Operator, false}, {Self, Admin, false},
		{Viewer, Self, true}, {Operator, Self, true}, {Admin, Self, true},
		{"", Self, false}, {"root", Self, false},
	} {
		if got := c.have.Allows(c.need); got != c.want {
			t.Errorf("%q allows %q: %v, want %v", c.have, c.need, got, c.want)
		}
	}
	if _, err := ParseRole(string(Self)); !errors.Is(err, ErrInvalid) {
		t.Errorf("ParseRole(%q) gave %v, want ErrInvalid", Self, err)
	}
	for _, r := range Roles {
		if r == Self {
			t.Errorf("Roles lists %q, which is no API role", Self)
		}
	}
}

// The token of the self scope (SDN-58): it needs no API role, it carries the role Self and the name of its
// User, an admin who gives the User a role does not widen it and taking the role away does not end it, a
// secret that is none and one that ended authenticate nothing, and a logout ends it once.
func TestTheTokenOfTheSelfScopeNeedsNoRoleAndKeepsItsScope(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t))
	if _, err := tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour)); !errors.Is(err, ErrNoRole) {
		t.Fatalf("a user token for a User that holds no role: %v, want ErrNoRole", err)
	}
	tok, err := tokens.IssueSelfToken(ctx, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := Token{Name: "user:alice", Role: Self, User: "alice"}
	if tok.Token != want || !strings.HasPrefix(tok.Secret, selfTokenPrefix) || tok.Actor() != "user:alice" {
		t.Errorf("the token of the self scope is %+v", tok)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("the token of the self scope authenticates as %+v, %v", got, err)
	}

	// An admin gives alice a role, and later takes it away: the token keeps its scope throughout
	if _, err := tokens.SetUserRole(ctx, "alice", Admin); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("after alice got the role admin the token authenticates as %+v, %v, want the self scope", got, err)
	}
	role, err := tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, role.Secret); err != nil || got.Role != Admin || strings.HasPrefix(role.Secret, selfTokenPrefix) {
		t.Errorf("the user token of the role authenticates as %+v, %v, want the role admin and a secret of its own", got, err)
	}
	if _, err := tokens.DeleteUserRole(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("after the role of alice went the token authenticates as %+v, %v, want the self scope", got, err)
	}
	if _, err := tokens.Authenticate(ctx, role.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the user token of the role after the role went: %v, want ErrUnauthenticated", err)
	}

	// A secret that is none, and a token that ended
	for _, s := range []string{selfTokenPrefix + "NOTATOKEN", selfTokenPrefix} {
		if _, err := tokens.Authenticate(ctx, s); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) gave %v, want ErrUnauthenticated", s, err)
		}
	}
	ended, err := tokens.IssueSelfToken(ctx, "bob", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(ctx, ended.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a token of the self scope past its end: %v, want ErrUnauthenticated", err)
	}

	// The logout of the login ends the token, once
	if got, err := tokens.RevokeUserToken(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("the logout: %+v, %v", got, err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token after its logout: %v, want ErrUnauthenticated", err)
	}
	if _, err := tokens.RevokeUserToken(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a second logout with the secret: %v, want ErrUnauthenticated", err)
	}
}
