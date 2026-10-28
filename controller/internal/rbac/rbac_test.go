package rbac

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// Each role allows what it and the roles below it may do, and nothing allows an unknown role.
func TestAllows(t *testing.T) {
	want := map[Role][]Role{
		Viewer:   {Viewer},
		Operator: {Viewer, Operator},
		Admin:    {Viewer, Operator, Admin},
		"":       nil,
		"root":   nil,
	}
	for r, allowed := range want {
		for _, need := range []Role{Viewer, Operator, Admin, "", "root"} {
			got := r.Allows(need)
			if exp := slices.Contains(allowed, need); got != exp {
				t.Errorf("%q allows %q: %v, want %v", r, need, got, exp)
			}
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range Roles {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("ParseRole(%q) = %q, %v", r, got, err)
		}
	}
	for _, s := range []string{"", "Admin", "root"} {
		if _, err := ParseRole(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseRole(%q) gave %v, want ErrInvalid", s, err)
		}
	}
}

// The first start creates the admin token and hands its secret over; a later start creates
// nothing; a failed hand-over leaves no token behind.
func TestBootstrap(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tokens := New(st)

	if _, err := tokens.Bootstrap(ctx, func(string) error { return errors.New("disk full") }); err == nil {
		t.Fatal("a failed hand-over of the secret was not an error")
	}
	if ts, err := tokens.List(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("after a failed hand-over the tokens are %+v, %v", ts, err)
	}

	var secret string
	created, err := tokens.Bootstrap(ctx, func(s string) error { secret = s; return nil })
	if err != nil || !created {
		t.Fatalf("the first bootstrap: %v, %v", created, err)
	}
	if !strings.HasPrefix(secret, secretPrefix) || len(secret) < len(secretPrefix)+26 {
		t.Errorf("the secret %q is not %s and at least 26 characters", secret, secretPrefix)
	}
	tok, err := tokens.Authenticate(ctx, secret)
	if err != nil || tok != (Token{Name: FirstAdmin, Role: Admin}) {
		t.Errorf("the bootstrap secret authenticates as %+v, %v", tok, err)
	}

	created, err = tokens.Bootstrap(ctx, func(string) error {
		t.Error("a second bootstrap handed over a secret")
		return nil
	})
	if err != nil || created {
		t.Errorf("the second bootstrap: %v, %v", created, err)
	}
	for _, s := range []string{"", "ranz_", "ranz_ABCDEFGHIJKLMNOPQRSTUVWXYZ", strings.TrimPrefix(secret, secretPrefix)} {
		if _, err := tokens.Authenticate(ctx, s); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) gave %v, want ErrUnauthenticated", s, err)
		}
	}
}

// A recovery creates a new admin token beside the ones that exist and hands its secret over; a
// failed hand-over leaves no token behind, also when the store holds no admin token.
func TestRecover(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tokens := New(st)
	if _, err := tokens.Recover(ctx, "admin-lost", func(string) error { return errors.New("disk full") }); err == nil {
		t.Fatal("a failed hand-over of the secret was not an error")
	}
	if ts, err := tokens.List(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("after a failed hand-over the tokens are %+v, %v", ts, err)
	}

	if _, err := tokens.Bootstrap(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var secret string
	tok, err := tokens.Recover(ctx, "admin-20261022-120000", func(s string) error { secret = s; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if want := (Token{Name: "admin-20261022-120000", Role: Admin}); tok.Token != want || tok.Secret != secret || !strings.HasPrefix(secret, secretPrefix) {
		t.Errorf("the recovery gave %+v with the secret %q handed over, want %+v", tok, secret, want)
	}
	if got, err := tokens.Authenticate(ctx, secret); err != nil || got != tok.Token {
		t.Errorf("the recovered secret authenticates as %+v, %v", got, err)
	}
	ts, err := tokens.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The recovered secret was used above, so its listing has a last use that a bare token has not
	if want := []Token{{Name: FirstAdmin, Role: Admin}, tok.Token}; len(ts) != 2 || who(ts[0]) != who(want[0]) || who(ts[1]) != who(want[1]) {
		t.Errorf("after the recovery the tokens are %+v, want %+v", ts, want)
	}
	if _, err := tokens.Recover(ctx, tok.Name, func(string) error { return nil }); !errors.Is(err, ErrExists) {
		t.Errorf("a recovery with the name of a token gave %v, want ErrExists", err)
	}
}

// who strips a token of its life, which a use changes: the name and the role are what a test
// compares.
func who(t Token) Token {
	return Token{Name: t.Name, Role: t.Role}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}
