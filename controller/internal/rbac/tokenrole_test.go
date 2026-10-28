package rbac

import (
	"context"
	"errors"
	"testing"
)

// The role of an API token changes in place: the secret authenticates with the new role at once; the
// last admin token keeps the role admin, another admin token can lose it; a token that does not exist
// and a role that does not exist are refused.
func TestSetRole(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t))
	if _, err := tokens.Bootstrap(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ops, err := tokens.Create(ctx, "ops", Operator)
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := tokens.SetRole(ctx, "ops", Viewer); err != nil || tok != (Token{Name: "ops", Role: Viewer}) {
		t.Fatalf("SetRole(ops, viewer): %+v, %v", tok, err)
	}
	if got, err := tokens.Authenticate(ctx, ops.Secret); err != nil || got.Role != Viewer {
		t.Errorf("the secret of ops authenticates as %+v, %v, want the role viewer", got, err)
	}
	if _, err := tokens.SetRole(ctx, FirstAdmin, Operator); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("the last admin token loses the role admin: %v, want ErrLastAdmin", err)
	}
	if _, err := tokens.SetRole(ctx, FirstAdmin, Admin); err != nil {
		t.Errorf("the last admin token keeps the role admin: %v", err)
	}
	if _, err := tokens.SetRole(ctx, "ops", Admin); err != nil {
		t.Fatal(err)
	}
	if tok, err := tokens.SetRole(ctx, FirstAdmin, Viewer); err != nil || tok.Role != Viewer {
		t.Errorf("an admin token that is not the last one loses the role admin: %+v, %v", tok, err)
	}
	if _, err := tokens.SetRole(ctx, "nobody", Viewer); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetRole of a token that does not exist: %v, want ErrNotFound", err)
	}
	if _, err := tokens.SetRole(ctx, "ops", "root"); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetRole with a role that does not exist: %v, want ErrInvalid", err)
	}
}
