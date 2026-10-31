package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests of the last-admin guard (AUD1-DT-15, #497): the controller keeps one admin token that has not expired. A clock that a test
// moves stands in for the time, as in life_test.go.

// With the token admin, which never expires, and the admin token ops, which has expired, the delete of admin, the change of its role
// and the scoping of it are refused as the last admin token that works; the expired token is deleted as any is, and the last admin
// token that works is still refused once it is the only one. Another admin token that has not expired takes its place.
func TestTheLastAdminGuardCountsTheAdminTokensThatHaveNotExpired(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)

	if _, err := tokens.Bootstrap(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ops, err := tokens.CreateExpiring(ctx, "ops", Admin, clk.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Before its expiry ops is an admin token that works, so admin is not the last one: it may become a viewer, and an admin again
	if _, err := tokens.SetRole(ctx, FirstAdmin, Viewer); err != nil {
		t.Fatalf("an admin token beside one that has not expired lost the role admin: %v", err)
	}
	if _, err := tokens.SetRole(ctx, FirstAdmin, Admin); err != nil {
		t.Fatal(err)
	}

	clk.Advance(time.Hour)
	if _, err := tokens.Authenticate(ctx, ops.Secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("the secret of ops authenticates with %v, want ErrExpired", err)
	}
	for name, change := range map[string]func() error{
		"delete": func() error { _, err := tokens.Delete(ctx, FirstAdmin); return err },
		"role":   func() error { _, err := tokens.SetRole(ctx, FirstAdmin, Operator); return err },
		"scope": func() error {
			_, err := tokens.SetGrant(ctx, FirstAdmin, Grant{Role: Admin, Network: "branch-a"})
			return err
		},
	} {
		err := change()
		if !errors.Is(err, ErrLastAdmin) || !strings.Contains(err.Error(), "that has not expired") {
			t.Errorf("the %s of the only admin token that has not expired gave %v, want ErrLastAdmin that says it is the last one that has not expired", name, err)
		}
	}
	if kept := find(t, tokens, FirstAdmin); kept.Role != Admin || kept.Network != "" || kept.Expired {
		t.Errorf("the refused changes left the token admin as %+v, want the role admin for the whole API", kept)
	}
	if listed := find(t, tokens, "ops"); !listed.Expired || listed.Role != Admin {
		t.Errorf("ops is listed as %+v, want an admin token that has expired", listed)
	}

	// The expired admin token goes as any token that has expired does: admin is left
	gone, err := tokens.Delete(ctx, "ops")
	if err != nil || gone.Name != "ops" || !gone.Expired || gone.Role != Admin {
		t.Fatalf("deleting the expired admin token gave %+v, %v", gone, err)
	}
	if _, err := tokens.Delete(ctx, FirstAdmin); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the only admin token gave %v, want ErrLastAdmin", err)
	}

	// An admin token that has not expired is another one that works: admin may go
	if _, err := tokens.CreateExpiring(ctx, "next", Admin, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Delete(ctx, FirstAdmin); err != nil {
		t.Errorf("deleting admin beside an admin token that has not expired gave %v", err)
	}
	// It expires, and is the last admin token that there is: the controller keeps it
	clk.Advance(time.Hour)
	if _, err := tokens.Delete(ctx, "next"); !errors.Is(err, ErrLastAdmin) || !strings.Contains(err.Error(), "has expired and is the last token") {
		t.Errorf("deleting the only admin token, which has expired, gave %v, want ErrLastAdmin that says it has expired and is the last one", err)
	}
}

// A controller whose admin tokens have all expired keeps the last of them, as it always kept the last admin token, and deletes the
// others and the tokens of any other role: an expired admin token does not count as one that works, and is no reason to refuse the
// delete of a token that does not hold the role.
func TestTheLastAdminTokenThereIsKeptEvenWhenItHasExpired(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)

	for name, life := range map[string]time.Duration{"first": time.Hour, "second": 2 * time.Hour} {
		if _, err := tokens.CreateExpiring(ctx, name, Admin, clk.Now().Add(life)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tokens.Create(ctx, "reader", Viewer); err != nil {
		t.Fatal(err)
	}
	clk.Advance(3 * time.Hour)

	if _, err := tokens.Delete(ctx, "first"); err != nil {
		t.Fatalf("deleting an expired admin token beside another admin token gave %v", err)
	}
	if _, err := tokens.SetRole(ctx, "second", Viewer); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("taking the role from the last admin token there is, which has expired, gave %v, want ErrLastAdmin", err)
	}
	if _, err := tokens.Delete(ctx, "second"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the last admin token there is, which has expired, gave %v, want ErrLastAdmin", err)
	}
	if _, err := tokens.Delete(ctx, "reader"); err != nil {
		t.Errorf("deleting a viewer token gave %v, want it deleted: it is no admin token", err)
	}
	if listed := find(t, tokens, "second"); !listed.Expired || listed.Role != Admin {
		t.Errorf("the last admin token is %+v, want it kept, expired, with its role", listed)
	}
}
