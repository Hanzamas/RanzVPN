package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The last-admin guard of changes that are made at the same time (AUD1-DT-15-R1, #561). The guard is the condition that the one statement
// of a delete, and of a change of a role, carries (store.keepsRole), so rqlite, which applies the statements that it is sent one after
// the other, lets the first of two changes pass and refuses the second, which then finds no other admin token that has not expired. A
// check in Go before the write would let both pass, since each would still see the other token there.

// concurrentRounds is how many times the test makes the same two changes at once: a check that is made before the write is passed by
// both changes only when their reads come before both writes, which is not every time.
const concurrentRounds = 10

// Two changes of two admin tokens at the same time, as two deletes, as two changes of a role and as a delete with a change of a role,
// leave one admin token that has not expired: one change is made and the other is refused (ErrLastAdmin), and the token that is left
// authenticates. An admin token that has expired is beside them all the time, and it does not count, so it saves neither change.
func TestTwoChangesOfAdminTokensAtOnceLeaveOneThatHasNotExpired(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)

	if _, err := tokens.CreateExpiring(ctx, "old", Admin, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	if listed := find(t, tokens, "old"); !listed.Expired || listed.Role != Admin {
		t.Fatalf("old is listed as %+v, want an admin token that has expired", listed)
	}

	// The two admin tokens of a round: a never expires and b does, a day from now, so both ways of not having expired are counted
	names := [2]string{"a", "b"}
	secrets := map[string]string{}
	// ensure makes a and b what they are at the start of a round, whatever the round before did to them
	ensure := func() {
		t.Helper()
		for i, name := range names {
			var expires time.Time
			if i == 1 {
				expires = clk.Now().Add(24 * time.Hour)
			}
			made, err := tokens.CreateExpiring(ctx, name, Admin, expires)
			switch {
			case err == nil:
				secrets[name] = made.Secret
			case errors.Is(err, ErrExists):
				if _, err := tokens.SetRole(ctx, name, Admin); err != nil {
					t.Fatalf("giving %s the role admin again: %v", name, err)
				}
			default:
				t.Fatal(err)
			}
		}
	}
	deletes := func(name string) func() error {
		return func() error {
			_, err := tokens.Delete(ctx, name)
			return err
		}
	}
	gives := func(name string, role Role) func() error {
		return func() error {
			_, err := tokens.SetRole(ctx, name, role)
			return err
		}
	}

	for _, c := range []struct {
		what    string
		changes [2]func() error
	}{
		{"two deletes", [2]func() error{deletes("a"), deletes("b")}},
		{"two changes of the role", [2]func() error{gives("a", Viewer), gives("b", Operator)}},
		{"a delete and a change of the role", [2]func() error{deletes("a"), gives("b", Viewer)}},
	} {
		for round := range concurrentRounds {
			ensure()

			// Both changes wait for one signal, so that they are sent together
			var errs [2]error
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i, change := range c.changes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs[i] = change()
				}()
			}
			close(start)
			wg.Wait()

			var made, refused int
			for _, err := range errs {
				switch {
				case err == nil:
					made++
				case errors.Is(err, ErrLastAdmin):
					refused++
				default:
					t.Errorf("%s, round %d: a change gave %v, want it made or refused as the last admin token", c.what, round, err)
				}
			}
			if made != 1 || refused != 1 {
				t.Errorf("%s, round %d: %d changes were made and %d refused (%v; %v), want one of each", c.what, round, made, refused, errs[0], errs[1])
			}

			listed, err := tokens.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var works []Token
			for _, tok := range listed {
				if tok.Role == Admin && !tok.Expired {
					works = append(works, tok)
				}
			}
			if len(works) != 1 {
				t.Errorf("%s, round %d: the controller holds %d admin tokens that have not expired (%+v), want the one that was kept", c.what, round, len(works), works)
				continue
			}
			if got, err := tokens.Authenticate(ctx, secrets[works[0].Name]); err != nil || got.Role != Admin {
				t.Errorf("%s, round %d: the admin token that was kept, %s, authenticates as %+v (%v), want an admin token that works", c.what, round, works[0].Name, got, err)
			}
		}
	}
}
