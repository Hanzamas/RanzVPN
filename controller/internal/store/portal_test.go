package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestSelfTokens checks the tokens of the self scope (SDN-58): one is stored for any User, with no API role,
// and is found until its end; a token that ended is removed by the next one stored; a delete takes it once; and
// what ends the user tokens of a User, a ban, an expiry that moves earlier and the removal of the User, ends
// these too.
func TestSelfTokens(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()

	add := func(hash, name string, expires time.Time) {
		t.Helper()
		if err := st.AddSelfToken(ctx, store.UserToken{Hash: hash, Name: name, Expires: expires}, now); err != nil {
			t.Fatal(err)
		}
	}
	found := func(hash string, at time.Time) (string, bool) {
		t.Helper()
		name, ok, err := st.SelfTokenByHash(ctx, hash, at)
		if err != nil {
			t.Fatal(err)
		}
		return name, ok
	}
	add("s1", "alice", now.Add(time.Hour))
	add("s2", "bob", now.Add(time.Hour))
	add("s3", "alice", now.Add(2*time.Hour))
	if name, ok := found("s1", now); !ok || name != "alice" {
		t.Errorf("the token s1 is %q, %v, want alice's", name, ok)
	}
	if _, ok := found("nothing", now); ok {
		t.Error("a hash that no token has was found")
	}
	if _, ok := found("s1", now.Add(time.Hour)); ok {
		t.Error("a token was found at the instant that it ends")
	}

	// A token that ended is removed by the next one stored
	add("s0", "carol", now.Add(-time.Minute))
	if _, ok := found("s0", now.Add(-2*time.Minute)); !ok {
		t.Error("a token that ended was not found when asked for before its end")
	}
	if err := st.AddSelfToken(ctx, store.UserToken{Hash: "s9", Name: "carol", Expires: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := found("s0", now.Add(-2*time.Minute)); ok {
		t.Error("a token that ended was kept by the next store")
	}

	// A delete takes the token once
	if name, ok, err := st.DeleteSelfToken(ctx, "s2"); err != nil || !ok || name != "bob" {
		t.Errorf("deleting s2: %q, %v, %v, want bob's", name, ok, err)
	}
	if _, ok, err := st.DeleteSelfToken(ctx, "s2"); err != nil || ok {
		t.Errorf("deleting s2 again: %v, %v, want none", ok, err)
	}

	// A ban ends the tokens of the User with its user tokens, and nobody else's
	if err := st.DeleteUserTokens(ctx, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"s1", "s3"} {
		if _, ok := found(h, now); ok {
			t.Errorf("the token %s of a banned User was kept", h)
		}
	}
	if _, ok := found("s9", now); !ok {
		t.Error("the ban of alice ended the token of carol")
	}

	// An expiry that moves earlier ends the tokens then, and one that would move later changes nothing
	add("e1", "dave", now.Add(time.Hour))
	add("e2", "dave", now.Add(time.Minute))
	until := now.Add(10 * time.Minute)
	if err := st.EndUserTokens(ctx, "dave", until); err != nil {
		t.Fatal(err)
	}
	if _, ok := found("e1", until.Add(-time.Second)); !ok {
		t.Error("the token e1 ended before the expiry of its User")
	}
	if _, ok := found("e1", until); ok {
		t.Error("the token e1 outlived the expiry of its User")
	}
	if _, ok := found("e2", now.Add(2*time.Minute)); ok {
		t.Error("the token e2, which ended earlier, was moved later")
	}

	// The removal of the User takes the tokens too
	if err := st.DeleteUserRoles(ctx, []string{"carol"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := found("s9", now); ok {
		t.Error("the token of a User that was removed was kept")
	}
}

// TestJoinTokens checks the join tokens (SDN-58): a User holds a limited number that wait, they are listed
// oldest first without their hashes, a device takes one with a claim that two cannot make at once, the claim is
// given back or ends in the delete of the token, a User revokes its own and no other, an end is an end, and the
// removal of a User takes its tokens.
func TestJoinTokens(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().Truncate(time.Millisecond)

	tok := func(i int, owner, name string) store.JoinToken {
		return store.JoinToken{Hash: fmt.Sprintf("hash%d", i), ID: fmt.Sprintf("id%d", i), Owner: owner, Name: name,
			Created: now.Add(time.Duration(i) * time.Second), Expires: now.Add(time.Hour)}
	}
	list := func(owner string, at time.Time) []store.JoinToken {
		t.Helper()
		ts, err := st.JoinTokens(ctx, owner, at)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}

	// A User holds at most the limit that waits, and another User has a count of its own
	for i := 1; i <= 2; i++ {
		if ok, err := st.AddJoinToken(ctx, tok(i, "alice", ""), now, 2); err != nil || !ok {
			t.Fatalf("storing join token %d: %v, %v", i, ok, err)
		}
	}
	if ok, err := st.AddJoinToken(ctx, tok(3, "alice", ""), now, 2); err != nil || ok {
		t.Errorf("a third join token above the limit of 2: %v, %v, want it refused", ok, err)
	}
	if ok, err := st.AddJoinToken(ctx, tok(4, "bob", "phone"), now, 2); err != nil || !ok {
		t.Fatalf("a join token of bob: %v, %v", ok, err)
	}

	// The list: the tokens of the User, oldest first, with their id, name and times and no hash
	ts := list("alice", now)
	if len(ts) != 2 || ts[0].ID != "id1" || ts[1].ID != "id2" || ts[0].Hash != "" || ts[0].Owner != "alice" ||
		!ts[0].Created.Equal(now.Add(time.Second)) || !ts[0].Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("the join tokens of alice are %+v", ts)
	}
	if ts := list("bob", now); len(ts) != 1 || ts[0].Name != "phone" {
		t.Errorf("the join tokens of bob are %+v", ts)
	}
	if ts := list("nobody", now); ts == nil || len(ts) != 0 {
		t.Errorf("the join tokens of nobody are %v, want an empty list", ts)
	}
	if ts := list("alice", now.Add(time.Hour)); len(ts) != 0 {
		t.Errorf("the join tokens of alice at their end are %+v", ts)
	}

	// A claim is made once, and a claimed token is not listed, not revoked and not counted
	got, ok, err := st.ClaimJoinToken(ctx, "hash1", now)
	if err != nil || !ok || got.Owner != "alice" || got.ID != "id1" || got.Hash != "hash1" || got.Name != "" {
		t.Fatalf("the claim of hash1: %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := st.ClaimJoinToken(ctx, "hash1", now); err != nil || ok {
		t.Errorf("a second claim of hash1: %v, %v, want none", ok, err)
	}
	if _, ok, err := st.ClaimJoinToken(ctx, "no hash", now); err != nil || ok {
		t.Errorf("the claim of a hash that no token has: %v, %v, want none", ok, err)
	}
	if ts := list("alice", now); len(ts) != 1 || ts[0].ID != "id2" {
		t.Errorf("the join tokens of alice while one is claimed are %+v", ts)
	}
	if _, ok, err := st.DeleteJoinToken(ctx, "alice", "id1"); err != nil || ok {
		t.Errorf("the revocation of a claimed token: %v, %v, want none", ok, err)
	}
	if ok, err := st.AddJoinToken(ctx, tok(5, "alice", ""), now, 2); err != nil || !ok {
		t.Errorf("a join token while one is claimed, which does not count: %v, %v", ok, err)
	}

	// Given back, the token waits again; finished, it is gone
	if err := st.ReleaseJoinToken(ctx, "hash1"); err != nil {
		t.Fatal(err)
	}
	if ts := list("alice", now); len(ts) != 3 {
		t.Errorf("the join tokens of alice after the release are %+v, want 3", ts)
	}
	if _, ok, err := st.ClaimJoinToken(ctx, "hash1", now); err != nil || !ok {
		t.Fatalf("the claim after the release: %v, %v", ok, err)
	}
	if err := st.FinishJoinToken(ctx, "hash1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.ClaimJoinToken(ctx, "hash1", now); err != nil || ok {
		t.Errorf("the claim of a token that was finished: %v, %v, want none", ok, err)
	}

	// A User revokes its own token, and not the token of another User
	if _, ok, err := st.DeleteJoinToken(ctx, "bob", "id2"); err != nil || ok {
		t.Errorf("bob revoked the token of alice: %v, %v", ok, err)
	}
	if rev, ok, err := st.DeleteJoinToken(ctx, "alice", "id2"); err != nil || !ok || rev.ID != "id2" || rev.Owner != "alice" {
		t.Errorf("alice revoked her token: %+v, %v, %v", rev, ok, err)
	}
	if _, ok, err := st.DeleteJoinToken(ctx, "alice", "id2"); err != nil || ok {
		t.Errorf("a second revocation: %v, %v, want none", ok, err)
	}

	// An end is an end: no claim at it, and the next token stored removes the ones that ended
	if _, ok, err := st.ClaimJoinToken(ctx, "hash4", now.Add(time.Hour)); err != nil || ok {
		t.Errorf("the claim of a token at its end: %v, %v, want none", ok, err)
	}
	later := now.Add(2 * time.Hour)
	if ok, err := st.AddJoinToken(ctx, store.JoinToken{Hash: "hash6", ID: "id6", Owner: "bob", Created: later, Expires: later.Add(time.Hour)}, later, 2); err != nil || !ok {
		t.Fatalf("a join token after the others ended: %v, %v", ok, err)
	}
	if ts := list("bob", now); len(ts) != 1 || ts[0].ID != "id6" {
		t.Errorf("the join tokens of bob after the next one was stored are %+v, want the new one alone", ts)
	}

	// The removal of a User takes its tokens
	if err := st.DeleteUserRoles(ctx, []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	if ts := list("bob", later); len(ts) != 0 {
		t.Errorf("the join tokens of a User that was removed are %+v", ts)
	}
}
