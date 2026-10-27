package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestBans checks the bans of the users (SDN-50): a new store holds none, a ban stores its instant to
// the millisecond, its actor and its reason, a second ban of a user replaces the first, the bans come
// back ordered, and a delete removes the rows it names and no other.
func TestBans(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if bans, err := st.Bans(ctx); err != nil || bans == nil || len(bans) != 0 {
		t.Fatalf("a new store holds the bans %v (%v), want an empty list", bans, err)
	}

	since := time.Date(2026, time.October, 27, 11, 12, 13, 456000000, time.UTC)
	for _, b := range []store.Ban{
		{User: "carol", Since: since, By: "token:ops", Reason: "stolen laptop"},
		{User: "alice", Since: since.Add(time.Hour), By: "token:admin"},
		{User: "bob", Since: since.Add(2 * time.Hour), By: "token:ops", Reason: "left the company"},
	} {
		if err := st.AddBan(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	bans, err := st.Bans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 3 || bans[0].User != "alice" || bans[1].User != "bob" || bans[2].User != "carol" {
		t.Fatalf("the bans are %+v, want alice, bob and carol in that order", bans)
	}
	if b := bans[2]; !b.Since.Equal(since) || b.By != "token:ops" || b.Reason != "stolen laptop" || b.Since.Location() != time.UTC {
		t.Errorf("the ban of carol is %+v, want the instant %v, the actor token:ops and the reason that was given", b, since)
	}
	if b := bans[0]; b.Reason != "" || b.By != "token:admin" {
		t.Errorf("the ban of alice is %+v, want no reason", b)
	}

	// A second ban of a user takes the place of the first
	if err := st.AddBan(ctx, store.Ban{User: "carol", Since: since.Add(24 * time.Hour), By: "token:admin", Reason: "again"}); err != nil {
		t.Fatal(err)
	}
	if bans, err = st.Bans(ctx); err != nil || len(bans) != 3 || bans[2].Reason != "again" || bans[2].By != "token:admin" {
		t.Errorf("the bans after a second ban of carol are %+v (%v), want one ban of carol, the new one", bans, err)
	}

	if err := st.DeleteBans(ctx, []string{"alice", "nobody"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteBans(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if bans, err = st.Bans(ctx); err != nil || len(bans) != 2 || bans[0].User != "bob" || bans[1].User != "carol" {
		t.Errorf("the bans after the delete of alice are %+v (%v), want bob and carol", bans, err)
	}
}
