package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestAdminSources checks the admin source allowlist (SDN-39): a new store holds none, a set
// replaces what was there, an empty set removes it, and the events of a change are stored in the
// same transaction, so a change that fails leaves neither.
func TestAdminSources(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	got, err := st.AdminSources(ctx)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("a new store holds the admin source allowlist %v (%v), want an empty one", got, err)
	}
	ev := event.Event{Time: time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC), Type: event.AdminSourcesChanged, Message: "set"}
	if err := st.SetAdminSources(ctx, []string{"203.0.113.0/24", "10.0.0.0/8"}, ev); err != nil {
		t.Fatal(err)
	}
	if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, []string{"10.0.0.0/8", "203.0.113.0/24"}) {
		t.Errorf("the allowlist is %v (%v), want the two prefixes in order", got, err)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 || evs[0].Type != event.AdminSourcesChanged || evs[0].Message != "set" {
		t.Errorf("the events are %+v (%v), want the one of the change", evs, err)
	}

	if err := st.SetAdminSources(ctx, []string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, []string{"192.0.2.0/24"}) {
		t.Errorf("the allowlist is %v (%v) after a set, want the new prefix alone", got, err)
	}

	// A prefix twice breaks the primary key: nothing of the change is written, event included.
	if err := st.SetAdminSources(ctx, []string{"198.51.100.0/24", "198.51.100.0/24"}, ev); err == nil {
		t.Error("a list with a prefix twice was stored")
	}
	if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, []string{"192.0.2.0/24"}) {
		t.Errorf("the allowlist is %v (%v) after a failed set, want it unchanged", got, err)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 {
		t.Errorf("the events are %+v (%v) after a failed set, want the first one alone", evs, err)
	}

	if err := st.SetAdminSources(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := st.AdminSources(ctx); err != nil || got == nil || len(got) != 0 {
		t.Errorf("the allowlist is %v (%v) after an empty set, want none", got, err)
	}
}
