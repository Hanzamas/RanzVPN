package audit

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRetentionValidate(t *testing.T) {
	for _, r := range []Retention{DefaultRetention, {Days: 1, MaxRecords: 1000}, {Days: 3650, MaxRecords: 100_000_000}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, c := range []struct {
		r    Retention
		want string
	}{
		{Retention{Days: 0, MaxRecords: 2_000_000}, "days is 0, and must be from 1 to 3650"},
		{Retention{Days: 3651, MaxRecords: 2_000_000}, "days is 3651"},
		{Retention{Days: 365, MaxRecords: 999}, "maxRecords is 999, and must be from 1000 to 100000000"},
		{Retention{Days: 365, MaxRecords: 100_000_001}, "maxRecords is 100000001"},
	} {
		if err := c.r.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: the error is %v, want one that wraps ErrInvalid and says %q", c.r, err, c.want)
		}
	}
	err := Retention{}.Validate()
	if err == nil || !strings.Contains(err.Error(), "days is 0") || !strings.Contains(err.Error(), "maxRecords is 0") {
		t.Errorf("a policy with nothing in it gives %v, want both problems named", err)
	}
}

// Prune removes what the policy of the store says: the default policy until an operator sets one.
func TestPruneFollowsThePolicy(t *testing.T) {
	s := &memStore{}
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)

	if err := Prune(ctx, s, now); err != nil {
		t.Fatal(err)
	}
	if got := s.pruned(); len(got) != 1 || !got[0].before.Equal(now.Add(-365*24*time.Hour)) || got[0].keep != 2_000_000 {
		t.Errorf("without a policy the store was pruned as %+v, want a year and two million records", got)
	}

	if err := s.SetAuditRetention(ctx, Retention{Days: 30, MaxRecords: 5000}); err != nil {
		t.Fatal(err)
	}
	if err := Prune(ctx, s, now); err != nil {
		t.Fatal(err)
	}
	if got := s.pruned(); len(got) != 2 || !got[1].before.Equal(now.Add(-30*24*time.Hour)) || got[1].keep != 5000 {
		t.Errorf("with a policy the store was pruned as %+v, want 30 days and 5000 records", got)
	}

	down := errors.New("rqlite is down")
	s.err = down
	if err := Prune(ctx, s, now); !errors.Is(err, down) {
		t.Errorf("Prune on a store that fails gave %v", err)
	}
}

// Prune removes the records that are too old, and the oldest of any beyond the maximum.
func TestPruneRemovesOldRecords(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	for _, age := range []time.Duration{400 * 24 * time.Hour, 366 * 24 * time.Hour, 10 * 24 * time.Hour, time.Hour} {
		if err := l.Record(context.Background(), Record{Kind: Login, Outcome: Success, Time: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Prune(context.Background(), s, now); err != nil {
		t.Fatal(err)
	}
	if got := s.all(); len(got) != 2 || got[0].ID != 3 || got[1].ID != 4 {
		t.Errorf("the records that stay are %+v, want the two of the last year", got)
	}
}

// Retain prunes at once and then again and again, and ends with its context.
func TestRetainRunsUntilItsContextEnds(t *testing.T) {
	s := &memStore{err: errors.New("rqlite is down")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Retain(ctx, s, 5*time.Millisecond, slog.New(slog.DiscardHandler))
	}()
	// A failure does not end it: it tries again, and the store that comes back is pruned
	time.Sleep(20 * time.Millisecond)
	s.mu.Lock()
	s.err = nil
	s.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.pruned()) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the store was pruned %d times within 5 s, want 2", len(s.pruned()))
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Retain did not end with its context")
	}
}
