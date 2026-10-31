package store_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// firstWriteEvent is the event that a write of the admin source allowlist adds.
func firstWriteEvent(message string) event.Event {
	return event.Event{Time: time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC), Type: event.AdminSourcesChanged, Message: message}
}

// TestSetFirstAdminSourcesTheFirstWriteWins (AUD1-DT-15, #497): the list is written, with its event, only when the store holds none.
// A later write, whatever it holds, writes nothing, not a prefix and not an event, and tells that it was not the first.
func TestSetFirstAdminSourcesTheFirstWriteWins(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if first, err := st.SetFirstAdminSources(ctx, nil, firstWriteEvent("none")); err != nil || first {
		t.Fatalf("a write of no prefix gave %v (%v), want it no write", first, err)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 0 {
		t.Fatalf("a write of no prefix left the events %+v (%v)", evs, err)
	}

	if first, err := st.SetFirstAdminSources(ctx, []string{"192.0.2.0/24", "10.0.0.0/8"}, firstWriteEvent("first")); err != nil || !first {
		t.Fatalf("the first write gave %v (%v), want it made", first, err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.0/24"}
	// A list that holds the first and more, another that holds none of it, and the same one again
	for _, list := range [][]string{{"10.0.0.0/8", "192.0.2.0/24", "203.0.113.0/24"}, {"198.51.100.0/24"}, want} {
		if later, err := st.SetFirstAdminSources(ctx, list, firstWriteEvent("later")); err != nil || later {
			t.Errorf("a later write of %v gave %v (%v), want it not the first", list, later, err)
		}
		if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, want) {
			t.Errorf("after a later write of %v the list is %v (%v), want the first one alone, %v", list, got, err, want)
		}
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 || evs[0].Message != "first" {
		t.Errorf("the events are %+v (%v), want the one of the first write alone", evs, err)
	}

	// What an admin sets afterwards replaces the list as it did, the first write has no say in it
	if err := st.SetAdminSources(ctx, []string{"2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
	if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, []string{"2001:db8::/32"}) {
		t.Errorf("the list is %v (%v) after an admin set it, want what the admin set", got, err)
	}
}

// Members of a cluster that make their first start at the same time write at the same time: of all of them one write is the first, the
// list that the store ends with is that one in whole, never a mix of two, and the events are the one of that write.
func TestSetFirstAdminSourcesOfMembersThatStartTogether(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const members = 8
	lists := make([][]string, members)
	var (
		mu    sync.Mutex
		first []int
		wg    sync.WaitGroup
	)
	start := make(chan struct{})
	for i := range members {
		lists[i] = []string{fmt.Sprintf("10.%d.0.0/16", i), fmt.Sprintf("192.0.2.%d/32", i), fmt.Sprintf("2001:db8:%d::/48", i)}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			made, err := st.SetFirstAdminSources(ctx, lists[i], firstWriteEvent(fmt.Sprintf("member %d", i)))
			if err != nil {
				t.Errorf("member %d: %v", i, err)
				return
			}
			if made {
				mu.Lock()
				first = append(first, i)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(first) != 1 {
		t.Fatalf("%d of %d writes were the first, want one: %v", len(first), members, first)
	}
	want := slices.Clone(lists[first[0]])
	slices.Sort(want)
	if got, err := st.AdminSources(ctx); err != nil || !slices.Equal(got, want) {
		t.Errorf("the list is %v (%v), want the whole list of member %d, %v", got, err, first[0], want)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 || !strings.HasSuffix(evs[0].Message, fmt.Sprint(first[0])) {
		t.Errorf("the events are %+v (%v), want the one of member %d", evs, err, first[0])
	}
}
