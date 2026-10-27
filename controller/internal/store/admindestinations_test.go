package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestAdminDestinations checks the admin destination lists (AUD1-DT-9 #457): a new store holds three
// empty lists, a set replaces all of them, and the events of a change are stored in the same
// transaction, so a change that fails leaves neither.
func TestAdminDestinations(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	got, err := st.AdminDestinations(ctx)
	if err != nil || got.Targets == nil || got.Sensors == nil || got.UNCServers == nil || len(got.Targets)+len(got.Sensors)+len(got.UNCServers) != 0 {
		t.Fatalf("a new store holds the lists %+v (%v), want three empty ones", got, err)
	}
	ev := event.Event{Time: time.Date(2026, time.October, 27, 12, 0, 0, 0, time.UTC), Type: event.AdminDestinationsChanged, Message: "set"}
	want := intent.Destinations{Targets: []string{"127.0.0.0/8", "hooks.example"}, Sensors: []string{"192.0.2.0/24"}, UNCServers: []string{"files.example"}}
	if err := st.SetAdminDestinations(ctx, want, ev); err != nil {
		t.Fatal(err)
	}
	got, err = st.AdminDestinations(ctx)
	if err != nil || !slices.Equal(got.Targets, want.Targets) || !slices.Equal(got.Sensors, want.Sensors) || !slices.Equal(got.UNCServers, want.UNCServers) {
		t.Errorf("the lists are %+v (%v), want %+v", got, err, want)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 || evs[0].Type != event.AdminDestinationsChanged {
		t.Errorf("the events are %+v (%v), want the one of the change", evs, err)
	}

	if err := st.SetAdminDestinations(ctx, intent.Destinations{Sensors: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if got, err := st.AdminDestinations(ctx); err != nil || len(got.Targets) != 0 || !slices.Equal(got.Sensors, []string{"198.51.100.0/24"}) || len(got.UNCServers) != 0 {
		t.Errorf("the lists are %+v (%v) after a set, want the new sensor prefix alone", got, err)
	}

	// An entry twice breaks the primary key: nothing of the change is written, event included.
	if err := st.SetAdminDestinations(ctx, intent.Destinations{Targets: []string{"10.0.0.0/8", "10.0.0.0/8"}}, ev); err == nil {
		t.Error("a list with an entry twice was stored")
	}
	if got, err := st.AdminDestinations(ctx); err != nil || len(got.Targets) != 0 || len(got.Sensors) != 1 {
		t.Errorf("the lists are %+v (%v) after a failed set, want the ones before it", got, err)
	}
	if evs, err := st.Events(ctx); err != nil || len(evs) != 1 {
		t.Errorf("a failed set left %d events (%v), want the first alone", len(evs), err)
	}
}
