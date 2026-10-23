package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestExportTargets checks the export targets of SDN-16 in the store: a target keeps its secret
// and its types, a new target starts at the latest event, an update keeps what the webhook was
// sent, the record of what it was sent only moves forward, and EventsAfter hands out the events
// in order.
func TestExportTargets(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if ts, err := st.Targets(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("a new store holds the targets %+v, %v", ts, err)
	}
	if evs, err := st.EventsAfter(ctx, 0, 10); err != nil || len(evs) != 0 {
		t.Fatalf("a new store holds the events %+v, %v", evs, err)
	}
	for _, typ := range []string{event.NodeDown, event.GatewayFailover, event.PoolNearExhaustion} {
		ev := event.Event{Time: time.Unix(1760000000, 0).UTC(), Type: typ, Message: typ, Node: "node-a"}
		if err := st.Commit(ctx, store.Changes{AddEvents: []event.Event{ev}}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := st.EventsAfter(ctx, 0, 2)
	if err != nil || len(first) != 2 || first[0].ID != 1 || first[1].ID != 2 || first[0].Type != event.NodeDown || first[0].Node != "node-a" {
		t.Fatalf("the first two events are %+v, %v", first, err)
	}
	if rest, err := st.EventsAfter(ctx, 2, 10); err != nil || len(rest) != 1 || rest[0].ID != 3 || rest[0].Type != event.PoolNearExhaustion {
		t.Fatalf("the events after the second are %+v, %v", rest, err)
	}

	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "key", Types: []string{event.NodeDown}}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	flows := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"}
	if err := st.PutTarget(ctx, flows); err != nil {
		t.Fatal(err)
	}
	ts, err := st.Targets(ctx)
	if err != nil || len(ts) != 2 || ts[0].Name != "alerts" || ts[1].Name != "flows" {
		t.Fatalf("the targets are %+v, %v, want alerts and flows", ts, err)
	}
	if got := ts[0]; got.Secret != "key" || got.URL != hook.URL || len(got.Types) != 1 || got.Types[0] != event.NodeDown || got.Kind != export.KindWebhook {
		t.Errorf("the target alerts is %+v, want what was stored, with its secret and types", got)
	}
	if ts[0].Delivered != 3 || ts[1].Delivered != 3 {
		t.Errorf("a new target starts after the events of before it: it was sent up to %d and %d, want 3", ts[0].Delivered, ts[1].Delivered)
	}

	// The webhook is sent two more events, and a record that goes back changes nothing
	for _, id := range []uint64{5, 4} {
		if err := st.Delivered(ctx, "alerts", id); err != nil {
			t.Fatal(err)
		}
	}
	if ts, _ = st.Targets(ctx); ts[0].Delivered != 5 || ts[1].Delivered != 3 {
		t.Errorf("the record of what was sent is %d and %d, want 5 and 3", ts[0].Delivered, ts[1].Delivered)
	}

	// An update replaces the target and keeps what it was sent; a new event does not move it
	hook.URL, hook.Secret, hook.Types = "https://hooks.example.com/y", "", nil
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if ts, _ = st.Targets(ctx); len(ts) != 2 || ts[0].URL != hook.URL || ts[0].Secret != "" || len(ts[0].Types) != 0 || ts[0].Delivered != 5 {
		t.Errorf("after the update the target is %+v, want the new URL, no secret, no types, still sent up to 5", ts[0])
	}

	if err := st.DeleteTarget(ctx, "alerts"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTarget(ctx, "alerts"); err != nil {
		t.Errorf("deleting a target twice: %v", err)
	}
	if ts, _ = st.Targets(ctx); len(ts) != 1 || ts[0].Name != "flows" {
		t.Errorf("after the delete the targets are %+v", ts)
	}
}
