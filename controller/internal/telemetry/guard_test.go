package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// loopbackGuard returns a Guard that allows the target hosts listed, and every address that is no
// loopback, link-local or unspecified one.
func loopbackGuard(listed ...string) *export.Guard {
	return &export.Guard{Allowed: func(context.Context) ([]string, error) { return listed, nil }}
}

// A target is checked when it is used (AUD1-DT-9, #457): a webhook on loopback that no admin lists is
// not called, however it came into the store, and it is once a listed prefix holds it.
func TestFeedCallsOnlyWhatTheGuardAllows(t *testing.T) {
	srv := newReceiver(t)
	j := &fakeJournal{}
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: srv.URL}, 0)
	j.add(event.NodeDown, "a")

	f := NewFeed(j, nil, "ranz-controller/test", 0)
	f.SetGuard(loopbackGuard())
	f.step(context.Background())
	if srv.calls.Load() != 0 || j.delivered("alerts") != 0 {
		t.Errorf("the webhook on loopback was called %d times and sent up to %d, want neither", srv.calls.Load(), j.delivered("alerts"))
	}
	if failed, _ := sampleValue(f, "webhook_deliveries", "alerts", "failed"); failed != 1 {
		t.Errorf("the refused delivery is counted as %d failures, want 1", failed)
	}

	f.SetGuard(loopbackGuard("127.0.0.0/8"))
	f.attempts = map[string]attempt{}
	f.step(context.Background())
	if got := srv.events(); len(got) != 1 || j.delivered("alerts") != 1 {
		t.Errorf("with the prefix listed the webhook got %+v and was sent up to %d, want the event", got, j.delivered("alerts"))
	}
}

// The IPFIX collector is checked when the exporter connects, and the connection again before each
// write, so that an address an admin takes out of the list is not written to any more.
func TestIPFIXConnectsOnlyWhereTheGuardAllows(t *testing.T) {
	pc := listenUDP(t)
	target := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://" + pc.addr}

	x, err := NewGuardedIPFIX(target, loopbackGuard())
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if err := x.Export("node-a", []Flow{testFlow(1)}); !errors.Is(err, export.ErrBlocked) {
		t.Errorf("exporting to a collector on loopback that is not listed gave %v, want export.ErrBlocked", err)
	}

	listed := true
	g := &export.Guard{Allowed: func(context.Context) ([]string, error) {
		if listed {
			return []string{"127.0.0.0/8"}, nil
		}
		return nil, nil
	}}
	y, err := NewGuardedIPFIX(target, g)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Close()
	if err := y.Export("node-a", []Flow{testFlow(1)}); err != nil {
		t.Fatalf("exporting to a listed collector: %v", err)
	}
	listed = false
	if err := y.Export("node-a", []Flow{testFlow(2)}); !errors.Is(err, export.ErrBlocked) {
		t.Errorf("exporting after the prefix was taken out of the list gave %v, want export.ErrBlocked", err)
	}
}
