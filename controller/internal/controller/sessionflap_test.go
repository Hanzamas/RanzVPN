// Controller conformance for the session flap Event (AUD1-DT-11 #459; NS-12 of docs/threat-model.md), with the
// harness and the node simulator of conformance_test.go: the summary of a node that reports two holders of one key
// replacing the session of a peer again and again becomes the Event session-flap, which the API lists as
// `ranz get events` prints it, a webhook that wants its type is sent, and the metrics count.
package controller_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// flapReport is the Telemetry of a node whose events are the ones given.
func flapReport(events ...*controlpb.NodeEvent) *controlpb.Telemetry {
	return &controlpb.Telemetry{Events: events}
}

// TestSessionFlapReachesTheEvents is the third criterion of AUD1-DT-11 at the controller: the event that a
// node reports when the session of a peer was replaced again and again is an Event of the type session-flap,
// with the node that reported it, the peer and the message that names the addresses. The API lists it, which is
// what `ranz get events` prints, a webhook that wants only this type is sent it, and the metrics count it from 0.
func TestSessionFlapReachesTheEvents(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	w := newWebhook(t)
	// A webhook that wants this type and no other: the type is one that a target may name
	h.putTarget(export.Target{Name: "keys", Kind: export.KindWebhook, URL: w.URL, Secret: "s3cret", Types: []string{event.SessionFlap}})
	b1 := h.joined()

	// Zero before there is an event, so that an alert on increase() sees the first one
	h.waitMetrics(`ranz_events_total{type="session-flap"} 0`)
	if evs := h.events(); len(evs) != 0 {
		t.Fatalf("the API lists %+v before any node reported anything", evs)
	}

	// A type that this controller does not know is skipped, as one of an older release would skip this one
	const message = "the session of peer branch-2 was replaced 5 times in 60 s, by sessions from 198.51.100.4 and 203.0.113.9"
	if err := b1.Telemetry(flapReport(&controlpb.NodeEvent{Type: controlpb.NodeEventType(99), Subject: "branch-2", Message: "from the future"})); err != nil {
		t.Fatal(err)
	}
	if err := b1.Telemetry(flapReport(&controlpb.NodeEvent{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, Subject: "branch-2", Message: message})); err != nil {
		t.Fatal(err)
	}

	// The webhook is sent the Event, with the signature and the type in its headers
	got, call := w.next(t)
	if got.Type != event.SessionFlap || got.Node != "branch-1" || got.Subject != "branch-2" || got.Message != message || got.ID == 0 || got.Time.IsZero() {
		t.Errorf("the webhook got %+v for the session flap", got)
	}
	if typ := call.header.Get("X-Ranz-Event"); typ != event.SessionFlap {
		t.Errorf("X-Ranz-Event is %q, want %q", typ, event.SessionFlap)
	}
	if call.header.Get("X-Ranz-Signature") == "" {
		t.Errorf("the webhook with a secret got no signature")
	}

	// The API lists it: the one event, the type that was skipped made none
	h.waitMetrics(`ranz_events_total{type="session-flap"} 1`)
	evs := h.events()
	if len(evs) != 1 {
		t.Fatalf("the API lists %d events, want the one session flap: %+v", len(evs), evs)
	}
	if e := evs[0]; e.ID != got.ID || e.Type != event.SessionFlap || e.Node != "branch-1" || e.Subject != "branch-2" || e.Message != message || !e.Time.Equal(got.Time) {
		t.Errorf("the API lists %+v, the webhook got %+v", e, got)
	}
	for _, addr := range []string{"198.51.100.4", "203.0.113.9"} {
		if !strings.Contains(evs[0].Message, addr) {
			t.Errorf("the message of the event does not name the address %s: %q", addr, evs[0].Message)
		}
	}

	// A report with no message gets one that names the node and the peer, and a peer name that is too long is cut
	long := strings.Repeat("p", 100)
	if err := b1.Telemetry(flapReport(
		&controlpb.NodeEvent{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, Subject: "branch-3"},
		&controlpb.NodeEvent{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, Subject: long, Message: strings.Repeat("m", 300)})); err != nil {
		t.Fatal(err)
	}
	second, _ := w.next(t)
	third, _ := w.next(t)
	if want := "the session of peer branch-3 of node branch-1 was replaced again and again"; second.Subject != "branch-3" || second.Message != want {
		t.Errorf("the report with no message became %+v, want the message %q", second, want)
	}
	if third.Subject != long[:63] || len(third.Message) != 255 {
		t.Errorf("the report with a long name and message became a subject of %d and a message of %d bytes, want 63 and 255", len(third.Subject), len(third.Message))
	}
	h.waitMetrics(`ranz_events_total{type="session-flap"} 3`)
	if evs := h.events(); len(evs) != 3 || evs[1].ID != second.ID || evs[2].ID != third.ID {
		t.Errorf("the API lists %+v, want the three session flaps in the order they were reported", evs)
	}
}

// TestSessionFlapTypeFilterOfAWebhook checks that a webhook that wants another type is sent no session flap,
// and that one without a filter is sent it.
func TestSessionFlapTypeFilterOfAWebhook(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	other := newWebhook(t)
	all := newWebhook(t)
	h.putTarget(export.Target{Name: "other", Kind: export.KindWebhook, URL: other.URL, Types: []string{event.NodeDown}})
	h.putTarget(export.Target{Name: "all", Kind: export.KindWebhook, URL: all.URL})
	b1 := h.joined()

	if err := b1.Telemetry(flapReport(&controlpb.NodeEvent{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, Subject: "branch-2", Message: "flap"})); err != nil {
		t.Fatal(err)
	}
	if got, _ := all.next(t); got.Type != event.SessionFlap || got.Subject != "branch-2" {
		t.Errorf("the webhook without a filter got %+v", got)
	}
	other.quiet(t, time.Second)
}
