// The Events page shows the session flap (AUD1-DT-11 #459; NS-12 of docs/threat-model.md), with the harness of ui_test.go:
// the controller serves the API and the UI on one TLS port, the node simulator reports that the session of a peer was
// replaced again and again by two holders of one key, and a headless Chrome reads the page (ADR-0038). Without rqlited
// (RQLITED) or a Chrome, the test is skipped, except under CI, where it fails.
package webui_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestTheEventsPageShowsASessionFlap is what the ticket asks of the web UI: the event that a node reports shows on the
// Events page of a viewer, with the type, the node that reported it, the peer and the message that names both addresses.
func TestTheEventsPageShowsASessionFlap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	nodeKey := newKey(t)
	if _, err := h.admin.Apply(ctx, document(nodeKey)); err != nil {
		t.Fatal(err)
	}

	node := &nodesim.Node{Key: nodeKey, Controller: h.ln.Addr().String(), ControllerKey: h.key.Public(),
		Capabilities: &controlpb.Capabilities{Sku: controlpb.Sku_SKU_PRO, Architecture: controlpb.Architecture_ARCHITECTURE_X64}}
	sctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- node.Serve(sctx) }()
	t.Cleanup(func() {
		stop()
		<-served
	})
	h.waitNode(t, "branch-1", 1)

	const message = "the session of peer branch-2 was replaced 5 times in 60 s, by sessions from 198.51.100.4 and 203.0.113.9"
	if err := node.Telemetry(&controlpb.Telemetry{Events: []*controlpb.NodeEvent{
		{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, Subject: "branch-2", Message: message}}}); err != nil {
		t.Fatal(err)
	}

	// The controller raises the event as it takes the summary: wait until the API lists it, then open the page
	deadline := time.Now().Add(waitTimeout)
	for {
		evs, err := h.admin.Events(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) == 1 {
			if e := evs[0]; e.Type != event.SessionFlap || e.Node != "branch-1" || e.Subject != "branch-2" || e.Message != message {
				t.Fatalf("the API lists %+v for the session flap", e)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the API lists %d events within %v, want the session flap", len(evs), waitTimeout)
		}
		time.Sleep(pollInterval)
	}

	tab := newBrowser(t)
	h.signIn(t, tab, h.token(t, "viewer-1", rbac.Viewer))
	h.visit(t, tab, "/events", "events")
	row := run(t, tab, chromedp.Text(chromedp.Search(`//tr[td[2][normalize-space()="session-flap"]]`)))
	for _, want := range []string{"session-flap", "branch-1", "branch-2", "198.51.100.4", "203.0.113.9"} {
		if !strings.Contains(row, want) {
			t.Errorf("the row of the session flap on the Events page has no %q: %q", want, row)
		}
	}
}
