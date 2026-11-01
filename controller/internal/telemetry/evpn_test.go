package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The EVPN of a gateway (SDN-25-R3, #571): the Hub keeps the last counters that the node reported, a summary without them
// leaves them as they were, the JSON has them, and the export has them as ranz_evpn_packets_total by direction and
// ranz_evpn_dropped_frames_total by reason, the frames of unknown VTEPs among them. A node that reported none has no series.
func TestHubKeepsAndExportsTheEVPN(t *testing.T) {
	h := NewHub(0)
	h.Report("gw", &controlpb.Telemetry{Evpn: &controlpb.EvpnCounters{UnknownVtep: 1}})
	h.Report("gw", &controlpb.Telemetry{Evpn: &controlpb.EvpnCounters{Sent: 6, Failed: 4, Delivered: 5, Undelivered: 1, UnknownVtep: 7, Strangers: 1, NotOurs: 1, UnknownVni: 2, Malformed: 3}})
	h.Report("gw", summary(5))
	h.Report("node-b", summary(1))
	want := EvpnCounters{Sent: 6, Failed: 4, Delivered: 5, Undelivered: 1, UnknownVtep: 7, Strangers: 1, NotOurs: 1, UnknownVni: 2, Malformed: 3}
	snap := h.Snapshot(nil)
	if len(snap) != 2 || snap[0].EVPN == nil || *snap[0].EVPN != want || snap[1].EVPN != nil {
		t.Fatalf("the snapshot holds %+v, want the last EVPN of gw and none of node-b", snap)
	}

	data, err := json.Marshal(snap[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"evpn":{"sent":6,"failed":4,"delivered":5,"undelivered":1,"unknownVtep":7,"strangers":1,"notOurs":1,"unknownVni":2,"malformed":3}`) {
		t.Errorf("the JSON of gw is %s, want its EVPN", data)
	}

	rec := httptest.NewRecorder()
	Handler(func() []Sample { return h.Samples(nil) }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	text := rec.Body.String()
	for _, want := range []string{
		"# TYPE ranz_evpn_packets_total counter",
		`ranz_evpn_packets_total{direction="tx",node="gw"} 6`,
		`ranz_evpn_packets_total{direction="rx",node="gw"} 5`,
		"# TYPE ranz_evpn_dropped_frames_total counter",
		`ranz_evpn_dropped_frames_total{node="gw",reason="unknown-vtep"} 7`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="stranger"} 1`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="not-ours"} 1`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="unknown-vni"} 2`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="malformed"} 3`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="undelivered"} 1`,
		`ranz_evpn_dropped_frames_total{node="gw",reason="failed"} 4`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the metrics do not hold %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `node="node-b",reason=`) || strings.Contains(text, `ranz_evpn_packets_total{direction="tx",node="node-b"}`) {
		t.Errorf("node-b reported no EVPN, and the metrics have a series of its EVPN:\n%s", text)
	}
}

// The EVPN that a node stopped reporting, as its EVPN stopped, goes stale as its other counters do, and a node that reported
// nothing but its EVPN stays while it is fresh.
func TestHubDropsAStaleEVPN(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	h := NewHub(time.Minute)
	h.now = func() time.Time { return now }
	h.Report("gw", &controlpb.Telemetry{Evpn: &controlpb.EvpnCounters{UnknownVtep: 3}})
	now = now.Add(50 * time.Second)
	if snap := h.Snapshot(nil); len(snap) != 1 || snap[0].EVPN == nil || snap[0].EVPN.UnknownVtep != 3 {
		t.Fatalf("50 s after its EVPN the Hub holds %+v, want it", snap)
	}
	now = now.Add(20 * time.Second)
	if snap := h.Snapshot(nil); len(snap) != 0 {
		t.Errorf("70 s after its EVPN, with nothing else reported, the Hub still holds %+v", snap)
	}
}
