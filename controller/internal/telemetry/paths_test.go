package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The Upgrades and the Fallbacks of the Paths of a node (CORE-S5-6, #412): the Hub keeps the last
// counts that the node reported, a summary without them leaves them as they were, and the export
// has them as ranz_path_upgrades_total and ranz_path_fallbacks_total of the node. A node that
// reported none has no series.
func TestHubKeepsAndExportsTheUpgradesAndFallbacks(t *testing.T) {
	h := NewHub(0)
	h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 1}})
	h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 2, Fallbacks: 1}})
	h.Report("node-a", summary(5))
	h.Report("node-b", summary(1))
	snap := h.Snapshot(nil)
	if len(snap) != 2 || snap[0].Paths == nil || *snap[0].Paths != (PathCounters{Upgrades: 2, Fallbacks: 1}) || snap[1].Paths != nil {
		t.Fatalf("the snapshot holds %+v, want the last Paths of node-a and none of node-b", snap)
	}

	rec := httptest.NewRecorder()
	Handler(func() []Sample { return h.Samples(nil) }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	text := rec.Body.String()
	for _, want := range []string{
		"# TYPE ranz_path_upgrades_total counter",
		`ranz_path_upgrades_total{node="node-a"} 2`,
		"# TYPE ranz_path_fallbacks_total counter",
		`ranz_path_fallbacks_total{node="node-a"} 1`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the metrics do not hold %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `ranz_path_upgrades_total{node="node-b"}`) || strings.Contains(text, `ranz_path_fallbacks_total{node="node-b"}`) {
		t.Errorf("node-b reported no Paths, and the metrics have a series of its Paths:\n%s", text)
	}
}

// The Paths that a node stopped reporting go stale as its other counters do, and a node that
// reported nothing but its Paths stays while they are fresh.
func TestHubDropsStalePaths(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	h := NewHub(time.Minute)
	h.now = func() time.Time { return now }
	h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 3, Fallbacks: 2}})
	now = now.Add(50 * time.Second)
	if snap := h.Snapshot(nil); len(snap) != 1 || snap[0].Paths == nil || *snap[0].Paths != (PathCounters{Upgrades: 3, Fallbacks: 2}) {
		t.Fatalf("50 s after its Paths the Hub holds %+v, want them", snap)
	}
	now = now.Add(20 * time.Second)
	if snap := h.Snapshot(nil); len(snap) != 0 {
		t.Errorf("70 s after its Paths, with nothing else reported, the Hub still holds %+v", snap)
	}
}
