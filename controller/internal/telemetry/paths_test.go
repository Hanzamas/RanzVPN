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

// The punches of a node (CORE-S5-7, #413): the Hub keeps the attempts, the successes and the
// failures of the prediction that the node reported last with its Paths, and the export has them as
// ranz_path_punch_attempts_total, ranz_path_punch_successes_total and
// ranz_path_punch_failures_total of the node, next to its Upgrades and Fallbacks, and in the JSON.
func TestHubKeepsAndExportsThePunches(t *testing.T) {
	h := NewHub(0)
	h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{PunchAttempts: 1, PunchFailures: 1}})
	h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 1, PunchAttempts: 4, PunchSuccesses: 1, PunchFailures: 3}})
	h.Report("node-b", summary(1))
	want := PathCounters{Upgrades: 1, PunchAttempts: 4, PunchSuccesses: 1, PunchFailures: 3}
	snap := h.Snapshot(nil)
	if len(snap) != 2 || snap[0].Paths == nil || *snap[0].Paths != want || snap[1].Paths != nil {
		t.Fatalf("the snapshot holds %+v, want the last punches of node-a and none of node-b", snap)
	}

	data, err := json.Marshal(snap[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"paths":{"upgrades":1,"fallbacks":0,"punchAttempts":4,"punchSuccesses":1,"punchFailures":3}`) {
		t.Errorf("the JSON of node-a is %s, want its punches with its Paths", data)
	}

	rec := httptest.NewRecorder()
	Handler(func() []Sample { return h.Samples(nil) }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	text := rec.Body.String()
	for _, want := range []string{
		"# TYPE ranz_path_punch_attempts_total counter",
		`ranz_path_punch_attempts_total{node="node-a"} 4`,
		"# TYPE ranz_path_punch_successes_total counter",
		`ranz_path_punch_successes_total{node="node-a"} 1`,
		"# TYPE ranz_path_punch_failures_total counter",
		`ranz_path_punch_failures_total{node="node-a"} 3`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the metrics do not hold %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `ranz_path_punch_attempts_total{node="node-b"}`) {
		t.Errorf("node-b reported no Paths, and the metrics have a series of its punches:\n%s", text)
	}
}

// nodePathRefresh is how often a node lists its Paths again while they stay the same:
// CONTROL_PATH_REFRESH of the C node (src/Core/Control.h).
const nodePathRefresh = 15 * time.Second

// A node whose Paths stay the same, as they do for hours on a node whose pairs keep their paths,
// lists them again every nodePathRefresh: the Hub keeps them in the export for as long as it does,
// well past the stale time of a counter, and drops them once it stopped.
func TestHubKeepsThePathsOfAStableNode(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	h := NewHub(0)
	h.now = func() time.Time { return now }
	want := PathCounters{Upgrades: 1, Fallbacks: 1}
	for since := time.Duration(0); since <= 3*DefaultStale; since += nodePathRefresh {
		h.Report("node-a", &controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: want.Upgrades, Fallbacks: want.Fallbacks}})
		now = now.Add(nodePathRefresh - time.Second)
		if snap := h.Snapshot(nil); len(snap) != 1 || snap[0].Paths == nil || *snap[0].Paths != want {
			t.Fatalf("%s after the first report of the same Paths every %s, the Hub holds %+v, want them", since+nodePathRefresh-time.Second, nodePathRefresh, snap)
		}
		now = now.Add(time.Second)
	}
	samples := h.Samples(nil)
	if len(samples) != 5 || samples[0].Metric != "path_upgrades" || samples[0].Value != 1 || samples[1].Metric != "path_fallbacks" || samples[1].Value != 1 ||
		samples[2].Metric != "path_punch_attempts" || samples[3].Metric != "path_punch_successes" || samples[4].Metric != "path_punch_failures" {
		t.Errorf("the export of node-a after %s holds %+v, want its Upgrades and Fallbacks and its punches", 3*DefaultStale, samples)
	}
	now = now.Add(DefaultStale + time.Second)
	if snap := h.Snapshot(nil); len(snap) != 0 {
		t.Errorf("past the stale time after node-a stopped listing its Paths, the Hub still holds %+v", snap)
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
