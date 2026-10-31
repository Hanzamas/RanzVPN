package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The counters of the source groups (SDN-87): the Hub keeps the latest of each tag mode that a node reports,
// unspecified as off, leaves out a mode that it has no name for, drops them when they go stale, and exports them
// as source_group_packets by node, mode and result.
func TestHubKeepsTheSourceGroups(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	h := NewHub(time.Minute)
	h.now = func() time.Time { return now }
	h.Report("node-b", &controlpb.Telemetry{Groups: []*controlpb.SourceGroupCounters{
		{Mode: controlpb.TagMode_TAG_MODE_SESSION, Carried: 10, Missing: 1, Refused: 2},
		{Mode: controlpb.TagMode_TAG_MODE_UNSPECIFIED, Missing: 3, Ignored: 4},
		{Mode: controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY, Carried: 5, Refused: 6},
		{Mode: controlpb.TagMode(99), Carried: 7},
	}})
	h.Report("node-b", &controlpb.Telemetry{Groups: []*controlpb.SourceGroupCounters{{Mode: controlpb.TagMode_TAG_MODE_SESSION, Carried: 12, Missing: 1, Refused: 2}}})
	snap := h.Snapshot(nil)
	if len(snap) != 1 {
		t.Fatalf("the snapshot holds %+v, want node-b", snap)
	}
	want := []SourceGroupCounters{
		{Mode: ModeOff, Missing: 3, Ignored: 4},
		{Mode: ModeSession, Carried: 12, Missing: 1, Refused: 2},
		{Mode: ModeTrustedUnderlay, Carried: 5, Refused: 6},
	}
	if got := snap[0].SourceGroups; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("the source groups of node-b are %+v, want %+v", got, want)
	}

	rec := httptest.NewRecorder()
	Handler(func() []Sample { return h.Samples(nil) }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, line := range []string{
		`ranz_source_group_packets_total{mode="session",node="node-b",result="carried"} 12`,
		`ranz_source_group_packets_total{mode="session",node="node-b",result="refused"} 2`,
		`ranz_source_group_packets_total{mode="off",node="node-b",result="ignored"} 4`,
		`ranz_source_group_packets_total{mode="trusted-underlay",node="node-b",result="refused"} 6`,
		`ranz_source_group_packets_total{mode="trusted-underlay",node="node-b",result="missing"} 0`,
	} {
		if !strings.Contains(rec.Body.String(), line+"\n") {
			t.Errorf("the scrape does not hold %q:\n%s", line, rec.Body.String())
		}
	}

	// The modes that the node does not report again go stale, and so does the node
	now = now.Add(50 * time.Second)
	h.Report("node-b", &controlpb.Telemetry{Groups: []*controlpb.SourceGroupCounters{{Mode: controlpb.TagMode_TAG_MODE_SESSION, Carried: 13}}})
	now = now.Add(30 * time.Second)
	if got := h.Snapshot(nil)[0].SourceGroups; len(got) != 1 || got[0].Mode != ModeSession || got[0].Carried != 13 {
		t.Errorf("80 s after the first summary and 30 s after the last, node-b holds %+v, want the mode session alone", got)
	}
	now = now.Add(time.Minute)
	if snap := h.Snapshot(nil); len(snap) != 0 {
		t.Errorf("a node that reported nothing for a minute is still held: %+v", snap)
	}
}
