package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The counters of the tag mode hmac (SDN-88): the Hub keeps them beside the other modes of a node, with the
// packets whose MAC the node could not verify, and exports them as source_group_packets with the result
// unauthenticated, which every mode has.
func TestHubKeepsTheHMACCounters(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	h := NewHub(time.Minute)
	h.now = func() time.Time { return now }
	h.Report("node-b", &controlpb.Telemetry{Groups: []*controlpb.SourceGroupCounters{
		{Mode: controlpb.TagMode_TAG_MODE_OFF},
		{Mode: controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY},
		{Mode: controlpb.TagMode_TAG_MODE_SESSION, Carried: 3},
		{Mode: controlpb.TagMode_TAG_MODE_HMAC, Carried: 20, Missing: 1, Unauthenticated: 6},
	}})
	snap := h.Snapshot(nil)
	if len(snap) != 1 {
		t.Fatalf("the snapshot holds %+v, want node-b", snap)
	}
	var hmac *SourceGroupCounters
	for i, g := range snap[0].SourceGroups {
		if g.Mode == ModeHMAC {
			hmac = &snap[0].SourceGroups[i]
		}
	}
	if len(snap[0].SourceGroups) != 4 || hmac == nil || *hmac != (SourceGroupCounters{Mode: ModeHMAC, Carried: 20, Missing: 1, Unauthenticated: 6}) {
		t.Errorf("the source groups of node-b are %+v, want the four modes with hmac carried 20, missing 1, unauthenticated 6", snap[0].SourceGroups)
	}

	rec := httptest.NewRecorder()
	Handler(func() []Sample { return h.Samples(nil) }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, line := range []string{
		`ranz_source_group_packets_total{mode="hmac",node="node-b",result="carried"} 20`,
		`ranz_source_group_packets_total{mode="hmac",node="node-b",result="unauthenticated"} 6`,
		`ranz_source_group_packets_total{mode="session",node="node-b",result="unauthenticated"} 0`,
	} {
		if !strings.Contains(rec.Body.String(), line+"\n") {
			t.Errorf("the scrape does not hold %q:\n%s", line, rec.Body.String())
		}
	}
}
