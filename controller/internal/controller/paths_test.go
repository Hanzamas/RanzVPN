// Controller conformance for the Paths of the peer agent of a node (CORE-S5-6 #412, ADR-0030
// decision 3), with the harness and the node simulator of conformance_test.go.
package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// TestUpgradesAndFallbacksReachTheExport is the fifth criterion of #412 at the controller: the
// Upgrades and the Fallbacks of the Paths that a node reports on its control stream are in the
// Prometheus export, as ranz_path_upgrades_total and ranz_path_fallbacks_total of the node, and in
// the JSON of the API, and each later summary replaces them.
func TestUpgradesAndFallbacksReachTheExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	b1 := h.joined()
	if err := b1.Telemetry(&controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 1}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_path_upgrades_total{node="branch-1"} 1`, `ranz_path_fallbacks_total{node="branch-1"} 0`)

	if err := b1.Telemetry(&controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 2, Fallbacks: 1}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_path_upgrades_total{node="branch-1"} 2`, `ranz_path_fallbacks_total{node="branch-1"} 1`)

	snap, err := h.api.Telemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 || snap[0].Node != "branch-1" || snap[0].Paths == nil || snap[0].Paths.Upgrades != 2 || snap[0].Paths.Fallbacks != 1 {
		t.Errorf("the telemetry of the API is %+v, want the Paths of branch-1 with 2 Upgrades and 1 Fallback", snap)
	}
}

// TestPunchesReachTheExport is the fifth criterion of #413 at the controller: the attempts, the
// successes and the failures of the prediction of the punches that a node reports with its Paths on
// its control stream are in the Prometheus export, as ranz_path_punch_attempts_total,
// ranz_path_punch_successes_total and ranz_path_punch_failures_total of the node, and in the JSON of
// the API, and each later summary replaces them.
func TestPunchesReachTheExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	b1 := h.joined()
	if err := b1.Telemetry(&controlpb.Telemetry{Paths: &controlpb.PathCounters{PunchAttempts: 3, PunchFailures: 3}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_path_punch_attempts_total{node="branch-1"} 3`, `ranz_path_punch_successes_total{node="branch-1"} 0`, `ranz_path_punch_failures_total{node="branch-1"} 3`)

	if err := b1.Telemetry(&controlpb.Telemetry{Paths: &controlpb.PathCounters{Upgrades: 1, PunchAttempts: 4, PunchSuccesses: 1, PunchFailures: 3}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_path_punch_attempts_total{node="branch-1"} 4`, `ranz_path_punch_successes_total{node="branch-1"} 1`, `ranz_path_punch_failures_total{node="branch-1"} 3`,
		`ranz_path_upgrades_total{node="branch-1"} 1`)

	snap, err := h.api.Telemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 || snap[0].Paths == nil || snap[0].Paths.PunchAttempts != 4 || snap[0].Paths.PunchSuccesses != 1 || snap[0].Paths.PunchFailures != 3 {
		t.Errorf("the telemetry of the API is %+v, want the punches of branch-1: 4 attempts, 1 success and 3 failures", snap)
	}
}
