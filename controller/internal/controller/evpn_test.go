// Controller conformance for the counters of the EVPN of a gateway (SDN-25-R3 #571, ADR-0030 decision 3), with the harness
// and the node simulator of conformance_test.go.
package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// TestTheFramesOfUnknownVtepsReachTheExport is the third criterion of #571 at the controller: the counters of the EVPN of a
// gateway that a node reports on its control stream are in the Prometheus export, the frames of unknown VTEPs as
// ranz_evpn_dropped_frames_total{reason="unknown-vtep"} of the node, and in the JSON of the API, and each later summary
// replaces them.
func TestTheFramesOfUnknownVtepsReachTheExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	b1 := h.joined()
	if err := b1.Telemetry(&controlpb.Telemetry{Evpn: &controlpb.EvpnCounters{UnknownVtep: 1}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_evpn_dropped_frames_total{node="branch-1",reason="unknown-vtep"} 1`, `ranz_evpn_packets_total{direction="tx",node="branch-1"} 0`)

	if err := b1.Telemetry(&controlpb.Telemetry{Evpn: &controlpb.EvpnCounters{Sent: 3, Delivered: 2, UnknownVtep: 9, UnknownVni: 4}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_evpn_dropped_frames_total{node="branch-1",reason="unknown-vtep"} 9`, `ranz_evpn_dropped_frames_total{node="branch-1",reason="unknown-vni"} 4`,
		`ranz_evpn_packets_total{direction="tx",node="branch-1"} 3`, `ranz_evpn_packets_total{direction="rx",node="branch-1"} 2`)

	snap, err := h.api.Telemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 || snap[0].Node != "branch-1" || snap[0].EVPN == nil || snap[0].EVPN.UnknownVtep != 9 || snap[0].EVPN.Sent != 3 {
		t.Errorf("the telemetry of the API is %+v, want the EVPN of branch-1 with 9 frames of unknown VTEPs", snap)
	}
}
