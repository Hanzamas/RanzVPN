// The scale scenario of SDN-18 (#194, ADR-0026 decision 7) in the controller conformance seam: one controller serves a fleet of
// simulated nodes in many VRFs that advertise many routes, and the scenario measures how long each node takes to acknowledge a
// change, from the apply that makes it (internal/nodesim, scale.go). TestScaleSmall runs the whole scenario on 60 nodes with
// the other tests, under the race detector too. TestScale runs it at the size that RANZ_SCALE names, which ranz.yml sets: a
// tenth of the target for a pull request (pr), and the target itself, 10,000 nodes, 1,000 VRFs and 100,000 routes, for the
// full set (full). It writes what it measured to the directory that RANZ_SCALE_OUT names, for the performance gate, the job
// summary and the artifact of CI.
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newScaleHarness returns a harness for the scale scenario s: its controller has an Enterprise licence key for the nodes of s,
// takes thousands of streams from one address (every simulated node connects from 127.0.0.1, where a site of that size has an
// address for each node or a few NAT addresses; the limits for a source and the cap on the streams that wait for a Hello are
// raised so that they do not stand between the fleet and the controller), and logs warnings only: it would log six lines
// for each of the 10,000 nodes in each phase.
func newScaleHarness(t *testing.T, s nodesim.Scale) *harness {
	t.Helper()
	h := &harness{t: t, rq: rqlitetest.Fresh(t)}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.limits = port.Limits{MaxPending: 1 << 20, MaxPendingPerSource: 1 << 20, ConnectRate: 1e6, ConnectBurst: 1 << 20, HandshakeRate: 1e6, HandshakeBurst: 1 << 20}
	h.tune = func(cfg *controller.Config) {
		cfg.Waiting = control.NewWaiting(1<<20, 1<<20)
		cfg.Log = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	h.start()
	t.Cleanup(h.stop)
	h.setLicence(licence.Licence{ID: "scale", Licensee: "Test", Tier: licence.Enterprise, Nodes: s.Nodes, Expires: time.Now().Add(year)})
	return h
}

// scaleTarget returns the controller of h as the target of a scale run: the API for the applies, the list of the nodes and the
// intent, and the one address of its TLS port for the streams. The run stops the controller before it stops the nodes.
func (h *harness) scaleTarget() nodesim.ScaleTarget {
	return nodesim.ScaleTarget{
		Endpoints: []nodesim.Endpoint{{Address: h.ln.Addr().String(), Key: h.key.Public()}},
		Apply: func(ctx context.Context, doc intent.Document) (map[string]uint64, error) {
			res, err := h.api.Apply(ctx, doc)
			if err != nil {
				return nil, err
			}
			changed := make(map[string]uint64, len(res.Nodes))
			for _, n := range res.Nodes {
				changed[n.Name] = n.Generation
			}
			return changed, nil
		},
		Statuses: func(ctx context.Context) ([]nodesim.ScaleStatus, error) {
			nodes, err := h.api.Nodes(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]nodesim.ScaleStatus, 0, len(nodes))
			for _, n := range nodes {
				out = append(out, nodesim.ScaleStatus{Name: n.Name, Generation: n.Generation, Acked: n.AckedGeneration, Connected: n.Connected})
			}
			return out, nil
		},
		Resources: h.api.Resources,
		Quiesce:   h.stop,
		Log:       h.t.Logf,
	}
}

// checkScaleReport checks that the report of a run holds what the scenario s measured: every phase, every node in it, and
// percentiles in their order.
func checkScaleReport(t *testing.T, s nodesim.Scale, rep *nodesim.ScaleReport) {
	t.Helper()
	if len(rep.SetupApplyMs) != s.Batches {
		t.Errorf("the report holds %d applies of the setup, want %d", len(rep.SetupApplyMs), s.Batches)
	}
	if rep.Enrol.Nodes != s.Nodes || rep.Enrol.Ack.Count != s.Nodes || rep.Enrol.PerSecond <= 0 {
		t.Errorf("the enrolment in the report is %+v, want %d nodes and a rate", rep.Enrol, s.Nodes)
	}
	if len(rep.Changes) != s.Runs {
		t.Fatalf("the report holds %d changes of every VRF, want %d", len(rep.Changes), s.Runs)
	}
	for _, c := range append(rep.Changes, rep.Route) {
		want := s.Nodes
		if c.Name == "route" {
			want = s.PerVRF()
		}
		if c.Nodes != want || c.Ack.Count != want || len(c.ApplyMs) == 0 {
			t.Errorf("%s in the report has %d nodes and %d applies, want %d nodes", c.Name, c.Nodes, len(c.ApplyMs), want)
		}
		a := c.Ack
		if !(0 < a.MinMs && a.MinMs <= a.P50Ms && a.P50Ms <= a.P90Ms && a.P90Ms <= a.P95Ms && a.P95Ms <= a.P99Ms && a.P99Ms <= a.MaxMs) {
			t.Errorf("%s: the percentiles of the apply-to-ack latency are out of order: %+v", c.Name, a)
		}
	}
}

// TestScaleSmall runs the scale scenario on a small fleet: the VRFs are declared in two applies, the nodes enrol, the MTU of
// every VRF changes, and a route changes, and at the end each node is at the generation that it acknowledged, with the state of
// the intent and the updates that its changes called for and no others. It runs with the other tests, so every pull request
// that changes the controller shows it, but not beside them: the streams of its fleet and the applies that compile its intent
// would slow the tests that run in parallel, some of which wait for a stream to end or to begin again.
func TestScaleSmall(t *testing.T) {
	rqlitetest.Alone(t)
	s := nodesim.SmallScale
	h := newScaleHarness(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	rep, err := nodesim.RunScale(ctx, h.scaleTarget(), s)
	if err != nil {
		t.Fatal(err)
	}
	checkScaleReport(t, s, rep)
}

// TestScale is the scale test of #194 at the size that RANZ_SCALE names, pr or full, and skipped without it. It runs alone, on an
// rqlited of its own, since its numbers are what ranz.yml records for the performance gate.
func TestScale(t *testing.T) {
	var s nodesim.Scale
	switch size := os.Getenv("RANZ_SCALE"); size {
	case "":
		t.Skip("RANZ_SCALE is not set: set it to pr (a tenth of the scale target) or full (10,000 nodes, 1,000 VRFs and 100,000 routes) to run the scale test")
	case "pr":
		s = nodesim.ReducedScale
	case "full":
		s = nodesim.FullScale
	default:
		t.Fatalf("RANZ_SCALE is %q, want pr or full", size)
	}
	rqlitetest.Own(t)
	rqlitetest.Alone(t)
	h := newScaleHarness(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()
	rep, err := nodesim.RunScale(ctx, h.scaleTarget(), s)
	if dir := os.Getenv("RANZ_SCALE_OUT"); dir != "" && rep != nil {
		if werr := rep.Write(dir); werr != nil {
			t.Errorf("writing the report to %s: %v", dir, werr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	checkScaleReport(t, s, rep)
	t.Log("\n" + rep.Markdown())
}
