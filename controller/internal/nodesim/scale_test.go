package nodesim

// The scale scenario (SDN-18, #194) without a controller: the intent that it declares is accepted by the rules of the intent and
// compiles to the states that the scenario promises, each change reaches the nodes that it names and no others, and the
// Fleet and the report do what the run relies on. The run against a controller is TestScale and TestScaleSmall of
// internal/controller.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

func TestScaleValidate(t *testing.T) {
	for _, s := range []Scale{FullScale, ReducedScale, SmallScale} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	for _, c := range []struct {
		name string
		s    Scale
	}{
		{"no nodes", Scale{VRFs: 1, Routes: 1}},
		{"nodes that do not divide into the VRFs", Scale{Nodes: 25, VRFs: 10, Routes: 250}},
		{"routes that do not divide among the nodes", Scale{Nodes: 20, VRFs: 2, Routes: 25}},
		{"one node in a VRF", Scale{Nodes: 4, VRFs: 4, Routes: 4}},
		{"more routes for a node than the protocol carries", Scale{Nodes: 20, VRFs: 2, Routes: 20 * 16}},
		{"VRFs that do not divide into the batches", Scale{Nodes: 60, VRFs: 6, Routes: 60, Batches: 4}},
		{"a negative number of runs", Scale{Nodes: 20, VRFs: 2, Routes: 20, Runs: -1}},
	} {
		if err := c.s.Validate(); err == nil {
			t.Errorf("%s: %+v was accepted", c.name, c.s)
		}
	}
	if FullScale.Nodes != 10000 || FullScale.VRFs != 1000 || FullScale.Routes != 100000 {
		t.Errorf("FullScale is %+v, not the scale target of ADR-0026: 10,000 nodes, 1,000 VRFs and 100,000 routes", FullScale)
	}
	if ReducedScale.Nodes*10 != FullScale.Nodes || ReducedScale.VRFs*10 != FullScale.VRFs || ReducedScale.Routes*10 != FullScale.Routes {
		t.Errorf("ReducedScale is %+v, not a tenth of FullScale", ReducedScale)
	}
}

// changedNodes returns the names of the nodes whose state differs between before and after, in order.
func changedNodes(before, after map[string]desired.State) []string {
	var out []string
	for name, st := range after {
		if !desired.Equal(before[name], st) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// TestScaleIntent applies the documents of the scenario as the controller does, and checks what the scenario says of it: the
// resources and routes that it declares, a Peer for every other node of a VRF with the routes of that node, the nodes that
// each change touches, and the ones that it leaves alone.
func TestScaleIntent(t *testing.T) {
	s := SmallScale
	docs, err := s.Setup()
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != s.Batches {
		t.Fatalf("Setup returned %d documents for %d batches", len(docs), s.Batches)
	}
	in := intent.New()
	for b, doc := range docs {
		if want := s.VRFs / s.Batches * (3 + s.PerVRF()); len(doc.Resources) != want {
			t.Errorf("batch %d has %d resources, want %d", b+1, len(doc.Resources), want)
		}
		if in, err = intent.Apply(in, doc, nil); err != nil {
			t.Fatalf("applying batch %d: %v", b+1, err)
		}
	}
	if len(in.VRFs) != s.VRFs || len(in.Networks) != s.VRFs || len(in.Policies) != s.VRFs || len(in.Nodes) != s.Nodes {
		t.Errorf("the intent has %d VRFs, %d Networks, %d Policies and %d Nodes, want %d VRFs and Networks and Policies and %d Nodes",
			len(in.VRFs), len(in.Networks), len(in.Policies), len(in.Nodes), s.VRFs, s.Nodes)
	}
	if got := len(in.Routes()); got != s.Routes {
		t.Errorf("the intent has %d routes, want %d", got, s.Routes)
	}
	states, err := desired.Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != s.Nodes {
		t.Fatalf("the intent compiles to the states of %d nodes, want %d", len(states), s.Nodes)
	}
	for name, st := range states {
		peers := 0
		for k, o := range st {
			switch k.Kind {
			case controlpb.Kind_KIND_PEER:
				peers++
				if got := len(o.GetPeer().GetRoutes()); got != s.PerNode() {
					t.Errorf("%s: peer %s has %d routes, want %d", name, k.Name, got, s.PerNode())
				}
			case controlpb.Kind_KIND_NODE:
				if got := len(o.GetNode().GetLanSubnets()); got != s.PerNode() {
					t.Errorf("%s advertises %d LAN subnets, want %d", name, got, s.PerNode())
				}
			}
		}
		if peers != s.PerVRF()-1 {
			t.Errorf("%s has %d peers, want the %d other nodes of its VRF", name, peers, s.PerVRF()-1)
		}
	}

	// Every change touches the nodes that it names, in every batch and every run, and no other node
	for run := range 2 {
		for b := range s.batches() {
			doc, names, err := s.Change(run, b)
			if err != nil {
				t.Fatal(err)
			}
			next, err := intent.Apply(in, doc, nil)
			if err != nil {
				t.Fatalf("applying the change %d of batch %d: %v", run+1, b+1, err)
			}
			after, err := desired.Compile(next)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := changedNodes(states, after), slices.Sorted(slices.Values(names)); !slices.Equal(got, want) {
				t.Errorf("the change %d of batch %d changed the states of %d nodes %v, want the %d nodes of its VRFs %v", run+1, b+1, len(got), got, len(want), want)
			}
			in, states = next, after
		}
	}
	doc, names, err := s.RouteChange()
	if err != nil {
		t.Fatal(err)
	}
	next, err := intent.Apply(in, doc, nil)
	if err != nil {
		t.Fatalf("applying the change of a route: %v", err)
	}
	after, err := desired.Compile(next)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := changedNodes(states, after), slices.Sorted(slices.Values(names)); !slices.Equal(got, want) {
		t.Errorf("the change of a route changed the states of %v, want the nodes of the first VRF %v", got, want)
	}
	if got := len(next.Routes()); got != s.Routes+1 {
		t.Errorf("the intent has %d routes after the change of a route, want %d", got, s.Routes+1)
	}
}

func TestSummarize(t *testing.T) {
	var d []time.Duration
	for i := 100; i >= 1; i-- {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	got := Summarize(d)
	want := ScaleStats{Count: 100, MinMs: 1, MeanMs: 50.5, P50Ms: 50, P90Ms: 90, P95Ms: 95, P99Ms: 99, MaxMs: 100}
	if got != want {
		t.Errorf("the percentiles of 1 ms to 100 ms are %+v, want %+v", got, want)
	}
	if d[0] != 100*time.Millisecond {
		t.Error("Summarize sorted the slice that it was given")
	}
	if got := Summarize(nil); got != (ScaleStats{}) {
		t.Errorf("the percentiles of no times are %+v", got)
	}
	if got := Summarize([]time.Duration{7 * time.Millisecond}); got.P50Ms != 7 || got.P99Ms != 7 || got.MaxMs != 7 {
		t.Errorf("the percentiles of one time are %+v", got)
	}
}

func TestScaleReportFormats(t *testing.T) {
	ack := func(base int) ScaleStats {
		var d []time.Duration
		for i := 1; i <= 50; i++ {
			d = append(d, time.Duration(base+i)*time.Millisecond)
		}
		return Summarize(d)
	}
	r := &ScaleReport{
		Scale:        ReducedScale,
		Env:          map[string]string{"goos": "linux"},
		SetupApplyMs: []float64{100, 250},
		Enrol:        ScaleEnrol{Nodes: 1000, ConvergeMs: 4000, PerSecond: 250, Ack: ack(10)},
		Changes: []ScaleChange{
			{Name: "change-1", Nodes: 1000, ApplyMs: []float64{800}, Ack: ack(900)},
			{Name: "change-2", Nodes: 1000, ApplyMs: []float64{700}, Ack: ack(800)},
		},
		Route:   ScaleChange{Name: "route", Nodes: 10, ApplyMs: []float64{600}, Ack: ack(650)},
		TotalMs: 61000,
	}
	// The lines are the ones that bench-gate.py reads, and a run has the lines of its own change
	line := regexp.MustCompile(`^BENCH [a-z0-9_]+ -?[0-9]+(\.[0-9]+)? (ms|ops/s)$`)
	for run := 1; run <= 2; run++ {
		for _, l := range strings.Split(strings.TrimSpace(r.Bench(run)), "\n") {
			if !line.MatchString(l) {
				t.Errorf("run %d: %q is no BENCH line of bench-gate.py", run, l)
			}
		}
	}
	for run, want := range map[int]string{1: "BENCH scale_change_ack_p50 925.0 ms\n", 2: "BENCH scale_change_ack_p50 825.0 ms\n"} {
		if got := r.Bench(run); !strings.Contains(got, want) {
			t.Errorf("run %d does not hold the line %q:\n%s", run, want, got)
		}
	}
	if got := r.Bench(3); strings.Contains(got, "scale_change_") || !strings.Contains(got, "scale_enrol_rate 250.0 ops/s\n") {
		t.Errorf("a run that did not happen holds the lines of a change, or none of the enrolment:\n%s", got)
	}
	md := r.Markdown()
	for _, want := range []string{"1000 nodes, 100 VRFs, 10000 routes", "| change-2, the MTU of every VRF | 1000 |", "| route, one more LAN subnet of one gateway | 10 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("the summary does not hold %q:\n%s", want, md)
		}
	}

	dir := filepath.Join(t.TempDir(), "out")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scale.json", "scale-summary.md", "scale-bench.txt", "scale-bench-run2.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("Write made no %s: %v", name, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "scale.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back ScaleReport
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Scale != r.Scale || len(back.Changes) != 2 || back.Changes[1].Ack.P99Ms != r.Changes[1].Ack.P99Ms || back.Env["goos"] != "linux" {
		t.Errorf("the JSON of the report does not read back as the report: %+v", back)
	}
}

func TestFleetAwaitsTheAcks(t *testing.T) {
	s := SmallScale
	f, err := NewFleet(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Nodes) != s.Nodes {
		t.Fatalf("the fleet has %d nodes, want %d", len(f.Nodes), s.Nodes)
	}
	start := time.Now()
	want := map[string]uint64{scaleNodeName(0): 1, scaleNodeName(7): 3}
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.Nodes[0].OnAck(1)
		time.Sleep(50 * time.Millisecond)
		f.Nodes[7].OnAck(3)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	durs, err := f.Await(ctx, start, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(durs) != 2 {
		t.Fatalf("Await returned %d times for 2 nodes", len(durs))
	}
	slices.Sort(durs)
	if durs[0] < 40*time.Millisecond || durs[1] < durs[0]+40*time.Millisecond || durs[1] > 20*time.Second {
		t.Errorf("the nodes acknowledged %v after the start, want about 50 ms and 100 ms", durs)
	}
	if f.counts[0].Load() != 1 || f.counts[7].Load() != 1 || f.counts[1].Load() != 0 {
		t.Error("the Acks of the nodes are not counted")
	}
	if got := f.ConnectToAck(); len(got) != s.Nodes {
		t.Errorf("ConnectToAck returned %d times for %d nodes", len(got), s.Nodes)
	}

	// A node that acknowledges an older generation than the one that is awaited, or none, is waited for until the time allowed
	short, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	if _, err := f.Await(short, start, map[string]uint64{scaleNodeName(0): 2}, nil); err == nil {
		t.Error("Await returned for a node that acknowledged generation 1 when generation 2 was awaited")
	}
	if _, err := f.Await(ctx, start, map[string]uint64{"nobody": 1}, nil); err == nil {
		t.Error("Await accepted a name that is no node of the fleet")
	}
}

func TestScaleSameNodes(t *testing.T) {
	changed := map[string]uint64{"a": 2, "b": 5}
	if err := scaleSameNodes(changed, []string{"b", "a"}); err != nil {
		t.Error(err)
	}
	if err := scaleSameNodes(changed, []string{"a"}); err == nil {
		t.Error("an apply that changed one node more than named passed")
	}
	if err := scaleSameNodes(changed, []string{"a", "c"}); err == nil {
		t.Error("an apply that changed another node than the one named passed")
	}
}
