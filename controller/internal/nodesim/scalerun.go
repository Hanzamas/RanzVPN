package nodesim

// The phases of the scale scenario (SDN-18, #194) against a controller, which scale.go sizes and scalereport.go reports:
//
//  1. The VRFs, their Networks, Policies and Nodes are declared, a batch of VRFs in each apply (Scale.Setup).
//  2. The nodes open their streams, each gets its first state in full and acknowledges it: the enrolment.
//  3. The MTU of every VRF changes, a batch of VRFs in each apply, and every node of the batch gets the change as a delta.
//     The time from the start of the apply to the Ack of each node is the apply-to-ack latency. The change runs Scale.Runs times.
//  4. One gateway advertises one more route, which the other nodes of its VRF learn, and no other node hears of it.
//  5. The controller reports every node connected at the generation that it acknowledged, every node acknowledged exactly
//     the updates that the scenario called for, and the state of every node is what the intent compiles to.

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ScaleStatus is what the controller reports of one Node: the generation of its desired state, the generation that it
// acknowledged last, and whether it has a control stream.
type ScaleStatus struct {
	Name       string
	Generation uint64
	Acked      uint64
	Connected  bool
}

// ScaleTarget is the controller that a scale run runs against, as the test that started it describes it: the harness of one
// controller in the conformance tests of the controller, or the members of a cluster.
type ScaleTarget struct {
	// Endpoints are the controllers that the nodes open their streams to, in the order that they try them: the leader first.
	Endpoints []Endpoint
	// Apply applies doc through the API and returns the generation of each node whose desired state it changed.
	Apply func(ctx context.Context, doc intent.Document) (map[string]uint64, error)
	// Statuses returns the status of every Node, as the API lists them.
	Statuses func(ctx context.Context) ([]ScaleStatus, error)
	// Resources returns the intent as the controller holds it.
	Resources func(ctx context.Context) ([]intent.Resource, error)
	// Quiesce, when it is set, is called before the nodes stop, once the run ended: a controller that is still up records
	// the end of every stream, and stopping the controller first spares it thousands of store writes.
	Quiesce func()
	// Log, when it is set, receives a line for each step.
	Log func(format string, args ...any)
	// Rate is how many nodes start their streams in a second, DefaultStartRate when it is 0.
	Rate int
	// Wait bounds each wait of the run, Scale.Wait when it is 0.
	Wait time.Duration
}

// scaleRun is one run of the scenario.
type scaleRun struct {
	t     ScaleTarget
	s     Scale
	wait  time.Duration
	rate  int
	logf  func(format string, args ...any)
	fleet *Fleet
	rep   *ScaleReport
}

// RunScale runs the scale scenario s against the controller t and returns what it measured. On an error it returns the
// report of the phases that ran before it. The nodes stop when it returns.
func RunScale(ctx context.Context, t ScaleTarget, s Scale) (*ScaleReport, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	r := &scaleRun{t: t, s: s, wait: cmp.Or(t.Wait, s.Wait()), rate: cmp.Or(t.Rate, DefaultStartRate), logf: t.Log, rep: &ScaleReport{Scale: s, Env: scaleEnvironment()}}
	if r.logf == nil {
		r.logf = func(string, ...any) {}
	}
	begin := time.Now()
	defer func() {
		r.rep.TotalMs = scaleMs(time.Since(begin))
		if t.Quiesce != nil {
			t.Quiesce()
		}
		if r.fleet != nil {
			r.fleet.Stop()
		}
	}()
	err := r.run(ctx)
	return r.rep, err
}

func (r *scaleRun) run(ctx context.Context) error {
	docs, err := r.s.Setup()
	if err != nil {
		return err
	}
	for b, doc := range docs {
		start := time.Now()
		if _, err := r.t.Apply(ctx, doc); err != nil {
			return fmt.Errorf("nodesim: declaring batch %d of %d: %w", b+1, len(docs), err)
		}
		applied := time.Since(start)
		r.rep.SetupApplyMs = append(r.rep.SetupApplyMs, scaleMs(applied))
		r.logf("scale: declared batch %d of %d, %d resources, in %v", b+1, len(docs), len(doc.Resources), applied.Round(time.Millisecond))
	}
	if err := r.enrol(ctx); err != nil {
		return err
	}
	for run := range r.s.runs() {
		ch := ScaleChange{Name: fmt.Sprintf("change-%d", run+1)}
		var all []time.Duration
		for b := range r.s.batches() {
			doc, names, err := r.s.Change(run, b)
			if err != nil {
				return err
			}
			applied, durs, err := r.applyAndAwait(ctx, fmt.Sprintf("%s, batch %d of %d", ch.Name, b+1, r.s.batches()), doc, names)
			if err != nil {
				return err
			}
			ch.ApplyMs = append(ch.ApplyMs, scaleMs(applied))
			all = append(all, durs...)
		}
		ch.Nodes, ch.Ack = len(all), Summarize(all)
		r.rep.Changes = append(r.rep.Changes, ch)
	}
	doc, names, err := r.s.RouteChange()
	if err != nil {
		return err
	}
	applied, durs, err := r.applyAndAwait(ctx, "route", doc, names)
	if err != nil {
		return err
	}
	r.rep.Route = ScaleChange{Name: "route", Nodes: len(durs), ApplyMs: []float64{scaleMs(applied)}, Ack: Summarize(durs)}
	if err := r.settle(ctx); err != nil {
		return err
	}
	return r.verify(ctx)
}

// enrol starts the streams of the nodes and waits until each acknowledged the first state that the controller holds for it,
// and the controller says so too.
func (r *scaleRun) enrol(ctx context.Context) error {
	statuses, err := r.t.Statuses(ctx)
	if err != nil {
		return fmt.Errorf("nodesim: listing the nodes: %w", err)
	}
	want := make(map[string]uint64, len(statuses))
	for _, st := range statuses {
		if st.Generation == 0 {
			return fmt.Errorf("nodesim: node %s has no desired state after the setup", st.Name)
		}
		want[st.Name] = st.Generation
	}
	if len(want) != r.s.Nodes {
		return fmt.Errorf("nodesim: the controller lists %d nodes after the setup, want %d", len(want), r.s.Nodes)
	}
	if r.fleet, err = NewFleet(r.s, r.t.Endpoints); err != nil {
		return err
	}
	r.logf("scale: starting the streams of %d nodes, %d a second", r.s.Nodes, r.rate)
	start := time.Now()
	r.fleet.Start(ctx, r.rate)
	wctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	durs, err := r.fleet.Await(wctx, start, want, r.progress)
	if err != nil {
		return fmt.Errorf("nodesim: enrolment: %w", err)
	}
	converge := max(scaleLongest(durs), time.Millisecond)
	r.rep.Enrol = ScaleEnrol{Nodes: len(durs), ConvergeMs: scaleMs(converge), PerSecond: float64(len(durs)) / converge.Seconds(), Ack: Summarize(r.fleet.ConnectToAck())}
	r.logf("scale: %d nodes enrolled and acknowledged their first state in %v, %.0f a second", len(durs), converge.Round(time.Millisecond), r.rep.Enrol.PerSecond)
	return r.settle(ctx)
}

// applyAndAwait applies doc, checks that it changed the nodes names and no others, and waits until each of them acknowledged
// its new generation. It returns how long the apply took and, for each node, the time from the start of the apply to its Ack.
func (r *scaleRun) applyAndAwait(ctx context.Context, what string, doc intent.Document, names []string) (time.Duration, []time.Duration, error) {
	start := time.Now()
	changed, err := r.t.Apply(ctx, doc)
	applied := time.Since(start)
	if err != nil {
		return applied, nil, fmt.Errorf("nodesim: %s: %w", what, err)
	}
	if err := scaleSameNodes(changed, names); err != nil {
		return applied, nil, fmt.Errorf("nodesim: %s: %w", what, err)
	}
	wctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	durs, err := r.fleet.Await(wctx, start, changed, r.progress)
	if err != nil {
		return applied, nil, fmt.Errorf("nodesim: %s: %w", what, err)
	}
	r.logf("scale: %s: the apply took %v, and %d nodes acknowledged within %v of its start", what, applied.Round(time.Millisecond), len(durs), scaleLongest(durs).Round(time.Millisecond))
	return applied, durs, nil
}

func (r *scaleRun) progress(done, total int) {
	r.logf("scale: %d of %d nodes acknowledged so far", done, total)
}

// settle waits until the controller lists every node as connected at the generation that it acknowledged.
func (r *scaleRun) settle(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	last := ""
	for {
		statuses, err := r.t.Statuses(ctx)
		if err == nil {
			pending := 0
			for _, st := range statuses {
				if !st.Connected || st.Generation == 0 || st.Acked != st.Generation {
					pending++
				}
			}
			if pending == 0 && len(statuses) == r.s.Nodes {
				return nil
			}
			last = fmt.Sprintf("%d of %d nodes are not connected at the generation that they acknowledged", pending, len(statuses))
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("nodesim: the controller did not settle (%s): %w", last, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// verify checks what the scenario promises of every node once the run is over: it is at the generation that the controller
// holds for it, which is the one it acknowledged; it acknowledged the updates that the scenario called for and no others; and
// its state is what the intent of the controller compiles to for it.
func (r *scaleRun) verify(ctx context.Context) error {
	statuses, err := r.t.Statuses(ctx)
	if err != nil {
		return fmt.Errorf("nodesim: listing the nodes: %w", err)
	}
	generation := make(map[string]uint64, len(statuses))
	for _, st := range statuses {
		generation[st.Name] = st.Generation
	}
	resources, err := r.t.Resources(ctx)
	if err != nil {
		return fmt.Errorf("nodesim: reading the intent: %w", err)
	}
	in, err := intent.FromResources(resources)
	if err != nil {
		return fmt.Errorf("nodesim: the intent of the controller: %w", err)
	}
	if got := len(in.Routes()); got != r.s.Routes+1 {
		return fmt.Errorf("nodesim: the intent of the controller holds %d routes, want %d: the %d of the scenario and the one that it added", got, r.s.Routes+1, r.s.Routes)
	}
	states, err := desired.Compile(in)
	if err != nil {
		return fmt.Errorf("nodesim: compiling the intent of the controller: %w", err)
	}
	var problems []string
	bad := 0
	note := func(format string, args ...any) {
		bad++
		if len(problems) < 10 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	for i, n := range r.fleet.Nodes {
		name := scaleNodeName(i)
		gen, state := n.State()
		if want := generation[name]; gen != want || r.fleet.gens[i].Load() != want {
			note("%s is at generation %d and acknowledged %d, the controller holds %d", name, gen, r.fleet.gens[i].Load(), want)
		}
		if want := r.s.acks(i); int(r.fleet.counts[i].Load()) != want {
			note("%s acknowledged %d updates, want %d", name, r.fleet.counts[i].Load(), want)
		}
		if !desired.Equal(state, states[name]) {
			note("%s: its state at generation %d is not what the intent compiles to", name, gen)
		}
	}
	if bad > 0 {
		return fmt.Errorf("nodesim: %d problems with the nodes: %s", bad, strings.Join(problems, "; "))
	}
	r.logf("scale: all %d nodes are at the generation that they acknowledged, with the state of the intent, after %d updates for each node of the first VRF and %d for the others",
		r.s.Nodes, r.s.acks(0), r.s.acks(r.s.Nodes-1))
	return nil
}

// scaleSameNodes checks that the nodes that an apply changed are the ones that it was written to change.
func scaleSameNodes(changed map[string]uint64, names []string) error {
	if len(changed) != len(names) {
		return fmt.Errorf("the apply changed %d nodes, want %d", len(changed), len(names))
	}
	for _, name := range names {
		if _, ok := changed[name]; !ok {
			return fmt.Errorf("the apply did not change %s", name)
		}
	}
	return nil
}

// scaleLongest returns the longest of d, 0 for none.
func scaleLongest(d []time.Duration) time.Duration {
	var out time.Duration
	for _, x := range d {
		out = max(out, x)
	}
	return out
}

// scaleEnvironment returns what the report says of the machine and of the run that measured.
func scaleEnvironment() map[string]string {
	env := map[string]string{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "cpus": strconv.Itoa(runtime.NumCPU()), "go": runtime.Version()}
	for _, name := range []string{"GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_REF_NAME"} {
		if v := os.Getenv(name); v != "" {
			env[strings.ToLower(name)] = v
		}
	}
	return env
}
