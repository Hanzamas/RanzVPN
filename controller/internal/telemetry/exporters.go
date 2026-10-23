package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// closeTimeout bounds how long closing an OTLP export waits for its last push.
const closeTimeout = 5 * time.Second

// queued is the flow records of one node that wait for the IPFIX exporters.
type queued struct {
	node  string
	flows []Flow
}

// runningOTLP and runningIPFIX are an exporter that runs, with the target it was made from, so
// that Apply restarts it when the target changed.
type runningOTLP struct {
	target export.Target
	otlp   *OTLP
}

type runningIPFIX struct {
	target export.Target
	ipfix  *IPFIX
}

// Exporters runs the exporters of the OTLP and IPFIX targets in the store: Apply makes what runs
// match the targets, Flows hands the flow records of a node to every IPFIX exporter, and Flush
// sends the metrics to every OTLP endpoint now. The IPFIX exporters send on a goroutine of their
// own, so that a collector that is slow cannot hold up the control stream of a node.
type Exporters struct {
	samples  func() []Sample
	interval time.Duration
	log      *slog.Logger

	mu     sync.Mutex
	closed bool
	otlp   map[string]runningOTLP
	ipfix  map[string]runningIPFIX
	jobs   chan queued
	done   chan struct{}
}

// NewExporters returns Exporters that export the series that samples gives, to the OTLP targets
// every interval (DefaultExportInterval when it is not above 0).
func NewExporters(samples func() []Sample, interval time.Duration, log *slog.Logger) *Exporters {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	e := &Exporters{samples: samples, interval: interval, log: log, otlp: map[string]runningOTLP{}, ipfix: map[string]runningIPFIX{},
		jobs: make(chan queued, 256), done: make(chan struct{})}
	go e.send()
	return e
}

// send hands the queued flow records to the IPFIX exporters until Close.
func (e *Exporters) send() {
	defer close(e.done)
	for q := range e.jobs {
		e.mu.Lock()
		current := map[string]*IPFIX{}
		for name, r := range e.ipfix {
			current[name] = r.ipfix
		}
		e.mu.Unlock()
		for name, x := range current {
			if err := x.Export(q.node, q.flows); err != nil {
				e.log.Warn("IPFIX export failed", "target", name, "node", q.node, "flows", len(q.flows), "err", err)
			}
		}
	}
}

// Apply makes the exporters match targets: an OTLP or IPFIX target that has none gets one, one
// whose target changed gets a new one, and one whose target is gone loses it. A target that
// cannot start is logged and left out until the next Apply.
func (e *Exporters) Apply(ctx context.Context, targets []export.Target) {
	wantOTLP, wantIPFIX := map[string]export.Target{}, map[string]export.Target{}
	for _, t := range targets {
		switch t.Kind {
		case export.KindOTLP:
			wantOTLP[t.Name] = t
		case export.KindIPFIX:
			wantIPFIX[t.Name] = t
		}
	}

	var staleOTLP []*OTLP
	var staleIPFIX []*IPFIX
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	for name, r := range e.otlp {
		if t, ok := wantOTLP[name]; !ok || !sameTarget(t, r.target) {
			staleOTLP = append(staleOTLP, r.otlp)
			delete(e.otlp, name)
		}
	}
	for name, t := range wantOTLP {
		if _, ok := e.otlp[name]; ok {
			continue
		}
		o, err := NewOTLP(ctx, t, e.samples, e.interval)
		if err != nil {
			e.log.Error("OTLP target not started", "target", name, "err", err)
			continue
		}
		e.otlp[name] = runningOTLP{target: t, otlp: o}
	}
	for name, r := range e.ipfix {
		if t, ok := wantIPFIX[name]; !ok || !sameTarget(t, r.target) {
			staleIPFIX = append(staleIPFIX, r.ipfix)
			delete(e.ipfix, name)
		}
	}
	for name, t := range wantIPFIX {
		if _, ok := e.ipfix[name]; ok {
			continue
		}
		x, err := NewIPFIX(t)
		if err != nil {
			e.log.Error("IPFIX target not started", "target", name, "err", err)
			continue
		}
		e.ipfix[name] = runningIPFIX{target: t, ipfix: x}
	}
	e.mu.Unlock()

	// The last push of an OTLP export may wait for its endpoint, so it runs outside the lock
	for _, o := range staleOTLP {
		closeOTLP(o)
	}
	for _, x := range staleIPFIX {
		x.Close()
	}
}

// sameTarget reports whether a and b would make the same exporter.
func sameTarget(a, b export.Target) bool {
	return a.URL == b.URL && a.Secret == b.Secret
}

// closeOTLP ends the export of o, sending the metrics one last time.
func closeOTLP(o *OTLP) {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	_ = o.Close(ctx)
}

// Flows queues the flow records that node reported for the IPFIX exporters. When the queue is full,
// they are dropped.
func (e *Exporters) Flows(node string, flows []Flow) {
	if len(flows) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || len(e.ipfix) == 0 {
		return
	}
	select {
	case e.jobs <- queued{node: node, flows: flows}:
	default:
		e.log.Warn("IPFIX export queue is full, flow records dropped", "node", node, "flows", len(flows))
	}
}

// Flush sends the metrics to every OTLP endpoint now.
func (e *Exporters) Flush(ctx context.Context) {
	e.mu.Lock()
	var all []*OTLP
	for _, r := range e.otlp {
		all = append(all, r.otlp)
	}
	e.mu.Unlock()
	for _, o := range all {
		if err := o.Flush(ctx); err != nil {
			e.log.Warn("OTLP export failed", "err", err)
		}
	}
}

// Close stops every exporter. The OTLP exporters send the metrics one last time.
func (e *Exporters) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	close(e.jobs)
	otlps, ipfixes := e.otlp, e.ipfix
	e.otlp, e.ipfix = map[string]runningOTLP{}, map[string]runningIPFIX{}
	e.mu.Unlock()
	<-e.done
	for _, r := range otlps {
		closeOTLP(r.otlp)
	}
	for _, r := range ipfixes {
		r.ipfix.Close()
	}
}
