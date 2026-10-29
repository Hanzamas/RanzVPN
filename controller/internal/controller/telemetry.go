package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// Telemetry and events (SDN-16 #192, ADR-0030). The nodes push the summaries of their counters, flow
// records and events over their control streams (takeTelemetry). The controller keeps the counters
// (telemetry.Hub) and exports them as Prometheus metrics and, to the targets an operator
// configured, over OTLP; it sends the flow records to the IPFIX targets; and it raises Events,
// which the event feed (telemetry.Feed) delivers to the webhook targets and counts: a node that
// has lost its control stream for NodeDownAfter, a node that reports a gateway failover or a
// session flap (sessionflap.go, AUD1-DT-11), the automatic rollback of an unconfirmed revision
// (revision.go) and the IPAM pool that a change of the intent takes to its threshold (ipam.go,
// SDN-10). The last two are stored in the transaction of the change that makes them; the first two
// are raised with Raise.

// DefaultNodeDownAfter is how long a node that had a control stream may have none before the
// controller raises a NodeDown event. A node opens a new stream within seconds when its old one
// is lost, so a shorter wait would raise the event for a node that only moved to another member
// of a controller cluster.
const DefaultNodeDownAfter = 30 * time.Second

// maxSubject and maxEventMessage bound the text that a node reports in an event: the Subject is a
// DNS label at most, and the message fits Refuse.message on the C node (control.options).
const (
	maxSubject      = 63
	maxEventMessage = 255
)

// telemetryState is what the controller keeps for telemetry and events.
type telemetryState struct {
	hub       *telemetry.Hub
	downAfter time.Duration
	poll      time.Duration
	interval  time.Duration

	// Started by startTelemetry, once the store is loaded
	feed    *telemetry.Feed
	exports *telemetry.Exporters
	metrics http.Handler

	// The nodes that lost their control stream, with the timer that raises NodeDown
	mu    sync.Mutex
	timer map[string]*time.Timer
}

func newTelemetryState(cfg Config) *telemetryState {
	t := &telemetryState{hub: telemetry.NewHub(cfg.TelemetryStale), downAfter: cfg.NodeDownAfter, poll: cfg.EventPoll, interval: cfg.ExportInterval,
		timer: map[string]*time.Timer{}}
	if t.downAfter <= 0 {
		t.downAfter = DefaultNodeDownAfter
	}
	return t
}

// startTelemetry starts the event feed and the exporters of the targets in the store. New calls it
// last, so that nothing runs for a controller that did not start.
func (c *Controller) startTelemetry(ctx context.Context) error {
	targets, err := c.store.Targets(ctx)
	if err != nil {
		return err
	}
	t := c.tel
	t.feed = telemetry.NewFeed(c.store, c.log, "ranz-controller/"+c.version, t.poll)
	t.exports = telemetry.NewExporters(c.samples, t.interval, c.log)
	t.feed.SetGuard(c.reach)
	t.exports.SetGuard(c.reach)
	t.metrics = telemetry.Handler(c.samples)
	t.exports.Apply(ctx, plain(targets))
	t.feed.Start()
	return nil
}

// stopTelemetry stops the timers, the feed and the exporters, and so everything that writes to the
// store or sends to a target. Close calls it once the control streams ended.
func (c *Controller) stopTelemetry() {
	t := c.tel
	t.mu.Lock()
	for name, tm := range t.timer {
		tm.Stop()
		delete(t.timer, name)
	}
	t.mu.Unlock()
	if t.feed != nil {
		t.feed.Stop()
	}
	if t.exports != nil {
		t.exports.Close()
	}
}

// plain returns the targets of stored.
func plain(stored []export.Stored) []export.Target {
	out := make([]export.Target, len(stored))
	for i, s := range stored {
		out[i] = s.Target
	}
	return out
}

// Raise records ev as an event (ADR-0030 decision 5): the store keeps it, `ranz get events` lists
// it, and the event feed delivers it to the webhooks and counts it in ranz_events_total. A
// condition that no change of the intent makes is raised here, for example a node that went down
// (event.NodeDown); the event of a change of the intent is stored with the change instead. The time
// of ev is now when it is left out.
func (c *Controller) Raise(ctx context.Context, ev event.Event) error {
	if ev.Type == "" {
		return fmt.Errorf("%w: an event needs a type", intent.ErrInvalid)
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC().Truncate(time.Millisecond)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.Commit(sctx, store.Changes{AddEvents: []event.Event{ev}}); err != nil {
		return err
	}
	c.tel.feed.Poke()
	c.log.Warn("event raised", "type", ev.Type, "node", ev.Node, "subject", ev.Subject, "message", ev.Message)
	return nil
}

// takeTelemetry takes a summary that the node of s sent: the Hub keeps its counters, the IPFIX
// exporters get its flow records, and each event of its own becomes an Event.
func (c *Controller) takeTelemetry(s *stream, t *controlpb.Telemetry) {
	c.tel.hub.Report(s.name, t)
	c.tel.exports.Flows(s.name, telemetry.FlowsOf(t))
	// The WireGuard ends of the Devices whose gateway the node is (devices.go; SDN-80)
	c.takeDevices(s.name, t.GetDevices())
	// The BGP peering of the standard mode at the node (peeringreport.go; SDN-77)
	c.takePeering(s.name, t.GetPeering())
	for _, ne := range t.GetEvents() {
		// Two holders of one key replace the session of a peer again and again (sessionflap.go; AUD1-DT-11, #459)
		if ne.GetType() == controlpb.NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP {
			c.takeSessionFlap(s, ne)
			continue
		}
		if ne.GetType() != controlpb.NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER {
			continue
		}
		subject := clip(ne.GetSubject(), maxSubject)
		msg := clip(ne.GetMessage(), maxEventMessage)
		if msg == "" {
			msg = fmt.Sprintf("node %s moved its traffic to gateway %s", s.name, subject)
		}
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		err := c.Raise(ctx, event.Event{Type: event.GatewayFailover, Node: s.name, Subject: subject, Message: msg})
		cancel()
		if err != nil {
			c.log.Error("raising the gateway failover that a node reported", "node", s.name, "err", err)
		}
	}
}

// clip returns s without what is no UTF-8 and at most limit bytes long, cut at a character.
func clip(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// nodeUp is called when the node name opened a control stream: it is no longer going down.
func (c *Controller) nodeUp(name string) {
	// A gateway that was down is up again for the health data of gateway HA (gateways.go; SDN-19)
	c.setGatewayDown(name, false)
	t := c.tel
	t.mu.Lock()
	defer t.mu.Unlock()
	if tm := t.timer[name]; tm != nil {
		tm.Stop()
		delete(t.timer, name)
	}
}

// nodeLost is called when the control stream of the node name ended while it was the node's one:
// the node is down once it has had none for NodeDownAfter.
func (c *Controller) nodeLost(name string) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	t := c.tel
	t.mu.Lock()
	defer t.mu.Unlock()
	if old := t.timer[name]; old != nil {
		old.Stop()
	}
	t.timer[name] = time.AfterFunc(t.downAfter, func() { c.nodeDown(name) })
}

// nodeDown raises NodeDown for the node name, unless it opened a stream again, was deleted or the
// controller closed meanwhile.
func (c *Controller) nodeDown(name string) {
	c.mu.Lock()
	n := c.nodes[name]
	_, declared := c.intent.Nodes[name]
	skip := c.closed || !declared || n == nil || n.stream != nil
	c.mu.Unlock()
	t := c.tel
	t.mu.Lock()
	delete(t.timer, name)
	t.mu.Unlock()
	if skip {
		return
	}
	// A gateway that is down for the health data of gateway HA (gateways.go; SDN-19)
	c.setGatewayDown(name, true)
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	msg := fmt.Sprintf("node %s has had no control stream for %s", name, t.downAfter)
	if err := c.Raise(ctx, event.Event{Type: event.NodeDown, Node: name, Message: msg}); err != nil {
		c.log.Error("raising node-down", "node", name, "err", err)
	}
}

// vrfNames returns the function that names a VRF by its id in the intent as it is now, and gives
// "" for an id that no VRF has.
func (c *Controller) vrfNames() func(uint32) string {
	c.mu.Lock()
	names := make(map[uint32]string, len(c.intent.VRFs))
	for name, v := range c.intent.VRFs {
		names[v.ID] = name
	}
	c.mu.Unlock()
	return func(id uint32) string { return names[id] }
}

// samples gives the series of every export: the counters of the nodes, whether each node is
// connected, the events by type and the deliveries to the webhooks.
func (c *Controller) samples() []telemetry.Sample {
	out := c.tel.hub.Samples(c.vrfNames())
	for _, n := range c.Nodes() {
		connected := uint64(0)
		if n.Connected {
			connected = 1
		}
		out = append(out, telemetry.Sample{Metric: "node_connected", Labels: []string{n.Name}, Value: connected})
	}
	out = append(out, c.waitingSamples()...)
	return append(out, c.tel.feed.Samples()...)
}

// Telemetry returns the counters that the nodes reported last (GET /api/v1/telemetry), with the
// VRFs named by the intent.
func (c *Controller) Telemetry() []telemetry.NodeSnapshot {
	return c.tel.hub.Snapshot(c.vrfNames())
}

// Metrics returns the handler that answers a Prometheus scrape (GET /api/v1/metrics).
func (c *Controller) Metrics() http.Handler {
	return c.tel.metrics
}

// FlushExports sends the metrics to every OTLP target now, instead of at the next interval.
func (c *Controller) FlushExports(ctx context.Context) {
	c.tel.exports.Flush(ctx)
}

// Targets returns the export targets, ordered by name, with their secrets.
func (c *Controller) Targets(ctx context.Context) ([]export.Target, error) {
	stored, err := c.store.Targets(ctx)
	if err != nil {
		return nil, err
	}
	return plain(stored), nil
}

// PutTarget stores the export target t, which replaces the one of its name, and starts or restarts
// its exporter. An error that wraps export.ErrInvalid is a target that is not valid.
func (c *Controller) PutTarget(ctx context.Context, t export.Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if err := c.reach.Check(ctx, t.URL); err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.PutTarget(sctx, t); err != nil {
		return err
	}
	return c.applyTargets(sctx)
}

// DeleteTarget deletes the export target name and returns it. There is none of that name when the
// error wraps intent.ErrNotFound.
func (c *Controller) DeleteTarget(ctx context.Context, name string) (export.Target, error) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	stored, err := c.store.Targets(sctx)
	if err != nil {
		return export.Target{}, err
	}
	for _, s := range stored {
		if s.Name != name {
			continue
		}
		if err := c.store.DeleteTarget(sctx, name); err != nil {
			return export.Target{}, err
		}
		return s.Target, c.applyTargets(sctx)
	}
	return export.Target{}, fmt.Errorf("%w: export target %q", intent.ErrNotFound, name)
}

// applyTargets makes the exporters match the targets in the store.
func (c *Controller) applyTargets(ctx context.Context) error {
	stored, err := c.store.Targets(ctx)
	if err != nil {
		return err
	}
	c.tel.exports.Apply(ctx, plain(stored))
	c.tel.feed.Poke()
	return nil
}
