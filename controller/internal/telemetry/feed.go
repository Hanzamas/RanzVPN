package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// DefaultPoll is how often the Feed looks at the store for new events.
const DefaultPoll = time.Second

// The results of a delivery that the metric webhook_deliveries counts.
const (
	resultOK      = "ok"
	resultFailed  = "failed"
	resultDropped = "dropped"
)

// maxAttempts is how many times the Feed tries to deliver an event to a webhook before it gives up
// on that event for that webhook. The wait doubles from a second to five minutes between the
// attempts, so the Feed gives up after about nine minutes.
const maxAttempts = 10

// maxBackoff is the longest wait between two attempts.
const maxBackoff = 5 * time.Minute

// batch is how many events the Feed reads from the store at once.
const batch = 200

// Journal is what the Feed needs of the store: the events, the targets and the record of what each
// webhook was sent.
type Journal interface {
	// EventsAfter returns up to limit events whose id is above after, the oldest first.
	EventsAfter(ctx context.Context, after uint64, limit int) ([]event.Event, error)
	// Targets returns every target with the id of the last event its webhook was sent.
	Targets(ctx context.Context) ([]export.Stored, error)
	// Delivered records that the webhook name was sent every event up to id.
	Delivered(ctx context.Context, name string, id uint64) error
}

// attempt is how far the delivery to one webhook has got when it fails: how often it was tried,
// and when it may be tried again.
type attempt struct {
	count int
	next  time.Time
}

// Feed turns the events in the store into metrics and webhook deliveries (ADR-0030 decision 5):
// it counts each event by its type, and sends each event to every webhook that wants its type, in
// the order of the events, once the store holds it. A webhook that fails is tried again with a
// growing wait, and is skipped for the event after maxAttempts. The store keeps, for each webhook,
// the last event it was sent, so a controller that restarts, or the next leader of a cluster,
// goes on where the last one stopped.
type Feed struct {
	journal Journal
	log     *slog.Logger
	client  *http.Client
	agent   string
	poll    time.Duration
	now     func() time.Time
	wake    chan struct{}

	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	seen     uint64
	counts   map[string]uint64
	results  map[string]map[string]uint64
	attempts map[string]attempt
}

// NewFeed returns a Feed on journal that looks for events every poll (DefaultPoll when it is not
// above 0). agent is the User-Agent of the webhook calls. Start runs it.
func NewFeed(journal Journal, log *slog.Logger, agent string, poll time.Duration) *Feed {
	if poll <= 0 {
		poll = DefaultPoll
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// A webhook that answers with a redirect has failed: the call must not go on to a host that the
	// operator did not name.
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Feed{
		journal:  journal,
		log:      log,
		client:   client,
		agent:    agent,
		poll:     poll,
		now:      time.Now,
		wake:     make(chan struct{}, 1),
		counts:   map[string]uint64{},
		results:  map[string]map[string]uint64{},
		attempts: map[string]attempt{},
	}
}

// SetGuard makes the Feed call its webhooks only where g allows (AUD1-DT-9 #457): each call is
// checked when it is made. Set it before Start.
func (f *Feed) SetGuard(g *export.Guard) {
	f.client = g.HTTPClient(10 * time.Second)
}

// Start runs the Feed on a goroutine of its own until Stop.
func (f *Feed) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel, f.done = cancel, make(chan struct{})
	go func() {
		defer close(f.done)
		t := time.NewTicker(f.poll)
		defer t.Stop()
		for {
			f.step(ctx)
			select {
			case <-ctx.Done():
				return
			case <-f.wake:
			case <-t.C:
			}
		}
	}()
}

// Stop ends the Feed and waits until its goroutine returns. A delivery that is in flight is
// cancelled.
func (f *Feed) Stop() {
	if f.cancel != nil {
		f.cancel()
		<-f.done
	}
}

// Poke has the Feed look at the store at once, for a caller that just wrote an event. A Feed that
// is nil, as before the controller started it, has nothing to wake.
func (f *Feed) Poke() {
	if f == nil {
		return
	}
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// step counts the new events and makes the deliveries that are due.
func (f *Feed) step(ctx context.Context) {
	f.mu.Lock()
	after := f.seen
	f.mu.Unlock()
	for {
		evs, err := f.journal.EventsAfter(ctx, after, batch)
		if err != nil {
			if ctx.Err() == nil {
				f.log.Warn("event feed: reading the events", "err", err)
			}
			return
		}
		f.mu.Lock()
		for _, ev := range evs {
			f.counts[ev.Type]++
			f.seen, after = ev.ID, ev.ID
		}
		f.mu.Unlock()
		if len(evs) < batch {
			break
		}
	}
	targets, err := f.journal.Targets(ctx)
	if err != nil {
		if ctx.Err() == nil {
			f.log.Warn("event feed: reading the targets", "err", err)
		}
		return
	}
	for _, t := range targets {
		if t.Kind == export.KindWebhook {
			f.deliver(ctx, t)
		}
	}
}

// deliver sends webhook t the events after the last one it was sent, in order, until one fails.
func (f *Feed) deliver(ctx context.Context, t export.Stored) {
	f.mu.Lock()
	at := f.attempts[t.Name]
	f.mu.Unlock()
	if f.now().Before(at.next) {
		return
	}
	evs, err := f.journal.EventsAfter(ctx, t.Delivered, batch)
	if err != nil {
		if ctx.Err() == nil {
			f.log.Warn("event feed: reading the events of a webhook", "webhook", t.Name, "err", err)
		}
		return
	}
	for _, ev := range evs {
		if t.Wants(ev.Type) {
			if err := f.post(ctx, t.Target, ev); err != nil {
				if ctx.Err() != nil {
					return
				}
				f.failed(ctx, t, ev, at, err)
				return
			}
			f.count(t.Name, resultOK)
		}
		at = attempt{}
		f.mu.Lock()
		delete(f.attempts, t.Name)
		f.mu.Unlock()
		if err := f.journal.Delivered(ctx, t.Name, ev.ID); err != nil {
			if ctx.Err() == nil {
				f.log.Warn("event feed: recording a delivery", "webhook", t.Name, "event", ev.ID, "err", err)
			}
			return
		}
	}
}

// failed records that the delivery of ev to webhook t failed with err, the at.count-th attempt in a
// row: the next one is later, or ev is given up on after maxAttempts.
func (f *Feed) failed(ctx context.Context, t export.Stored, ev event.Event, at attempt, err error) {
	at.count++
	if at.count < maxAttempts {
		wait := min(time.Second<<(at.count-1), maxBackoff)
		at.next = f.now().Add(wait)
		f.mu.Lock()
		f.attempts[t.Name] = at
		f.mu.Unlock()
		f.count(t.Name, resultFailed)
		f.log.Warn("event feed: a webhook failed, trying again later", "webhook", t.Name, "event", ev.ID, "type", ev.Type, "attempt", at.count, "wait", wait, "err", err)
		return
	}
	f.mu.Lock()
	delete(f.attempts, t.Name)
	f.mu.Unlock()
	f.count(t.Name, resultDropped)
	f.log.Error("event feed: a webhook failed for good, the event is skipped for it", "webhook", t.Name, "event", ev.ID, "type", ev.Type, "attempts", at.count, "err", err)
	if err := f.journal.Delivered(ctx, t.Name, ev.ID); err != nil && ctx.Err() == nil {
		f.log.Warn("event feed: recording a delivery", "webhook", t.Name, "event", ev.ID, "err", err)
	}
}

// count adds one to the deliveries of webhook name with result.
func (f *Feed) count(name, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.results[name] == nil {
		f.results[name] = map[string]uint64{}
	}
	f.results[name][result]++
}

// post sends ev to the webhook t as JSON, signed with its secret when it has one. Any answer other
// than 2xx is an error.
func (f *Feed) post(ctx context.Context, t export.Target, ev event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", f.agent)
	req.Header.Set("X-Ranz-Event", ev.Type)
	req.Header.Set("X-Ranz-Event-Id", strconv.FormatUint(ev.ID, 10))
	if t.Secret != "" {
		mac := hmac.New(sha256.New, []byte(t.Secret))
		mac.Write(body)
		req.Header.Set("X-Ranz-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the webhook answered %s", resp.Status)
	}
	return nil
}

// Samples returns the series that the Feed owns: the events by type, each known type from 0 on,
// and the deliveries of each webhook by result.
func (f *Feed) Samples() []Sample {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Sample
	for _, typ := range event.Types {
		out = append(out, Sample{Metric: "events", Labels: []string{typ}, Value: f.counts[typ]})
	}
	for typ, n := range f.counts {
		if !slices.Contains(event.Types, typ) {
			out = append(out, Sample{Metric: "events", Labels: []string{typ}, Value: n})
		}
	}
	for name, byResult := range f.results {
		for _, result := range []string{resultOK, resultFailed, resultDropped} {
			out = append(out, Sample{Metric: "webhook_deliveries", Labels: []string{name, result}, Value: byResult[result]})
		}
	}
	return out
}
