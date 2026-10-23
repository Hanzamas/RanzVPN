package telemetry

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// fakeJournal is the store of the Feed in memory.
type fakeJournal struct {
	mu      sync.Mutex
	events  []event.Event
	targets []export.Stored
	err     error
}

func (j *fakeJournal) add(typ, subject string) uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	id := uint64(len(j.events) + 1)
	j.events = append(j.events, event.Event{ID: id, Time: time.Unix(1760000000, 0).UTC(), Type: typ, Subject: subject, Message: typ + " " + subject})
	return id
}

func (j *fakeJournal) put(t export.Target, delivered uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.targets = append(j.targets, export.Stored{Target: t, Delivered: delivered})
}

func (j *fakeJournal) EventsAfter(_ context.Context, after uint64, limit int) ([]event.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return nil, j.err
	}
	var out []event.Event
	for _, e := range j.events {
		if e.ID > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (j *fakeJournal) Targets(context.Context) ([]export.Stored, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return nil, j.err
	}
	return append([]export.Stored(nil), j.targets...), nil
}

func (j *fakeJournal) Delivered(_ context.Context, name string, id uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.targets {
		if j.targets[i].Name == name && j.targets[i].Delivered < id {
			j.targets[i].Delivered = id
		}
	}
	return nil
}

func (j *fakeJournal) delivered(name string) uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, s := range j.targets {
		if s.Name == name {
			return s.Delivered
		}
	}
	return 0
}

// receiver is a webhook that keeps the events it is called with and can be told to fail.
type receiver struct {
	*httptest.Server
	mu      sync.Mutex
	got     []event.Event
	headers []http.Header
	status  atomic.Int32
	calls   atomic.Int32
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{}
	r.status.Store(http.StatusOK)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.calls.Add(1)
		body, _ := io.ReadAll(req.Body)
		if s := int(r.status.Load()); s != http.StatusOK {
			http.Error(w, "no", s)
			return
		}
		var ev event.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.got = append(r.got, ev)
		r.headers = append(r.headers, req.Header.Clone())
		sig := req.Header.Get("X-Ranz-Signature")
		if sig != "" {
			mac := hmac.New(sha256.New, []byte("key"))
			mac.Write(body)
			if sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
				http.Error(w, "bad signature", http.StatusUnauthorized)
			}
		}
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) events() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.got...)
}

func sampleValue(f *Feed, metric string, labels ...string) (uint64, bool) {
	for _, s := range f.Samples() {
		if s.Metric == metric && strings.Join(s.Labels, ",") == strings.Join(labels, ",") {
			return s.Value, true
		}
	}
	return 0, false
}

func TestFeedCountsEventsAndDeliversThemInOrder(t *testing.T) {
	j := &fakeJournal{}
	srv := newReceiver(t)
	j.add(event.NodeDown, "a")
	j.add(event.GatewayFailover, "gw")
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: srv.URL, Secret: "key"}, 0)
	// A webhook that was made after the first event is sent the events after it only
	j.put(export.Target{Name: "late", Kind: export.KindWebhook, URL: srv.URL}, 1)
	// The targets of the other kinds are not the Feed's
	j.put(export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://127.0.0.1:4739"}, 0)

	f := NewFeed(j, nil, "ranz-controller/test", 0)
	f.step(context.Background())

	got := srv.events()
	if len(got) != 3 || got[0].Type != event.NodeDown || got[1].Type != event.GatewayFailover || got[2].Type != event.GatewayFailover || got[2].ID != 2 {
		t.Fatalf("the webhooks got %+v, want the two events for alerts and the second for late", got)
	}
	if j.delivered("alerts") != 2 || j.delivered("late") != 2 || j.delivered("flows") != 0 {
		t.Errorf("the webhooks were sent up to %d, %d and %d", j.delivered("alerts"), j.delivered("late"), j.delivered("flows"))
	}
	if h := srv.headers[0]; h.Get("X-Ranz-Event") != event.NodeDown || h.Get("X-Ranz-Event-Id") != "1" || h.Get("User-Agent") != "ranz-controller/test" ||
		h.Get("Content-Type") != "application/json" || !strings.HasPrefix(h.Get("X-Ranz-Signature"), "sha256=") {
		t.Errorf("the headers of the first call are %v", h)
	}
	if h := srv.headers[2]; h.Get("X-Ranz-Signature") != "" {
		t.Errorf("a webhook without a secret got the signature %q", h.Get("X-Ranz-Signature"))
	}

	if n, ok := sampleValue(f, "events", event.NodeDown); !ok || n != 1 {
		t.Errorf("node-down is counted %d times (%v), want 1", n, ok)
	}
	if n, ok := sampleValue(f, "events", event.PoolNearExhaustion); !ok || n != 0 {
		t.Errorf("ipam-pool-near-exhaustion is counted %d times (%v), want 0, which is listed", n, ok)
	}
	if n, _ := sampleValue(f, "webhook_deliveries", "alerts", "ok"); n != 2 {
		t.Errorf("alerts has %d deliveries, want 2", n)
	}

	// Nothing new: nothing is sent again, and the counts stay
	f.step(context.Background())
	if len(srv.events()) != 3 {
		t.Errorf("a second look at the same events sent %d calls in all", len(srv.events()))
	}
	j.add("custom-type", "")
	f.step(context.Background())
	if n, ok := sampleValue(f, "events", "custom-type"); !ok || n != 1 {
		t.Errorf("an event of a type that is none of the known ones is counted %d times (%v), want 1", n, ok)
	}
}

func TestFeedSendsAWebhookTheTypesItWants(t *testing.T) {
	j := &fakeJournal{}
	srv := newReceiver(t)
	j.put(export.Target{Name: "downs", Kind: export.KindWebhook, URL: srv.URL, Types: []string{event.NodeDown}}, 0)
	j.add(event.GatewayFailover, "gw")
	j.add(event.NodeDown, "a")
	j.add(event.AutomaticRollback, "")
	f := NewFeed(j, nil, "ranz-controller/test", 0)
	f.step(context.Background())
	if got := srv.events(); len(got) != 1 || got[0].Type != event.NodeDown {
		t.Errorf("the webhook for node-down got %+v", got)
	}
	if j.delivered("downs") != 3 {
		t.Errorf("the events that the webhook does not want are not skipped: it was sent up to %d, want 3", j.delivered("downs"))
	}
}

func TestFeedTriesAWebhookAgainAndGivesUp(t *testing.T) {
	j := &fakeJournal{}
	srv := newReceiver(t)
	srv.status.Store(http.StatusInternalServerError)
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: srv.URL}, 0)
	j.add(event.NodeDown, "a")
	j.add(event.NodeDown, "b")
	f := NewFeed(j, nil, "ranz-controller/test", 0)
	now := time.Unix(1760000000, 0)
	f.now = func() time.Time { return now }

	f.step(context.Background())
	if srv.calls.Load() != 1 || j.delivered("alerts") != 0 {
		t.Fatalf("after the first failure the webhook was called %d times and sent up to %d", srv.calls.Load(), j.delivered("alerts"))
	}
	// It waits a second before it tries again
	now = now.Add(900 * time.Millisecond)
	f.step(context.Background())
	if srv.calls.Load() != 1 {
		t.Errorf("the webhook was called again after 900 ms: %d calls", srv.calls.Load())
	}
	now = now.Add(200 * time.Millisecond)
	f.step(context.Background())
	if srv.calls.Load() != 2 {
		t.Errorf("the webhook was not called again after a second: %d calls", srv.calls.Load())
	}
	// The wait doubles, up to the longest, and the event is given up after maxAttempts
	for i := 2; i < maxAttempts; i++ {
		now = now.Add(maxBackoff + time.Second)
		f.step(context.Background())
	}
	if srv.calls.Load() != maxAttempts || j.delivered("alerts") != 1 {
		t.Fatalf("after %d attempts the webhook was called %d times and sent up to %d, want the first event given up on", maxAttempts, srv.calls.Load(), j.delivered("alerts"))
	}
	if failed, _ := sampleValue(f, "webhook_deliveries", "alerts", "failed"); failed != maxAttempts-1 {
		t.Errorf("%d failed deliveries are counted, want %d", failed, maxAttempts-1)
	}
	if dropped, _ := sampleValue(f, "webhook_deliveries", "alerts", "dropped"); dropped != 1 {
		t.Errorf("%d dropped deliveries are counted, want 1", dropped)
	}

	// The next event goes the same way, and a webhook that comes back gets it
	srv.status.Store(http.StatusOK)
	now = now.Add(time.Second)
	f.step(context.Background())
	if got := srv.events(); len(got) != 1 || got[0].Subject != "b" || j.delivered("alerts") != 2 {
		t.Errorf("after the webhook came back it got %+v and was sent up to %d, want the second event", got, j.delivered("alerts"))
	}
}

func TestFeedDoesNotFollowARedirect(t *testing.T) {
	elsewhere := newReceiver(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirect.Close()
	j := &fakeJournal{}
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: redirect.URL}, 0)
	j.add(event.NodeDown, "a")
	f := NewFeed(j, nil, "ranz-controller/test", 0)
	f.step(context.Background())
	if elsewhere.calls.Load() != 0 {
		t.Error("the Feed followed a redirect to another host")
	}
	if failed, _ := sampleValue(f, "webhook_deliveries", "alerts", "failed"); failed != 1 || j.delivered("alerts") != 0 {
		t.Errorf("a redirect is counted as %d failures and the webhook was sent up to %d, want 1 and 0", failed, j.delivered("alerts"))
	}
}

func TestFeedRunsUntilStopped(t *testing.T) {
	j := &fakeJournal{}
	srv := newReceiver(t)
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: srv.URL}, 0)
	f := NewFeed(j, nil, "ranz-controller/test", time.Hour)
	var nilFeed *Feed
	nilFeed.Poke()
	f.Stop()
	f.Start()
	j.add(event.NodeDown, "a")
	f.Poke()
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.events()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a poke did not make the Feed send the event within 5 s, with a poll interval of an hour")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.Stop()
	f.Stop()
	f.Poke()
}

func TestFeedSurvivesAStoreThatFails(t *testing.T) {
	j := &fakeJournal{err: errors.New("rqlite is down")}
	f := NewFeed(j, nil, "ranz-controller/test", 0)
	f.step(context.Background())
	j.err = nil
	j.put(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "http://127.0.0.1:1"}, 0)
	j.add(event.NodeDown, "a")
	f.step(context.Background())
	if n, _ := sampleValue(f, "events", event.NodeDown); n != 1 {
		t.Errorf("node-down is counted %d times after the store came back, want 1", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.step(ctx)
}
