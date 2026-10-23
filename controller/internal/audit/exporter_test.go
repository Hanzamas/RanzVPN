package audit

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// hook is a test webhook: an HTTP server that keeps the audit records it is called with. It answers
// 500 while status is not 200, and for the record whose id is failOn.
type hook struct {
	*httptest.Server
	mu      sync.Mutex
	got     []Record
	headers []http.Header
	status  atomic.Int32
	failOn  atomic.Uint64
	calls   atomic.Int32
}

func newHook(t *testing.T) *hook {
	h := &hook{}
	h.status.Store(http.StatusOK)
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if s := int(h.status.Load()); s != http.StatusOK {
			http.Error(w, "no", s)
			return
		}
		var rec Record
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if rec.ID == h.failOn.Load() {
			http.Error(w, "not this one", http.StatusInternalServerError)
			return
		}
		if sig := r.Header.Get("X-Ranz-Signature"); sig != "" {
			mac := hmac.New(sha256.New, []byte("key"))
			mac.Write(body)
			if sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.got = append(h.got, rec)
		h.headers = append(h.headers, r.Header.Clone())
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hook) records() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Record(nil), h.got...)
}

func (h *hook) header(i int) http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.headers[i]
}

// ids returns the ids of the records that the webhook got, in order.
func (h *hook) ids() []uint64 {
	var out []uint64
	for _, r := range h.records() {
		out = append(out, r.ID)
	}
	return out
}

func TestExporterPostsTheRecordsInOrder(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	s.add(Login)
	s.add(AuthFailed)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL, Secret: "key"}, 0)
	// A target that was made after the first record is sent the records after it only
	s.put(export.Target{Name: "late", Kind: export.KindWebhook, URL: h.URL}, 1)

	x := NewExporter(s, nil, "ranz-controller/test", 0)
	x.step(context.Background())

	got := h.records()
	if len(got) != 3 || got[0].ID != 1 || got[0].Kind != Login || got[1].ID != 2 || got[1].Kind != AuthFailed || got[2].ID != 2 {
		t.Fatalf("the webhooks got %+v, want the two records for siem and the second for late", got)
	}
	if s.deliveredTo("siem") != 2 || s.deliveredTo("late") != 2 {
		t.Errorf("the webhooks were sent up to %d and %d, want 2", s.deliveredTo("siem"), s.deliveredTo("late"))
	}
	if hd := h.header(0); hd.Get("X-Ranz-Audit") != Login || hd.Get("X-Ranz-Audit-Id") != "1" || hd.Get("User-Agent") != "ranz-controller/test" ||
		hd.Get("Content-Type") != "application/json" || !strings.HasPrefix(hd.Get("X-Ranz-Signature"), "sha256=") {
		t.Errorf("the headers of the first call are %v", hd)
	}
	if hd := h.header(2); hd.Get("X-Ranz-Signature") != "" {
		t.Errorf("a webhook without a secret got the signature %q", hd.Get("X-Ranz-Signature"))
	}

	// Nothing new: nothing is sent again
	x.step(context.Background())
	if n := len(h.records()); n != 3 {
		t.Errorf("a second look at the same records sent %d calls in all", n)
	}
	s.add(Logout)
	x.step(context.Background())
	if ids := h.ids(); len(ids) != 5 || ids[3] != 3 || ids[4] != 3 {
		t.Errorf("after a new record the webhooks got %v, want it once for each of them", ids)
	}
}

// A target that wants some kinds is sent those only, and what it does not want is skipped over, so
// that it is not looked at again.
func TestExporterSendsATargetTheKindsItWants(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	s.put(export.Target{Name: "failures", Kind: export.KindWebhook, URL: h.URL, Types: []string{AuthFailed}}, 0)
	s.add(Login)
	s.add(AuthFailed)
	s.add(Logout)
	NewExporter(s, nil, "ranz-controller/test", 0).step(context.Background())
	if got := h.records(); len(got) != 1 || got[0].Kind != AuthFailed {
		t.Errorf("the webhook for failed authentications got %+v", got)
	}
	if s.deliveredTo("failures") != 3 {
		t.Errorf("the records that the webhook does not want are not skipped: it was sent up to %d, want 3", s.deliveredTo("failures"))
	}
}

// A target that fails is tried again with a growing wait, and no record is skipped for it: when it
// comes back it gets every record, in order.
func TestExporterTriesATargetAgainAndNeverSkipsARecord(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	h.status.Store(http.StatusInternalServerError)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL}, 0)
	s.add(Login)
	s.add(Logout)
	x := NewExporter(s, nil, "ranz-controller/test", 0)
	now := time.Unix(1760000000, 0)
	x.now = func() time.Time { return now }
	ctx := context.Background()

	x.step(ctx)
	if h.calls.Load() != 1 || s.deliveredTo("siem") != 0 {
		t.Fatalf("after the first failure the webhook was called %d times and sent up to %d", h.calls.Load(), s.deliveredTo("siem"))
	}
	// It waits a second before it tries again
	now = now.Add(900 * time.Millisecond)
	x.step(ctx)
	if h.calls.Load() != 1 {
		t.Errorf("the webhook was called again after 900 ms: %d calls", h.calls.Load())
	}
	now = now.Add(200 * time.Millisecond)
	x.step(ctx)
	if h.calls.Load() != 2 {
		t.Errorf("the webhook was not called again after a second: %d calls", h.calls.Load())
	}
	// The wait doubles up to the longest, and the records are never given up on
	for range 12 {
		now = now.Add(maxBackoff + time.Second)
		x.step(ctx)
	}
	if h.calls.Load() != 14 || s.deliveredTo("siem") != 0 {
		t.Fatalf("after 14 attempts the webhook was called %d times and sent up to %d, want no record given up on", h.calls.Load(), s.deliveredTo("siem"))
	}

	h.status.Store(http.StatusOK)
	now = now.Add(maxBackoff + time.Second)
	x.step(ctx)
	if ids := h.ids(); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 || s.deliveredTo("siem") != 2 {
		t.Errorf("after the webhook came back it got %v and was sent up to %d, want both records in order", ids, s.deliveredTo("siem"))
	}
}

// A target that fails in the middle of what it is sent keeps what it got, and is sent the rest
// later, not the records again.
func TestExporterKeepsWhatATargetGotBeforeItFailed(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	h.failOn.Store(2)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL}, 0)
	for range 3 {
		s.add(Login)
	}
	x := NewExporter(s, nil, "ranz-controller/test", 0)
	now := time.Unix(1760000000, 0)
	x.now = func() time.Time { return now }

	x.step(context.Background())
	if ids := h.ids(); len(ids) != 1 || ids[0] != 1 || s.deliveredTo("siem") != 1 {
		t.Fatalf("the webhook got %v and was sent up to %d, want the first record only", ids, s.deliveredTo("siem"))
	}
	h.failOn.Store(0)
	now = now.Add(2 * time.Second)
	x.step(context.Background())
	if ids := h.ids(); len(ids) != 3 || ids[1] != 2 || ids[2] != 3 || s.deliveredTo("siem") != 3 {
		t.Errorf("the webhook got %v and was sent up to %d, want the records 1, 2 and 3, each once", ids, s.deliveredTo("siem"))
	}
}

// More records than one batch are sent in the same round.
func TestExporterSendsMoreThanOneBatch(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	for range batch*2 + 50 {
		s.add(Operation)
	}
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL}, 0)
	NewExporter(s, nil, "ranz-controller/test", 0).step(context.Background())
	if n := len(h.records()); n != batch*2+50 || s.deliveredTo("siem") != uint64(batch*2+50) {
		t.Errorf("the webhook got %d records and was sent up to %d, want %d", n, s.deliveredTo("siem"), batch*2+50)
	}
}

func TestExporterDoesNotFollowARedirect(t *testing.T) {
	elsewhere := newHook(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirect.Close()
	s := &memStore{}
	s.add(Login)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: redirect.URL}, 0)
	NewExporter(s, nil, "ranz-controller/test", 0).step(context.Background())
	if elsewhere.calls.Load() != 0 || s.deliveredTo("siem") != 0 {
		t.Errorf("the redirect was followed (%d calls elsewhere), or counted as a delivery (up to %d)", elsewhere.calls.Load(), s.deliveredTo("siem"))
	}
}

// syslogReceiver is a syslog receiver on loopback that keeps the messages it is sent.
type syslogReceiver struct {
	addr string
	msgs chan string
	tls  *tls.Config // what a sender must trust to send to it over TLS
}

func newSyslogReceiver(t *testing.T, scheme string) *syslogReceiver {
	t.Helper()
	r := &syslogReceiver{msgs: make(chan string, 64)}
	if scheme == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		r.addr = pc.LocalAddr().String()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				r.msgs <- string(buf[:n])
			}
		}()
		return r
	}
	var ln net.Listener
	var err error
	if scheme == "tls" {
		// The certificate of a test server, which is valid for 127.0.0.1
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		r.tls = &tls.Config{RootCAs: pool}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.read(c)
		}
	}()
	return r
}

// read takes the messages of a connection, each with its length in front of it (octet counting).
func (r *syslogReceiver) read(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		head, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSuffix(head, " "))
		if err != nil {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(br, msg); err != nil {
			return
		}
		r.msgs <- string(msg)
	}
}

// next returns the next message that the receiver got.
func (r *syslogReceiver) next(t *testing.T) string {
	t.Helper()
	select {
	case m := <-r.msgs:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("the syslog receiver got no message within 10 s")
	}
	return ""
}

// The records reach a syslog receiver as RFC 5424 messages over UDP, over TCP and over TLS, each in
// the order it was made, and a failure is a warning.
func TestExporterSendsSyslog(t *testing.T) {
	for _, scheme := range []string{"udp", "tcp", "tls"} {
		t.Run(scheme, func(t *testing.T) {
			s := &memStore{}
			rcv := newSyslogReceiver(t, scheme)
			s.add(Login)
			if err := s.AddAudit(context.Background(), Record{Time: time.Unix(1760000000, 0).UTC(), Kind: AuthFailed, Actor: ActorUnknown, Source: "198.51.100.1",
				Outcome: Failure, Message: "the request has no bearer token"}); err != nil {
				t.Fatal(err)
			}
			s.put(export.Target{Name: "siem", Kind: export.KindSyslog, URL: scheme + "://" + rcv.addr}, 0)
			x := NewExporter(s, nil, "ranz-controller/test", 0)
			x.TLS = rcv.tls
			x.host = "ctl-1"
			x.step(context.Background())

			first, second := rcv.next(t), rcv.next(t)
			if !strings.HasPrefix(first, "<110>1 ") || !strings.Contains(first, " ctl-1 ranz-controller - login - kind=login id=1 actor=system source=local outcome=success") {
				t.Errorf("the first message is %q", first)
			}
			if !strings.HasPrefix(second, "<108>1 ") || !strings.Contains(second, " - auth-failed - kind=auth-failed id=2 actor=unknown source=198.51.100.1 outcome=failure") ||
				!strings.HasSuffix(second, `message="the request has no bearer token"`) {
				t.Errorf("the second message is %q", second)
			}
			if s.deliveredTo("siem") != 2 {
				t.Errorf("the receiver was sent up to %d, want 2", s.deliveredTo("siem"))
			}
		})
	}
}

// A target that cannot be reached, that has a URL or a kind that no sender takes, is a failure
// that waits and tries again, and sends nothing.
func TestExporterFailsATargetItCannotSendTo(t *testing.T) {
	s := &memStore{}
	s.add(Login)
	names := []string{"odd", "bad-url", "bad-scheme", "refused", "bad-webhook"}
	for i, tg := range []export.Target{
		{Kind: "carrier-pigeon", URL: "http://127.0.0.1:1"},
		{Kind: export.KindSyslog, URL: "%zz"},
		{Kind: export.KindSyslog, URL: "http://127.0.0.1:1"},
		{Kind: export.KindSyslog, URL: "tcp://127.0.0.1:1"},
		{Kind: export.KindWebhook, URL: "http://[::1"},
	} {
		tg.Name = names[i]
		s.put(tg, 0)
	}
	x := NewExporter(s, nil, "ranz-controller/test", 0)
	x.step(context.Background())
	for _, name := range names {
		if s.deliveredTo(name) != 0 {
			t.Errorf("the target %s was sent up to %d, want nothing", name, s.deliveredTo(name))
		}
	}
	x.mu.Lock()
	waiting := len(x.attempts)
	x.mu.Unlock()
	if waiting != len(names) {
		t.Errorf("%d targets wait to be tried again, want %d", waiting, len(names))
	}
}

func TestExporterSurvivesAStoreThatFails(t *testing.T) {
	s := &memStore{}
	s.add(Login)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: "http://127.0.0.1:1"}, 0)
	x := NewExporter(s, nil, "ranz-controller/test", 0)

	s.err = errors.New("rqlite is down")
	x.step(context.Background())
	s.err = nil

	s.failRead = errors.New("the records cannot be read")
	x.step(context.Background())
	s.failRead = nil

	// The records are sent, and the record of the delivery fails
	h := newHook(t)
	s.put(export.Target{Name: "tap", Kind: export.KindWebhook, URL: h.URL}, 0)
	s.failDelivered = errors.New("the delivery cannot be recorded")
	x.step(context.Background())
	if n := len(h.records()); n != 1 || s.deliveredTo("tap") != 0 {
		t.Errorf("the webhook got %d records and was sent up to %d, want one record sent and not recorded", n, s.deliveredTo("tap"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	x.step(ctx)
}

func TestExporterRunsUntilStopped(t *testing.T) {
	s := &memStore{}
	h := newHook(t)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL}, 0)
	x := NewExporter(s, nil, "ranz-controller/test", time.Hour)
	var nobody *Exporter
	nobody.Poke()
	x.Stop()
	x.Start()
	s.add(Login)
	x.Poke()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.records()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a poke did not make the Exporter send the record within 5 s, with a poll interval of an hour")
		}
		time.Sleep(5 * time.Millisecond)
	}
	x.Stop()
	x.Stop()
	x.Poke()
}
