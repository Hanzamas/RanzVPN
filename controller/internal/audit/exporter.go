package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// DefaultPoll is how often the Exporter looks at the store for records that are due.
const DefaultPoll = time.Second

const (
	// maxBackoff is the longest wait between two attempts to send to a target that fails.
	maxBackoff = 5 * time.Minute
	// batch is how many records the Exporter reads from the store at once.
	batch = 200
	// dialTimeout bounds the connection to a syslog receiver, and sendTimeout one write to it and one
	// call of a webhook.
	dialTimeout = 5 * time.Second
	sendTimeout = 10 * time.Second
)

// attempt is how far the delivery to one target has got when it fails: how often it was tried in a
// row, and when it may be tried again.
type attempt struct {
	count int
	next  time.Time
}

// Exporter sends the audit log to the audit targets that an operator configured (SDN-49 #242): to
// each webhook, every record as a JSON POST signed with the secret of the target, and to each
// syslog receiver, every record as an RFC 5424 message over UDP, TCP or TLS. Each target is sent
// the records in the order they were made, once the store holds them, and the store keeps for each
// target the last record it was sent, so a controller that restarts, or the next leader of a
// cluster, goes on where the last one stopped. A target that fails is tried again with a growing wait
// (to five minutes), and no record is skipped for it: the records wait in the store, where the
// retention policy bounds them, until the target takes them or an operator deletes it. A record can be
// sent twice, when the write of a batch fails after some of it was written.
type Exporter struct {
	// TLS is the configuration of the connection to a tls:// target, the default one (the system's
	// roots) when it is nil. Set it before Start.
	TLS *tls.Config

	store  Store
	log    *slog.Logger
	client *http.Client
	guard  *export.Guard // nil: connect to any address
	agent  string
	host   string
	poll   time.Duration
	now    func() time.Time
	wake   chan struct{}

	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	attempts map[string]attempt
}

// NewExporter returns an Exporter on s that looks for records every poll (DefaultPoll when it is
// not above 0). agent is the User-Agent of the webhook calls. Start runs it.
func NewExporter(s Store, log *slog.Logger, agent string, poll time.Duration) *Exporter {
	if poll <= 0 {
		poll = DefaultPoll
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	host, _ := os.Hostname()
	// A webhook that answers with a redirect has failed: the call must not go on to a host that the
	// operator did not name.
	client := &http.Client{Timeout: sendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Exporter{
		store:    s,
		log:      log,
		client:   client,
		agent:    agent,
		host:     strings.ToLower(host),
		poll:     poll,
		now:      time.Now,
		wake:     make(chan struct{}, 1),
		attempts: map[string]attempt{},
	}
}

// SetGuard makes the Exporter connect to its targets only where g allows (AUD1-DT-9 #457): each
// webhook call and each syslog connection is checked when it is made. Set it before Start.
func (x *Exporter) SetGuard(g *export.Guard) {
	x.guard = g
	x.client = g.HTTPClient(sendTimeout)
}

// Start runs the Exporter on a goroutine of its own until Stop.
func (x *Exporter) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	x.cancel, x.done = cancel, make(chan struct{})
	go func() {
		defer close(x.done)
		t := time.NewTicker(x.poll)
		defer t.Stop()
		for {
			x.step(ctx)
			select {
			case <-ctx.Done():
				return
			case <-x.wake:
			case <-t.C:
			}
		}
	}()
}

// Stop ends the Exporter and waits until its goroutine returns. A delivery that is in flight is
// cancelled.
func (x *Exporter) Stop() {
	if x.cancel != nil {
		x.cancel()
		<-x.done
	}
}

// Poke has the Exporter look at the store at once, for a caller that just added a record. An
// Exporter that is nil, as before the controller started it, has nothing to wake.
func (x *Exporter) Poke() {
	if x == nil {
		return
	}
	select {
	case x.wake <- struct{}{}:
	default:
	}
}

// step makes the deliveries that are due.
func (x *Exporter) step(ctx context.Context) {
	targets, err := x.store.AuditTargets(ctx)
	if err != nil {
		if ctx.Err() == nil {
			x.log.Warn("audit export: reading the targets failed", "err", err)
		}
		return
	}
	for _, t := range targets {
		x.deliver(ctx, t)
	}
}

// deliver sends the target t the records after the last one it was sent, in order, until one fails.
func (x *Exporter) deliver(ctx context.Context, t export.Stored) {
	x.mu.Lock()
	at := x.attempts[t.Name]
	x.mu.Unlock()
	if x.now().Before(at.next) {
		return
	}
	for {
		recs, err := x.store.Audit(ctx, Filter{After: t.Delivered, Limit: batch})
		if err != nil {
			if ctx.Err() == nil {
				x.log.Warn("audit export: reading the records failed", "target", t.Name, "err", err)
			}
			return
		}
		if len(recs) == 0 {
			return
		}
		var wanted []Record
		for _, r := range recs {
			if t.Wants(r.Kind) {
				wanted = append(wanted, r)
			}
		}
		sent, sendErr := x.send(ctx, t.Target, wanted)
		// Every record before the first one that was not sent is done: sent, or not wanted.
		upTo := recs[len(recs)-1].ID
		if sent < len(wanted) {
			upTo = wanted[sent].ID - 1
		}
		if upTo > t.Delivered {
			if err := x.store.AuditDelivered(ctx, t.Name, upTo); err != nil {
				if ctx.Err() == nil {
					x.log.Warn("audit export: recording a delivery failed", "target", t.Name, "record", upTo, "err", err)
				}
				return
			}
			t.Delivered = upTo
		}
		if sendErr != nil {
			if ctx.Err() == nil {
				x.failed(t, at, sendErr)
			}
			return
		}
		x.mu.Lock()
		delete(x.attempts, t.Name)
		x.mu.Unlock()
		at = attempt{}
		if len(recs) < batch {
			return
		}
	}
}

// failed records that the delivery to the target t failed with err, the at.count-th time in a row:
// the next attempt is later.
func (x *Exporter) failed(t export.Stored, at attempt, err error) {
	at.count++
	wait := min(time.Second<<min(at.count-1, 8), maxBackoff)
	at.next = x.now().Add(wait)
	x.mu.Lock()
	x.attempts[t.Name] = at
	x.mu.Unlock()
	x.log.Warn("audit export: a target failed, trying again later", "target", t.Name, "kind", t.Kind, "attempt", at.count, "wait", wait, "err", err)
}

// send sends recs to the target t and returns how many of them it sent, in order, before it failed.
func (x *Exporter) send(ctx context.Context, t export.Target, recs []Record) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	switch t.Kind {
	case export.KindWebhook:
		for i, r := range recs {
			if err := x.post(ctx, t, r); err != nil {
				return i, err
			}
		}
		return len(recs), nil
	case export.KindSyslog:
		return x.syslog(ctx, t, recs)
	}
	return 0, fmt.Errorf("the audit target %q has the kind %q, which is none of %s and %s", t.Name, t.Kind, export.KindWebhook, export.KindSyslog)
}

// post sends r to the webhook t as JSON, signed with its secret when it has one. Any answer other
// than 2xx is an error.
func (x *Exporter) post(ctx context.Context, t export.Target, r Record) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", x.agent)
	req.Header.Set("X-Ranz-Audit", r.Kind)
	req.Header.Set("X-Ranz-Audit-Id", strconv.FormatUint(r.ID, 10))
	if t.Secret != "" {
		mac := hmac.New(sha256.New, []byte(t.Secret))
		mac.Write(body)
		req.Header.Set("X-Ranz-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := x.client.Do(req)
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

// syslog sends recs to the syslog receiver t over one connection: a datagram for each record over
// UDP, and over TCP and TLS each message with the length in front of it (octet counting, RFC 6587
// section 3.4.1 and RFC 5425 section 4.3), so that no message can break the framing.
func (x *Exporter) syslog(ctx context.Context, t export.Target, recs []Record) (int, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return 0, err
	}
	conn, err := x.dial(ctx, u)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	for i, r := range recs {
		msg := r.Syslog(x.host)
		if u.Scheme != "udp" {
			msg = strconv.Itoa(len(msg)) + " " + msg
		}
		if err := conn.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
			return i, err
		}
		if _, err := io.WriteString(conn, msg); err != nil {
			return i, err
		}
	}
	return len(recs), nil
}

// dial connects to the syslog receiver at u.
func (x *Exporter) dial(ctx context.Context, u *url.URL) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	switch u.Scheme {
	case "udp", "tcp":
		if x.guard != nil {
			return x.guard.DialContext(ctx, u.Scheme, u.Host)
		}
		return d.DialContext(ctx, u.Scheme, u.Host)
	case "tls":
		if x.guard != nil {
			return x.guardedTLS(ctx, u)
		}
		return (&tls.Dialer{NetDialer: d, Config: x.TLS}).DialContext(ctx, "tcp", u.Host)
	}
	return nil, fmt.Errorf("the scheme %q of a syslog target is none of udp, tcp and tls", u.Scheme)
}

// guardedTLS connects to the tls:// receiver u through the Guard and starts TLS on the connection,
// as tls.Dialer does: the name of the host is the one the certificate must carry.
func (x *Exporter) guardedTLS(ctx context.Context, u *url.URL) (net.Conn, error) {
	conn, err := x.guard.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{}
	if x.TLS != nil {
		cfg = x.TLS.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}
