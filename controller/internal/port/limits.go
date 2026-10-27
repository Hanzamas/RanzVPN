package port

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// The limits for a source of the TLS port (AUD1-DT-3, #451; AP-11 of docs/threat-model.md), the ones that the front door
// and the QUIC listener of a node have in C (src/Core/SourceLimit.h). A connection counts as pending from the moment that
// the port takes it until its TLS handshake is done, which has 10 s at most (handshakeTimeout). At most MaxPending
// connections are pending in all and MaxPendingPerSource for one source, an IPv4 address or the /64 that an IPv6 address
// is in (control.SourceOf), so a source that opens many connections and holds them is cut at its cap and the others are
// served. A source also has a rate for its new connections and one for its TLS handshakes, each a bucket that holds
// Burst tokens and gets Rate more a second. The next connection, or the handshake, of a source over a limit is closed,
// and counted (Server.Refusals). The connections of the control stream are the connections of this port too, until their
// handshake is done; what a stream does after that is the cap of control.Waiting.
//
// The defaults are what an honest site does not meet: 1000 Nodes behind one NAT address that all connect in the same
// second are admitted, because 1000 is within the burst and within the cap for a source, and each Node is pending for a
// handshake only.
const (
	// DefaultMaxPending is the most connections that are pending in all.
	DefaultMaxPending = 4096
	// DefaultMaxPendingPerSource is the most that are pending for one source.
	DefaultMaxPendingPerSource = 1024
	// DefaultRate is how many new connections, and how many handshakes, a source may start in a second, and
	// DefaultBurst how many it may start at once.
	DefaultRate  = 200
	DefaultBurst = 2000

	// maxSources is the most sources that the limits keep. A source that holds nothing and has all its tokens is
	// forgotten, so only sources of the last seconds are in the table; when it is full of them, the next new source is
	// refused as if the port were full.
	maxSources = 8192
	// refusalLogEvery is how often a refusal is logged: the ones in between are counted in the next line.
	refusalLogEvery = 10 * time.Second
)

// Limits are the settings of the limits for a source of a Server. A field of 0 takes its default.
type Limits struct {
	// MaxPending is the most connections that are pending in all, and MaxPendingPerSource for one source.
	MaxPending          int
	MaxPendingPerSource int
	// ConnectRate is the new connections a second that a source may open, ConnectBurst how many at once.
	ConnectRate  float64
	ConnectBurst int
	// HandshakeRate is the TLS handshakes a second that a source may start, HandshakeBurst how many at once.
	HandshakeRate  float64
	HandshakeBurst int
}

// withDefaults returns l with the default in each field that is 0.
func (l Limits) withDefaults() Limits {
	if l.MaxPending <= 0 {
		l.MaxPending = DefaultMaxPending
	}
	if l.MaxPendingPerSource <= 0 {
		l.MaxPendingPerSource = DefaultMaxPendingPerSource
	}
	if l.ConnectRate <= 0 {
		l.ConnectRate = DefaultRate
	}
	if l.ConnectBurst <= 0 {
		l.ConnectBurst = DefaultBurst
	}
	if l.HandshakeRate <= 0 {
		l.HandshakeRate = DefaultRate
	}
	if l.HandshakeBurst <= 0 {
		l.HandshakeBurst = DefaultBurst
	}
	return l
}

// Refusals are what the limits for a source of a Server hold and refused since it started: the status of the Controller
// shows them (api.Status.Refused).
type Refusals struct {
	// Pending is how many connections wait for their TLS handshake now, and Sources how many sources the limits count.
	Pending int `json:"pending"`
	Sources int `json:"sources"`
	// Admitted is how many connections the limits let through.
	Admitted uint64 `json:"admitted"`
	// Full is how many connections were closed because too many were pending in all, Source because too many were
	// pending for their source, Rate because their source opened connections faster than its rate, and Handshake how
	// many were closed because their source started TLS handshakes faster than its rate.
	Full      uint64 `json:"full"`
	Source    uint64 `json:"source"`
	Rate      uint64 `json:"rate"`
	Handshake uint64 `json:"handshake"`
}

var (
	// errPendingFull is why a connection is refused when the most that may be pending in all are pending.
	errPendingFull = errors.New("port: too many connections wait for their TLS handshake")
	// errPendingSource is why it is refused when the most that may be pending for its source are pending.
	errPendingSource = errors.New("port: too many connections of one source wait for their TLS handshake")
	// errConnectRate is why it is refused when its source opens connections faster than its rate.
	errConnectRate = errors.New("port: the source opens connections faster than its rate")
	// errHandshakeRate is why a TLS handshake is refused when its source starts them faster than its rate.
	errHandshakeRate = errors.New("port: the source starts TLS handshakes faster than its rate")
)

// bucket is a token bucket: it holds tokens up to the burst, and gets rate more each second.
type bucket struct {
	tokens float64
	at     time.Time
}

// refill brings the bucket to now.
func (b *bucket) refill(now time.Time, rate float64, burst int) {
	if now.After(b.at) {
		b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*rate)
		b.at = now
	}
}

// take takes one token at now, and reports whether the bucket had one.
func (b *bucket) take(now time.Time, rate float64, burst int) bool {
	b.refill(now, rate, burst)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// source is what the limits know of one source: its pending connections and its two buckets.
type source struct {
	pending   int
	connect   bucket
	handshake bucket
}

// limiter holds the limits and the counters of a Server. It is safe for concurrent use.
type limiter struct {
	cfg Limits
	now func() time.Time

	mu       sync.Mutex
	pending  int
	sources  map[netip.Addr]*source
	admitted uint64
	full     uint64
	bySource uint64
	rate     uint64
	hshake   uint64

	logMu    sync.Mutex
	loggedAt time.Time
	skipped  uint64
}

// newLimiter returns the limits of cfg, with the defaults for what is 0, on the clock now.
func newLimiter(cfg Limits, now func() time.Time) *limiter {
	return &limiter{cfg: cfg.withDefaults(), now: now, sources: map[netip.Addr]*source{}}
}

// get returns the source src, new with full buckets when the limits do not know it, or nil when the table is full of
// sources that hold something. l.mu is held.
func (l *limiter) get(src netip.Addr, now time.Time) *source {
	if s, ok := l.sources[src]; ok {
		return s
	}
	if len(l.sources) >= maxSources {
		l.sweep(now)
	}
	if len(l.sources) >= maxSources {
		return nil
	}
	s := &source{connect: bucket{tokens: float64(l.cfg.ConnectBurst), at: now}, handshake: bucket{tokens: float64(l.cfg.HandshakeBurst), at: now}}
	l.sources[src] = s
	return s
}

// sweep forgets the sources that hold nothing and whose buckets are full again: they are the same as a source that
// was never seen. l.mu is held.
func (l *limiter) sweep(now time.Time) {
	for src, s := range l.sources {
		s.connect.refill(now, l.cfg.ConnectRate, l.cfg.ConnectBurst)
		s.handshake.refill(now, l.cfg.HandshakeRate, l.cfg.HandshakeBurst)
		if s.pending == 0 && s.connect.tokens >= float64(l.cfg.ConnectBurst) && s.handshake.tokens >= float64(l.cfg.HandshakeBurst) {
			delete(l.sources, src)
		}
	}
}

// enter counts a connection from remote that the port just took. It returns the function that the connection calls once
// its TLS handshake is done or it is closed, whichever comes first; a call after the first does nothing. When the
// connection is over a limit it returns the error that says which one and counts the refusal: the caller closes it.
func (l *limiter) enter(remote net.Addr) (leave func(), err error) {
	src := control.SourceOf(remote)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending >= l.cfg.MaxPending {
		l.full++
		return nil, errPendingFull
	}
	s := l.get(src, now)
	switch {
	case s == nil:
		l.full++
		return nil, errPendingFull
	case s.pending >= l.cfg.MaxPendingPerSource:
		l.bySource++
		return nil, errPendingSource
	case !s.connect.take(now, l.cfg.ConnectRate, l.cfg.ConnectBurst):
		l.rate++
		return nil, errConnectRate
	}
	l.pending++
	s.pending++
	l.admitted++
	return sync.OnceFunc(func() { l.leave(src) }), nil
}

// leave takes back the place that enter gave to a connection of the source src.
func (l *limiter) leave(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.sources[src]; ok && s.pending > 0 {
		s.pending--
		l.pending--
	}
}

// handshake counts a TLS handshake that a connection from remote starts now, when its ClientHello is read. It returns
// errHandshakeRate, and counts the refusal, when the source starts handshakes faster than its rate.
func (l *limiter) handshake(remote net.Addr) error {
	src := control.SourceOf(remote)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.get(src, now)
	if s == nil || !s.handshake.take(now, l.cfg.HandshakeRate, l.cfg.HandshakeBurst) {
		l.hshake++
		return errHandshakeRate
	}
	return nil
}

// refusals returns the counters.
func (l *limiter) refusals() Refusals {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Refusals{Pending: l.pending, Sources: len(l.sources), Admitted: l.admitted, Full: l.full, Source: l.bySource, Rate: l.rate, Handshake: l.hshake}
}

// logDue reports whether a refusal is logged now, and how many were not logged since the last one: at most one line
// in refusalLogEvery, so that a flood does not fill the log.
func (l *limiter) logDue() (skipped uint64, ok bool) {
	l.logMu.Lock()
	defer l.logMu.Unlock()
	now := l.now()
	if now.Sub(l.loggedAt) < refusalLogEvery {
		l.skipped++
		return 0, false
	}
	skipped, l.skipped, l.loggedAt = l.skipped, 0, now
	return skipped, true
}

// refuse closes raw, a connection that the limits for a source refused for the reason err, and logs it once in a while.
func (s *Server) refuse(raw net.Conn, err error) {
	if skipped, ok := s.limits.logDue(); ok {
		s.log.Warn("connection closed: over a limit for its source", "remote", raw.RemoteAddr().String(), "err", err, "skipped", skipped)
	}
	raw.Close()
}

// Refusals returns what the limits for a source hold and refused since the Server started.
func (s *Server) Refusals() Refusals {
	s.init()
	return s.limits.refusals()
}
