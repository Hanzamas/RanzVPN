package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The restriction of the API and the web UI to the admin source allowlist (SDN-39, #232). Sources
// stands in front of both, outside the Guard: a request from an address that the allowlist does
// not hold is answered 403 Forbidden before anything else looks at it, its token included, and is
// recorded as an event. Every member of a controller cluster makes the check on the requests it
// accepts, from the allowlist in the store that all of them read. A standby that forwards a call
// to the leader is a source of that call there, so the allowlist must hold the addresses of the
// members too (ADR-0031, amendment of SDN-39). The control stream of the nodes is not behind it:
// a Network limits where its nodes enrol from (internal/controller).

// auditTimeout bounds the write of the event of a refusal, so that a store that does not answer
// cannot hold the refusal back.
const auditTimeout = 5 * time.Second

// SourceStore is what Sources needs of the store: the admin source allowlist, and a place for the
// events of the refusals. *store.Store is one.
type SourceStore interface {
	AdminSources(ctx context.Context) ([]string, error)
	Commit(ctx context.Context, c store.Changes) error
}

// Sources restricts the API and the web UI to the admin source allowlist (Restrict).
type Sources struct {
	st  SourceStore
	log *slog.Logger
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	list     []netip.Prefix // the allowlist as it was read last, nil before the first read
	loaded   time.Time      // when it was read, the zero time before the first read
	refusals event.Throttle
	// audit is the audit log that a refusal is recorded in as well, nil for none (WithAudit).
	audit *audit.Log
}

// NewSources returns the restriction to the admin source allowlist that st holds. A read of the
// allowlist is used for ttl, so that a request costs no read of the store; with a ttl of 0 every
// request reads it. A change of the allowlist reaches the requests of a member within ttl. log is
// discarded when it is nil.
func NewSources(st SourceStore, log *slog.Logger, ttl time.Duration) *Sources {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Sources{st: st, log: log, ttl: ttl, now: time.Now}
}

// WithAudit makes s record each refusal that it records as an event in the audit log l as well,
// as a failed authentication from the address that was refused (SDN-49, #242), and returns s.
func (s *Sources) WithAudit(l *audit.Log) *Sources {
	s.audit = l
	return s
}

// Restrict returns h behind the admin source allowlist. A request from a loopback address, which
// is the host of the controller itself, is always served, before the allowlist is read, so that a
// list that is damaged or cannot be read never locks the host out. For any other address, h
// serves every request while the allowlist holds no prefix, and otherwise the requests from the
// addresses that it holds; every other request is answered 403 Forbidden and recorded as an event.
// While the allowlist cannot be read at all, nothing but a loopback request is served: 503 Service
// Unavailable.
func (s *Sources) Restrict(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from, _ := intent.SourceAddr(r.RemoteAddr)
		if from.IsLoopback() {
			h.ServeHTTP(w, r)
			return
		}
		list, err := s.current(r.Context())
		if err != nil {
			s.log.Warn("reading the admin source allowlist", "err", err)
			reply(w, http.StatusServiceUnavailable, Problem{Error: "the admin source allowlist cannot be read at the moment, so the controller serves nothing: try again in a few seconds"})
			return
		}
		if len(list) == 0 || adminAllows(list, from) {
			h.ServeHTTP(w, r)
			return
		}
		s.refuse(r, from)
		reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the address %s is not allowed to reach the API and the web UI of this controller", from)})
	})
}

// adminAllows reports whether a request from the address from passes the allowlist list. A
// loopback address, the host of the controller itself, always does, so that an administrator can
// still reach the controller when the list does not hold their address.
func adminAllows(list []netip.Prefix, from netip.Addr) bool {
	return from.IsLoopback() || intent.ContainsSource(list, from)
}

// current returns the admin source allowlist: the one read within the last ttl, else a new read.
// A read that fails leaves the list of the read before in force, and is tried again after ttl;
// with no read before, the error is returned, so that nothing is served on a list that cannot be
// known.
func (s *Sources) current(ctx context.Context) ([]netip.Prefix, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.loaded.IsZero() && now.Sub(s.loaded) < s.ttl {
		return s.list, nil
	}
	list, err := s.read(ctx)
	switch {
	case err == nil:
		s.list, s.loaded = list, now
	case s.loaded.IsZero():
		return nil, err
	default:
		s.log.Warn("reading the admin source allowlist failed, so the last one stays in force", "err", err)
		s.loaded = now
	}
	return s.list, nil
}

// read reads the admin source allowlist from the store.
func (s *Sources) read(ctx context.Context) ([]netip.Prefix, error) {
	list, err := s.st.AdminSources(ctx)
	if err != nil {
		return nil, err
	}
	return intent.ParseSources(list)
}

// refuse records the refusal of the request r, which came from the address from, as an event,
// unless the throttle holds it back: a client that is refused again and again is recorded once a
// minute, with the count of the refusals that were not.
func (s *Sources) refuse(r *http.Request, from netip.Addr) {
	now := s.now()
	method, path := clip(r.Method, 16), clip(r.URL.Path, 100)
	skipped, ok := s.refusals.Take(from.String(), now)
	if !ok {
		s.log.Debug("admin access refused: the source address is outside the admin source allowlist", "remote", from.String(), "method", method, "path", path)
		return
	}
	s.log.Warn("admin access refused: the source address is outside the admin source allowlist", "remote", from.String(), "method", method, "path", path)
	msg := fmt.Sprintf("%s %q from %s was refused: the address is outside the admin source allowlist", method, path, from)
	if skipped > 0 {
		msg += fmt.Sprintf(" (refusals not recorded since the last record: %d)", skipped)
	}
	ev := event.Event{Time: now.UTC().Truncate(time.Millisecond), Type: event.AdminAccessRefused, Message: msg}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditTimeout)
	defer cancel()
	if err := s.st.Commit(ctx, store.Changes{AddEvents: []event.Event{ev}}); err != nil {
		s.log.Error("recording a refused admin access", "err", err)
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Record{Kind: audit.AuthFailed, Actor: audit.ActorUnknown, Source: from.String(), Outcome: audit.Failure, Message: msg})
	}
}

// clip returns s shortened to n bytes, with an ellipsis when it was longer.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
