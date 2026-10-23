// Package audit is the controller's audit log (SDN-49 #242, ADR-0030): one Record for each login,
// logout, failed authentication, enrolment, change of the intent and operation, with who did it,
// when, from where and how it ended. The store keeps the records (internal/store). The Log adds
// them; the Exporter sends each one to the syslog and webhook receivers that an operator configured,
// the audit targets; and the retention policy removes the old ones (Retain). The audit log is the
// controller's record of who did what. The Events of internal/event are a different thing: the
// conditions that the controller reports to operators. What a node logs locally to ETW is the
// node's own part (ADR-0030 decision 2) and is not here.
package audit

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// The kinds of a Record.
const (
	// Login: a principal authenticated and its session began. Today that is a node that opened its
	// control stream, whose static key a Node resource holds. The logins of users and administrators
	// (SDN-32 #226) record themselves as this kind too.
	Login = "login"
	// Logout: a session ended, today the control stream of a node.
	Logout = "logout"
	// AuthFailed: a credential was refused: an API call whose bearer token is missing or is not one
	// of the controller's, or a node whose static key no Node resource holds.
	AuthFailed = "auth-failed"
	// Enrolment: the static key of a node reached the controller for the first time, in the first
	// Hello of its control stream.
	Enrolment = "enrolment"
	// IntentChange: a change of the intent. Revision is the revision that it made and Action the
	// operation of that revision (apply, delete, rollback, import, automatic-rollback or
	// first-start). A change that an API call asked for and that was refused has no revision.
	IntentChange = "intent-change"
	// Operation: any other call of the API that changes something: a licence key, an export target,
	// an API token. The live operations of SDN-50 (#243) are recorded as this kind.
	Operation = "operation"
)

// Kinds lists the kinds of a Record, in the order of the list above.
var Kinds = []string{Login, Logout, AuthFailed, Enrolment, IntentChange, Operation}

// The outcomes of a Record.
const (
	Success = "success"
	// Failure: it was tried and did not work: a credential that was refused, a change that was
	// invalid or refused.
	Failure = "failure"
)

// The actor and the source of a Record that has no caller to name.
const (
	// ActorSystem is the controller itself: its first start, and the automatic rollback of a revision
	// that nobody confirmed.
	ActorSystem = "system"
	// ActorUnknown is a caller that did not authenticate.
	ActorUnknown = "unknown"
	// SourceLocal is the source of what no remote caller made.
	SourceLocal = "local"
)

// ActorToken returns the actor of the API token name.
func ActorToken(name string) string { return "token:" + name }

// ActorNode returns the actor of the node name.
func ActorNode(name string) string { return "node:" + name }

// ActorKey returns the actor of a caller that proved a static key, which no resource holds: the key,
// in base64, so that an operator can write the Node resource for it.
func ActorKey(publicKey []byte) string { return "key:" + base64.StdEncoding.EncodeToString(publicKey) }

// The limits of the text of a Record, which a caller or a failing request can influence: the store
// never holds more than this of any field.
const (
	maxActor   = 128
	maxSource  = 64
	maxAction  = 160
	maxSubject = 256
	maxMessage = 512
)

// storeTimeout bounds one write to or read from the store.
const storeTimeout = 30 * time.Second

// ErrInvalid marks a Record, a Filter, an audit retention or an audit target that is not valid.
var ErrInvalid = errors.New("invalid audit request")

// Record is one entry of the audit log: who did what to what, when, from where, and how it ended.
type Record struct {
	ID   uint64    `json:"id"` // given by the store, in the order of the records
	Time time.Time `json:"time"`
	// Kind is one of Kinds.
	Kind string `json:"kind"`
	// Actor is who did it: the API token (ActorToken), the node (ActorNode), the key that no
	// resource holds (ActorKey), ActorSystem, or ActorUnknown for a caller that did not authenticate.
	Actor string `json:"actor"`
	// Source is where it came from: the address of the remote caller without its port, or SourceLocal.
	Source string `json:"source"`
	// Outcome is Success or Failure.
	Outcome string `json:"outcome"`
	// Action is what was done: the operation of the revision of an IntentChange, the call of an
	// Operation (for example PUT /api/v1/targets/slack).
	Action string `json:"action,omitempty"`
	// Subject is what it was done to, when Action does not say.
	Subject string `json:"subject,omitempty"`
	// Revision is the revision that an IntentChange made.
	Revision uint64 `json:"revision,omitempty"`
	// Message says more: why a failure failed.
	Message string `json:"message,omitempty"`
}

// Origin is where a call came from as the API's guard knows it: who made it and from which
// address. It travels in the context of the call (NewContext) to the controller, which fills in the
// actor and the source of the records that the call makes.
type Origin struct {
	Actor  string
	Source string
}

type originKey struct{}

// NewContext returns ctx with the origin o in it.
func NewContext(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// FromContext returns the origin that NewContext put in ctx.
func FromContext(ctx context.Context) (Origin, bool) {
	o, ok := ctx.Value(originKey{}).(Origin)
	return o, ok
}

// Host returns the host of the remote address addr, which a connection gives as host:port, so that
// the calls of one source are one source whatever their ports are. An address that is not host:port
// is returned as it is.
func Host(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap().String()
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// Store is what the audit log needs of the controller's store (internal/store).
type Store interface {
	// AddAudit stores r, which gets the next id.
	AddAudit(ctx context.Context, r Record) error
	// Audit returns the records that match f, the oldest first.
	Audit(ctx context.Context, f Filter) ([]Record, error)
	// PruneAudit removes the records made before the time before, and then the oldest ones until at
	// most keep remain when keep is above 0.
	PruneAudit(ctx context.Context, before time.Time, keep int) error
	// AuditRetention returns the retention policy that an operator set, and false when none is set.
	AuditRetention(ctx context.Context) (Retention, bool, error)
	// SetAuditRetention sets the retention policy.
	SetAuditRetention(ctx context.Context, r Retention) error
	// AuditTargets returns every audit target, ordered by name, with the id of the last record that
	// it was sent.
	AuditTargets(ctx context.Context) ([]export.Stored, error)
	// PutAuditTarget stores t, which replaces the audit target of its name. A new target starts at
	// the latest record: it is sent the records that follow, not the ones of before it existed.
	PutAuditTarget(ctx context.Context, t export.Target) error
	// DeleteAuditTarget deletes the audit target name. It is no error when there is none.
	DeleteAuditTarget(ctx context.Context, name string) error
	// AuditDelivered records that the audit target name was sent every record up to id.
	AuditDelivered(ctx context.Context, name string, id uint64) error
}

// Config is what the audit log of a controller runs with.
type Config struct {
	// Poll is how often the Exporter looks for records that are due: DefaultPoll when it is 0. A
	// record that the controller adds wakes it at once.
	Poll time.Duration
	// Prune is how often the leader removes the records past the retention policy: DefaultPrune when
	// it is 0.
	Prune time.Duration
}

const (
	// authFailedEvery is how often the Log makes a record of the failed authentications of one
	// source: a caller that guesses tokens does not fill the store. The first failure of a source
	// is always recorded.
	authFailedEvery = 10 * time.Second
	// maxSources bounds the sources that the Log remembers for that.
	maxSources = 4096
)

// Log adds records to the audit log in the store.
type Log struct {
	store Store
	log   *slog.Logger
	now   func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // for each source, when its last failed authentication was recorded
}

// NewLog returns a Log on s. A record that cannot be stored is logged to log, which is discarded
// when it is nil.
func NewLog(s Store, log *slog.Logger) *Log {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Log{store: s, log: log, now: time.Now, seen: map[string]time.Time{}}
}

// Record adds r to the audit log. A record without a time is made now. One without an actor or a
// source gets the ones of the origin in ctx (NewContext), and ActorSystem and SourceLocal when ctx
// has none. Any text that is too long is cut. A kind or an outcome that does not exist is refused
// with an error that wraps ErrInvalid. Of the failed authentications of one source only the first
// in authFailedEvery is recorded, the others are dropped without an error. The write does not end
// when ctx does: a caller that goes away does not make the record vanish.
func (l *Log) Record(ctx context.Context, r Record) error {
	switch {
	case !slices.Contains(Kinds, r.Kind):
		return fmt.Errorf("%w: the kind %q is none of %v", ErrInvalid, r.Kind, Kinds)
	case r.Outcome != Success && r.Outcome != Failure:
		return fmt.Errorf("%w: the outcome %q is %s or %s", ErrInvalid, r.Outcome, Success, Failure)
	}
	o, _ := FromContext(ctx)
	r.ID = 0
	r.Actor = clip(cmp.Or(r.Actor, o.Actor, ActorSystem), maxActor)
	r.Source = clip(cmp.Or(r.Source, o.Source, SourceLocal), maxSource)
	if r.Time.IsZero() {
		r.Time = l.now()
	}
	r.Time = r.Time.UTC().Truncate(time.Millisecond)
	r.Action = clip(r.Action, maxAction)
	r.Subject = clip(r.Subject, maxSubject)
	r.Message = clip(r.Message, maxMessage)
	if r.Kind == AuthFailed && !l.allow(r.Source) {
		return nil
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := l.store.AddAudit(sctx, r); err != nil {
		l.log.Error("audit log: a record was not stored", "kind", r.Kind, "actor", r.Actor, "source", r.Source, "err", err)
		return err
	}
	return nil
}

// allow reports whether a failed authentication from source is to be recorded now, and remembers
// that it was.
func (l *Log) allow(source string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.seen[source]; ok && now.Sub(last) < authFailedEvery {
		return false
	}
	if len(l.seen) >= maxSources {
		for s, last := range l.seen {
			if now.Sub(last) >= authFailedEvery {
				delete(l.seen, s)
			}
		}
		if len(l.seen) >= maxSources {
			return false
		}
	}
	l.seen[source] = now
	return true
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
