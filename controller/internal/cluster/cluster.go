// Package cluster runs a controller as a member of a controller cluster (#176 "Controller and
// high availability", SDN-17, ADR-0026). Each member runs its own rqlite member as a sidecar
// (internal/sidecar), and the rqlite members form one Raft cluster that holds the store. One
// member at a time, the leader, holds the lease in the store (internal/store) and runs the
// controller: it applies the intent and serves the control streams. The others are standbys. A
// standby refuses a node with REFUSE_REASON_NOT_LEADER and the address of the leader, and
// forwards every API call but the status to the leader, so management works through any member.
// When the leader is lost, a standby takes the lease once it has seen it unchanged for a whole
// lease duration, loads the intent and the node states from the store, and leads. A single
// controller is a cluster of one member and runs the same code.
//
// The lease follows the leader election of Kubernetes (client-go tools/leaderelection, with a
// 15 s lease, a 10 s renew deadline and a 2 s retry period by default): the leader renews every
// fifth of the lease duration and steps down when it could not renew for two thirds of it, which
// is before any standby may take over. The epoch of the lease fences every write of the leader
// (store.Fenced), so a leader that lost the lease and has not noticed yet writes nothing.
package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// DefaultLease is the lease duration when the configuration gives none.
const DefaultLease = 15 * time.Second

const (
	helloTimeout   = 10 * time.Second // from the end of the handshake to the Hello, on a standby
	writeTimeout   = 10 * time.Second // for the Refuse of a standby
	releaseTimeout = 5 * time.Second  // for the release of the lease when the leader stops
	// forwardedHeader marks an API call that a standby forwarded, so that the member it reaches
	// does not forward it again.
	forwardedHeader = "Ranz-Forwarded-By"
	// maxRefuseMessage is the size of Refuse.message on the C node, without the terminating NUL.
	maxRefuseMessage = 255
)

// Config is what a member runs with.
type Config struct {
	// Name is the member's name, unique in the cluster.
	Name string
	// Address is host:port of the member's port as the nodes and the other members reach it.
	// While the member leads, the standbys name it to the nodes and forward API calls to it. When
	// it is empty, they cannot do either.
	Address string
	// Fingerprint is the TLS fingerprint of the member's certificate (keys.Fingerprint), which a
	// standby checks when it forwards to this member.
	Fingerprint string
	// Store is the member's connection to its rqlite member.
	Store *store.Store
	// Tokens are the API tokens, in Store, which every member knows.
	Tokens *rbac.Tokens
	// Key is the member's Noise static key.
	Key keys.Static
	// Schema is the control schema version the controller runs as (controller.Config.Schema).
	Schema controlpb.SchemaVersion
	// LicenceKeys are the public keys that a licence key must be signed with
	// (controller.Config.LicenceKeys): licence.VendorKeys() when nil.
	LicenceKeys []ed25519.PublicKey
	// Lease is the lease duration, DefaultLease when it is 0.
	Lease time.Duration
	// Log is discarded when it is nil.
	Log *slog.Logger
	// Status is what GET /api/v1/status reports besides the public key and the cluster part.
	Status api.Status
	// Defaults has the first leader of an empty store create the intent of a first install
	// (controller.Config.Defaults).
	Defaults bool
}

// Member is one member of a controller cluster.
type Member struct {
	cfg      Config
	log      *slog.Logger
	retry    time.Duration // the period of the lease loop
	deadline time.Duration // the leader steps down when it could not renew for this long
	cancel   context.CancelFunc
	done     chan struct{}

	// audit records the calls that this member's Guard refuses as unauthenticated (SDN-49).
	audit *audit.Log

	// Used by the lease loop only.
	seen      store.Lease // the lease as this member saw it last
	seenSince time.Time   // since when it is unchanged
	renewed   time.Time   // the last renewal of this member's lease

	mu       sync.Mutex
	active   *controller.Controller // non-nil while this member leads
	handler  http.Handler           // the API of active
	lease    store.Lease            // the lease of the leader as this member knows it
	proxy    *httputil.ReverseProxy // forwards to the leader; nil while this member leads or knows none
	proxyFor store.Lease            // the lease of the member that proxy forwards to
}

// Start starts the member. It tries once to take the lease, and leads when it gets it, before it
// returns; then the lease loop runs until Close. A free lease, or one that held the member's own
// name before a restart, goes to the member at once, so a single controller leads when Start
// returns, unless its try failed: the try has a fifth of the lease duration to read the lease and
// to take it, which a store that answers late overruns. The member is then a standby until the next
// try of the lease loop, so a caller that needs the lead waits for it (Status).
func Start(cfg Config) (*Member, error) {
	if cfg.Name == "" {
		return nil, errors.New("cluster: the member has no name")
	}
	if cfg.Lease == 0 {
		cfg.Lease = DefaultLease
	}
	m := &Member{cfg: cfg, log: cfg.Log, retry: cfg.Lease / 5, deadline: cfg.Lease * 2 / 3, done: make(chan struct{})}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	m.log = m.log.With("member", cfg.Name)
	m.audit = audit.NewLog(cfg.Store, m.log)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.step(ctx)
	go m.loop(ctx)
	return m, nil
}

// Close stops the member. A leader closes its control streams and releases the lease, so that a
// standby takes it at once.
func (m *Member) Close() {
	m.cancel()
	<-m.done
}

// ServeStream serves the control stream of a node on tc, a TLS connection that negotiated
// control.ALPN: the controller takes it while this member leads; a standby refuses the node with
// REFUSE_REASON_NOT_LEADER and names the leader.
func (m *Member) ServeStream(tc *tls.Conn) {
	m.mu.Lock()
	c, l := m.active, m.lease
	m.mu.Unlock()
	if c != nil {
		c.ServeStream(tc)
		return
	}
	conn, err := control.Accept(context.Background(), tc, m.cfg.Key)
	if err != nil {
		m.log.Debug("control stream handshake failed", "remote", tc.RemoteAddr().String(), "err", err)
		return
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(helloTimeout)); err != nil {
		return
	}
	if _, _, err := conn.Read(); err != nil {
		return
	}
	r := &controlpb.Refuse{Reason: controlpb.RefuseReason_REFUSE_REASON_NOT_LEADER, Message: "this controller is a standby, and no member of the cluster leads at the moment"}
	if l.Holder != "" && l.Holder != m.cfg.Name {
		r.Message = "this controller is a standby: the leader is " + l.Holder
		if l.Address != "" {
			r.Message += " at " + l.Address
			r.Leader = l.Address
		}
	}
	if len(r.Message) > maxRefuseMessage {
		r.Message = r.Message[:maxRefuseMessage]
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Refuse{Refuse: r}})
	m.log.Debug("node refused: standby", "remote", conn.RemoteAddr().String(), "leader", l.Holder)
}

// Handler returns the member's HTTP API: GET /api/v1/status answers for this member, every other
// call goes to the controller of the leader, here or forwarded to the member that leads with the
// caller's bearer token, which the leader checks again. Every call needs the role that the API
// asks for it (api.Guard): the tokens are in the store, so every member knows them. A call that
// the Guard of a member refuses as unauthenticated is a failed authentication in the audit log
// (api.AuditRefusals); the calls that change something are recorded by the leader that serves them.
func (m *Member) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		api.Reply(w, http.StatusOK, m.Status())
	})
	mux.HandleFunc("/", m.serveAPI)
	return api.AuditRefusals(m.audit, api.Guard(m.cfg.Tokens, mux))
}

// Status returns the answer of GET /api/v1/status of this member.
func (m *Member) Status() api.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.cfg.Status
	s.PublicKey = base64.StdEncoding.EncodeToString(m.cfg.Key.Public())
	schema := m.cfg.Schema
	if schema == controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED {
		schema = controller.SchemaVersion
	}
	cs := &api.ClusterStatus{Member: m.cfg.Name, Role: api.RoleStandby, SchemaVersion: int32(schema)}
	if m.active != nil {
		cs.Role = api.RoleLeader
	}
	if m.lease.Holder != "" && (m.active != nil || m.lease.Holder != m.cfg.Name) {
		cs.Leader, cs.Epoch = m.lease.Holder, m.lease.Epoch
	}
	s.Cluster = cs
	return s
}

func (m *Member) serveAPI(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	h, p, l := m.handler, m.proxy, m.lease
	m.mu.Unlock()
	switch {
	case h != nil:
		h.ServeHTTP(w, r)
	case p != nil && r.Header.Get(forwardedHeader) == "":
		p.ServeHTTP(w, r)
	case l.Holder != "" && l.Holder != m.cfg.Name:
		api.Reply(w, http.StatusServiceUnavailable, api.Problem{Error: fmt.Sprintf("this controller is a standby and cannot forward to the leader %s: try again in a few seconds", l.Holder)})
	default:
		api.Reply(w, http.StatusServiceUnavailable, api.Problem{Error: "this controller is a standby, and no member of the cluster leads at the moment: try again in a few seconds"})
	}
}

// loop runs the lease loop until Close.
func (m *Member) loop(ctx context.Context) {
	defer close(m.done)
	t := time.NewTicker(m.retry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.stepDown(true)
			return
		case <-t.C:
			m.step(ctx)
		}
	}
}

// step runs one round of the lease loop: the leader renews its lease; a standby reads the lease
// and takes it when it may.
func (m *Member) step(ctx context.Context) {
	m.mu.Lock()
	leading := m.active != nil
	m.mu.Unlock()
	if leading {
		m.renew(ctx)
	} else {
		m.campaign(ctx)
	}
}

// campaign takes the lease when it is free, when it held this member's name (the member
// restarted), or when it stayed unchanged for a whole lease duration (its holder is lost).
func (m *Member) campaign(ctx context.Context) {
	sctx, cancel := context.WithTimeout(ctx, m.retry)
	defer cancel()
	l, err := m.cfg.Store.Lease(sctx)
	if err != nil {
		m.log.Debug("reading the lease", "err", err)
		return
	}
	now := time.Now()
	if l != m.seen || m.seenSince.IsZero() {
		m.seen, m.seenSince = l, now
	}
	m.know(l)
	if l.Holder != "" && l.Holder != m.cfg.Name && now.Sub(m.seenSince) < m.cfg.Lease {
		return
	}
	me := store.Lease{Holder: m.cfg.Name, Address: m.cfg.Address, Fingerprint: m.cfg.Fingerprint}
	won, err := m.cfg.Store.Acquire(sctx, l, me)
	if err != nil {
		m.log.Debug("taking the lease", "err", err)
		return
	}
	if !won {
		return
	}
	m.renewed = time.Now()
	me.Epoch, me.Renewal = l.Epoch+1, l.Renewal+1
	m.lead(ctx, me)
}

// lead runs the controller as the holder of lease l, which this member took just now: it loads
// the intent and the node states from the store, and every write it makes is fenced by the
// epoch of l.
func (m *Member) lead(ctx context.Context, l store.Lease) {
	c, err := controller.New(ctx, controller.Config{Store: m.cfg.Store.Fenced(l.Epoch), Key: m.cfg.Key, Log: m.log, Schema: m.cfg.Schema, LicenceKeys: m.cfg.LicenceKeys,
		Defaults: m.cfg.Defaults})
	if err != nil {
		m.log.Error("taking the lead", "epoch", l.Epoch, "err", err)
		m.release(l.Epoch)
		return
	}
	h := api.AuditCalls(c, api.Routes(c, m.cfg.Tokens, m.cfg.Status))
	m.mu.Lock()
	m.active, m.handler, m.lease = c, h, l
	m.proxy, m.proxyFor = nil, store.Lease{}
	m.mu.Unlock()
	m.log.Info("leading", "epoch", l.Epoch, "previous", m.seen.Holder)
}

// renew renews the lease of the leader, and steps down when another member took it or when it
// could not be renewed for the renew deadline.
func (m *Member) renew(ctx context.Context) {
	m.mu.Lock()
	l := m.lease
	m.mu.Unlock()
	sctx, cancel := context.WithTimeout(ctx, m.retry)
	defer cancel()
	ok, err := m.cfg.Store.Renew(sctx, l.Epoch)
	switch {
	case err == nil && ok:
		m.renewed = time.Now()
	case err == nil:
		m.log.Warn("stepping down: another member took the lease", "epoch", l.Epoch)
		m.stepDown(false)
	case time.Since(m.renewed) >= m.deadline:
		m.log.Warn("stepping down: the lease could not be renewed", "epoch", l.Epoch, "since", time.Since(m.renewed).Round(time.Millisecond), "err", err)
		m.stepDown(false)
	default:
		m.log.Debug("renewing the lease", "epoch", l.Epoch, "err", err)
	}
}

// stepDown ends the lead of this member: it closes the controller and so the control streams,
// whose nodes go to the next leader, and with release it gives up the lease.
func (m *Member) stepDown(release bool) {
	m.mu.Lock()
	c, l := m.active, m.lease
	m.active, m.handler = nil, nil
	m.mu.Unlock()
	m.seen, m.seenSince = store.Lease{}, time.Time{}
	if c == nil {
		return
	}
	c.Close()
	if release {
		m.release(l.Epoch)
	}
	m.log.Info("stepped down", "epoch", l.Epoch)
}

func (m *Member) release(epoch int64) {
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	if err := m.cfg.Store.Release(ctx, epoch); err != nil {
		m.log.Warn("releasing the lease", "epoch", epoch, "err", err)
	}
}

// know records l, the lease as a standby read it, and points the forwarding of API calls at its
// holder.
func (m *Member) know(l store.Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != nil {
		return
	}
	m.lease = l
	if l.Holder == "" || l.Holder == m.cfg.Name || l.Address == "" {
		m.proxy, m.proxyFor = nil, store.Lease{}
		return
	}
	if m.proxy != nil && m.proxyFor.Epoch == l.Epoch && m.proxyFor.Address == l.Address && m.proxyFor.Fingerprint == l.Fingerprint {
		return
	}
	m.proxy, m.proxyFor = forwarder(l, m.cfg.Name), l
}

// forwarder returns the proxy that forwards API calls to the holder of l, marked as forwarded by
// the member self. The holder's certificate is self-signed, so instead of a certificate chain
// the proxy checks that its key is the one of the lease.
func forwarder(l store.Lease, self string) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "https", Host: l.Address}
	fingerprint, holder := l.Fingerprint, l.Holder
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Header.Set(forwardedHeader, self)
		},
		Transport: &http.Transport{
			IdleConnTimeout: time.Minute,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("the leader sent no certificate")
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
					if hex.EncodeToString(sum[:]) != fingerprint {
						return fmt.Errorf("the TLS key of %s is not the one in the lease of the leader %s", target.Host, holder)
					}
					return nil
				},
			},
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			api.Reply(w, http.StatusBadGateway, api.Problem{Error: fmt.Sprintf("forwarding to the leader %s: %v", holder, err)})
		},
	}
}
