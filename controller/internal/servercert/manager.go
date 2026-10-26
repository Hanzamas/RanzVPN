package servercert

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/acmecert"
)

const (
	// DefaultPoll is how often a member looks at the setting in the store, which the other members
	// change: a change reaches a member within it.
	DefaultPoll = 2 * time.Second
	// acmeTimeout bounds one run of the ACME client, as the one of a Node does.
	acmeTimeout = 150 * time.Second
	// acmeCheck is how often the controller asks the ACME client whether the certificate is due, and
	// acmeRetry how soon it asks again after a run that failed.
	acmeCheck = 12 * time.Hour
	acmeRetry = 10 * time.Minute
	// challengePrefix is the path of the ACME HTTP-01 challenges (RFC 8555 section 8.3).
	challengePrefix = "/.well-known/acme-challenge/"
)

// Store is what the Manager reads of the store of the Controller: the certificate setting and the
// TLS fingerprint it was set with. *store.Store is one.
type Store interface {
	ControllerCertificate(ctx context.Context) (setting, fingerprint string, ok bool, err error)
}

// Config is what a Manager runs with.
type Config struct {
	// Store holds the setting; nil for a Manager that has none.
	Store Store
	// SelfSigned is the self-signed certificate of the Controller, with its Leaf set, which it serves
	// while no setting is in force; Key is its key. An ACME certificate is made for the same key.
	SelfSigned tls.Certificate
	Key        crypto.Signer
	// Dir is the data directory of the Controller, where the state of ACME is kept.
	Dir string
	// Advertised is the -advertise address of the Controller, host:port as the Nodes reach it, empty
	// for none. Its host is a host that a certificate must name.
	Advertised string
	// Challenges tells that the plain HTTP port of the Controller answers the ACME challenges through
	// the Manager (KeyAuthorization), in place of a port that each run listens on itself.
	Challenges bool
	// Poll is how often the store is looked at, DefaultPoll when it is 0.
	Poll time.Duration
	// Now is the clock; time.Now when it is nil.
	Now func() time.Time
	// Log is discarded when it is nil.
	Log *slog.Logger
}

// Manager holds the certificate that the TLS port of the Controller serves, and changes it.
type Manager struct {
	cfg  Config
	log  *slog.Logger
	self *Loaded

	// cur is the certificate that GetCertificate gives to each new handshake. It changes under mu.
	cur atomic.Pointer[Loaded]

	// mu guards what follows.
	mu sync.Mutex
	// epoch grows with every Adopt, so that a look at the store that began before it is dropped.
	epoch uint64
	// applied is the setting that cur was made of, "" while cur is the self-signed certificate.
	applied string
	// stored is the TLS fingerprint that the store holds for the setting, "" when it holds none.
	stored string
	// failure is the error of the last look at the store that failed, so that the log says it once.
	failure string
	// answers are the ACME challenges that are open: the token and its key authorization.
	answers map[string]string
	// nextACME is when the ACME client is asked next.
	nextACME time.Time

	cancel context.CancelFunc
	done   chan struct{}
}

// New returns the Manager of cfg. It serves the self-signed certificate until Start or Adopt says
// otherwise.
func New(cfg Config) *Manager {
	if cfg.Poll <= 0 {
		cfg.Poll = DefaultPoll
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := &Manager{cfg: cfg, log: log, self: selfSigned(cfg.SelfSigned), answers: map[string]string{}}
	m.cur.Store(m.self)
	return m
}

// Start reads the setting once and serves its certificate when it works, then looks at the store
// every Poll until Close, for a setting that another member changed and for an ACME certificate
// that is due. A setting that does not work leaves the Controller on the certificate it has, the
// self-signed one at the start, and the log says why.
func (m *Manager) Start(ctx context.Context) {
	if err := m.Refresh(ctx); err != nil {
		m.report(err)
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.done = make(chan struct{})
	go m.loop(ctx)
}

// Close stops what Start started.
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
}

func (m *Manager) loop(ctx context.Context) {
	defer close(m.done)
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(ctx); err != nil {
				m.report(err)
			} else {
				m.recovered()
			}
			m.renew(ctx)
		}
	}
}

// report logs the error of a look at the store, once until it changes.
func (m *Manager) report(err error) {
	m.mu.Lock()
	same := m.failure == err.Error()
	m.failure = err.Error()
	m.mu.Unlock()
	if !same {
		m.log.Warn("the certificate setting cannot be used, so the controller keeps the certificate it serves", "err", err)
	}
}

// recovered logs that the setting works again after report.
func (m *Manager) recovered() {
	m.mu.Lock()
	was := m.failure
	m.failure = ""
	m.mu.Unlock()
	if was != "" {
		m.log.Info("the certificate setting works again")
	}
}

// GetCertificate is the GetCertificate of the tls.Config of the TLS port: each new handshake gets
// the certificate that is current, and a connection that is up keeps the one it has.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &m.cur.Load().Cert, nil
}

// Info describes the certificate that is served now.
func (m *Manager) Info() Info {
	return m.cur.Load().Info
}

// Fingerprint returns the TLS fingerprint of the certificate that is served now.
func (m *Manager) Fingerprint() string {
	return m.cur.Load().Info.Fingerprint
}

// Fingerprints returns the TLS fingerprints that the Nodes may accept: the one of the certificate
// that is served, and the one that the store holds for the setting when it is another, which is
// what a setting that cannot be read at the moment would serve. It is empty while no setting is set:
// the Nodes have the fingerprint of the self-signed certificate from `ranz status`.
func (m *Manager) Fingerprints() []string {
	m.mu.Lock()
	stored := m.stored
	m.mu.Unlock()
	if stored == "" {
		return nil
	}
	served := m.Fingerprint()
	if served == stored {
		return []string{served}
	}
	return []string{served, stored}
}

// SelfSigned returns the self-signed certificate of the Controller as a Loaded, for a Controller
// that clears its setting.
func (m *Manager) SelfSigned() *Loaded {
	return m.self
}

// Adopt makes l the certificate that the next handshake gets. The caller has stored its setting
// first (or removed it, for the self-signed certificate), so a member that looks at the store finds
// what it serves.
func (m *Manager) Adopt(l *Loaded) {
	setting, stored := "", ""
	if l.Setting != nil {
		setting, stored = l.Setting.Encode(), l.Info.Fingerprint
	}
	m.mu.Lock()
	m.epoch++
	m.stored = stored
	m.adoptLocked(l, setting)
	m.mu.Unlock()
	m.logServed(l)
}

// adoptLocked serves l, which the setting (the JSON that the store holds, "" for none) gave. m.mu is
// held.
func (m *Manager) adoptLocked(l *Loaded, setting string) {
	m.applied = setting
	m.cur.Store(l)
}

// logServed says which certificate is served now.
func (m *Manager) logServed(l *Loaded) {
	m.log.Info("TLS certificate", "source", l.Info.Source, "subject", l.Info.Subject, "names", strings.Join(l.Info.Names, ","),
		"thumbprint", l.Info.Thumbprint, "tlsFingerprint", l.Info.Fingerprint, "notAfter", l.Info.NotAfter.Format(time.RFC3339))
}

// Refresh looks at the store: the certificate of a setting that is not the one in use is loaded and
// served, and with no setting the self-signed certificate is served. A setting that does not load
// leaves the certificate in use, and the error says why.
func (m *Manager) Refresh(ctx context.Context) error {
	if m.cfg.Store == nil {
		return nil
	}
	m.mu.Lock()
	epoch := m.epoch
	m.mu.Unlock()
	setting, fingerprint, ok, err := m.cfg.Store.ControllerCertificate(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.epoch != epoch {
		// A certificate was adopted while the store was read: what it held may be what was before
		m.mu.Unlock()
		return nil
	}
	m.stored = ""
	if ok {
		m.stored = fingerprint
	}
	applied := m.applied
	if !ok && applied != "" {
		m.adoptLocked(m.self, "")
	}
	m.mu.Unlock()
	if !ok {
		if applied != "" {
			m.logServed(m.self)
		}
		return nil
	}
	if setting == applied {
		return nil
	}
	s, err := ParseSetting([]byte(setting))
	if err != nil {
		return fmt.Errorf("the stored certificate setting: %w", err)
	}
	l, err := m.Load(ctx, s)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.epoch != epoch {
		m.mu.Unlock()
		return nil
	}
	m.adoptLocked(l, setting)
	m.mu.Unlock()
	m.logServed(l)
	return nil
}

// Load makes the certificate that the setting s names ready to be served, and checks it: it is
// refused, with the reason, when it does not load, does not belong to its key, is not valid now, is
// no certificate of a server, has a key that the TLS of the Nodes does not take, or does not name
// each host that the Nodes use. Nothing in use changes: Adopt serves it. For an ACME source Load runs
// the client, which keeps the certificate that it has while that is not due.
func (m *Manager) Load(ctx context.Context, s Setting) (*Loaded, error) {
	s, err := s.normalize()
	if err != nil {
		return nil, err
	}
	hosts, err := m.hosts(s)
	if err != nil {
		return nil, err
	}
	var cert tls.Certificate
	var source string
	switch {
	case s.File != nil:
		source = SourceFile
		cert, err = loadFile(*s.File)
	case s.KSP != "":
		source = SourceKSP
		cert, err = loadKSP(s.KSP)
	default:
		source = SourceACME
		cert, err = m.loadACME(ctx, *s.ACME)
	}
	if err != nil {
		return nil, err
	}
	if err := check(cert, hosts, m.cfg.Now()); err != nil {
		return nil, err
	}
	return &Loaded{Cert: cert, Info: describe(cert, source, &s), Setting: &s}, nil
}

// hosts returns the hosts that the certificate of s must name: the ones of s, which are the names
// of an ACME source when it has none, and the host of -advertise.
func (m *Manager) hosts(s Setting) ([]string, error) {
	hosts := slices.Clone(s.Hosts)
	if len(hosts) == 0 && s.ACME != nil {
		hosts = slices.Clone(s.ACME.Names)
	}
	if h, _, err := net.SplitHostPort(m.cfg.Advertised); err == nil {
		if n, ok := normalizeHost(h); ok && !slices.Contains(hosts, n) {
			hosts = append(hosts, n)
		}
	}
	if len(hosts) == 0 {
		return nil, refuse("the setting names no host: give the host that the Nodes use to reach the Controller, so that the certificate can be checked against it")
	}
	return hosts, nil
}

// loadACME gets the certificate of a that the ACME client keeps or issues. It is made for the TLS
// key of the Controller, so its TLS fingerprint is the one that the Nodes pinned.
func (m *Manager) loadACME(ctx context.Context, a ACME) (tls.Certificate, error) {
	if m.cfg.Dir == "" || m.cfg.Key == nil {
		return tls.Certificate{}, refuse("this controller has no data directory or no TLS key to keep an ACME certificate with")
	}
	dir := filepath.Join(m.cfg.Dir, "acme")
	st := &chainStore{dir: dir, key: m.cfg.Key}
	o := acmecert.Options{
		Directory: a.Directory,
		Names:     a.Names,
		Email:     a.Email,
		CAFile:    a.CAFile,
		HTTPPort:  int(a.HTTPPort),
		RenewDays: int(a.RenewDays),
		State:     filepath.Join(dir, "state"),
	}
	if m.cfg.Challenges {
		o.Responder = m
	}
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	res, err := acmecert.Run(ctx, o, st, m.cfg.Now())
	if err != nil {
		return tls.Certificate{}, refuse("the ACME service at %s gave no certificate: %v", a.Directory, err)
	}
	c, err := st.load(res.Thumbprint)
	if err != nil {
		return tls.Certificate{}, refuse("the certificate that the ACME service gave cannot be read: %v", err)
	}
	return c, nil
}

// renew asks the ACME client whether the certificate in use is due, when it comes from ACME and the
// time to ask has come; a new certificate takes the place of the old one for the next handshake. It
// is made for the key of the Controller too, so the TLS fingerprint stays.
func (m *Manager) renew(ctx context.Context) {
	cur := m.cur.Load()
	if cur.Info.Source != SourceACME || cur.Setting == nil {
		return
	}
	now := m.cfg.Now()
	m.mu.Lock()
	due := !now.Before(m.nextACME)
	m.mu.Unlock()
	if !due {
		return
	}
	wait := acmeCheck
	next, err := m.Load(ctx, *cur.Setting)
	if err != nil {
		m.log.Warn("the ACME certificate cannot be renewed", "err", err)
		wait = acmeRetry
	} else if next.Info.Thumbprint != cur.Info.Thumbprint {
		m.mu.Lock()
		swapped := m.cur.Load() == cur
		if swapped {
			m.adoptLocked(next, m.applied)
		}
		m.mu.Unlock()
		if swapped {
			m.log.Info("the ACME certificate was renewed")
			m.logServed(next)
		}
	}
	m.mu.Lock()
	m.nextACME = now.Add(wait)
	m.mu.Unlock()
}

// Put makes body the answer to the ACME challenge at path, for the plain HTTP port of the
// Controller (acmecert.Responder).
func (m *Manager) Put(path, body string) {
	token, ok := strings.CutPrefix(path, challengePrefix)
	if !ok {
		return
	}
	m.mu.Lock()
	m.answers[token] = body
	m.mu.Unlock()
}

// KeyAuthorization returns the answer to the ACME challenge of the token, for the plain HTTP port
// (port.Challenges).
func (m *Manager) KeyAuthorization(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.answers[token]
	return body, ok
}

// ErrNoManager is what a Controller without a Manager answers to a call for the certificate.
var ErrNoManager = errors.New("this controller serves one fixed certificate")
