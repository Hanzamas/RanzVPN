// Package acmecert is the ACME sidecar of the Listener of a node (SDN-45, #238): ranz acme, which the
// node runs (src/Cedar/NodeListener.c) to get the certificate of its Listener from an ACME service
// (RFC 8555) with the HTTP-01 challenge, and to renew it RenewDays before its end. The package
// acme of golang.org/x/crypto speaks the protocol. The certificate goes into the My store of
// Windows and its key into the Microsoft Software Key Storage Provider (WindowsStore), where the
// TLS and the QUIC of the node find it by its thumbprint. A new certificate takes the place of the
// one before, which goes from the store with its key.
//
// The state of a Listener is a directory of its own: the key of its ACME account, made at the first
// run, and the certificate that it has (state.json). A run keeps that certificate while the store
// holds it with its key, it names the same DNS names and it ends more than RenewDays from now;
// otherwise the run gets a new one.
package acmecert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
)

// The files of the state directory of a Listener
const (
	stateFile   = "state.json"  // the certificate that the Listener has
	accountFile = "account.key" // the key of its ACME account, ECDSA P-256 in PKCS #8 PEM
)

// Options is what one run does.
type Options struct {
	// Directory is the URL of the ACME directory.
	Directory string
	// Names are the DNS names of the certificate.
	Names []string
	// Email is the contact of the account, empty for none.
	Email string
	// CAFile is a PEM file with the roots of a private ACME service, empty for the roots of the
	// system.
	CAFile string
	// HTTPPort is the TCP port that answers the HTTP-01 challenge.
	HTTPPort int
	// RenewDays is how many days before its end the certificate is renewed.
	RenewDays int
	// State is the state directory of the Listener.
	State string
	// Responder, when it is set, is where the HTTP-01 challenges are answered: a port that is
	// listening already, as the plain HTTP port of the Controller (SDN-92, #397). Without one a run
	// listens on HTTPPort itself while the service validates.
	Responder Responder
}

// Responder answers the HTTP-01 challenges of a run: Put makes body the answer to a GET of path, the
// path of the challenge, for as long as the run needs it.
type Responder interface {
	Put(path, body string)
}

// Store is where a certificate and its key go.
type Store interface {
	// NewKey makes the key name and returns it.
	NewKey(name string) (crypto.Signer, error)
	// Install puts the certificate der into the store, linked to the key name, so that the node
	// finds the certificate with its key by its thumbprint.
	Install(der []byte, name string) error
	// Has reports whether the store holds the certificate of the thumbprint with its key.
	Has(thumbprint string) bool
	// Remove takes the certificate of the thumbprint and the key name away; an empty one is left.
	Remove(thumbprint, name string)
}

// ChainStore is a Store that serves the certificate with the ones that lead to its root, as the
// Controller does (SDN-92, #397): it gets the whole chain that the service gave, the certificate
// itself first, in place of the call of Install.
type ChainStore interface {
	Store
	// InstallChain puts the chain, DER certificates, into the store, linked to the key name.
	InstallChain(chain [][]byte, name string) error
}

// Result is what a run gave: the certificate by its thumbprint, the upper-case hex of its SHA-1, its
// end, and whether the run got it new.
type Result struct {
	Thumbprint string
	NotAfter   time.Time
	Renewed    bool
}

// state is the certificate that a Listener has: its thumbprint, the name of its key, its end and
// its DNS names.
type state struct {
	Thumbprint string    `json:"thumbprint"`
	Key        string    `json:"key"`
	NotAfter   time.Time `json:"notAfter"`
	Names      []string  `json:"names"`
}

// issuer gets a new certificate into the store, and returns the state that holds it.
type issuer func(ctx context.Context, o Options, st Store, now time.Time) (state, error)

// Run gets the certificate of o.Names from the ACME service of o.Directory into st, or keeps the
// one that the state directory names while it is due no renewal at now.
func Run(ctx context.Context, o Options, st Store, now time.Time) (Result, error) {
	return run(ctx, o, st, now, issue)
}

func run(ctx context.Context, o Options, st Store, now time.Time, get issuer) (Result, error) {
	if err := o.check(); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(o.State, 0o700); err != nil {
		return Result{}, fmt.Errorf("acme: the state directory: %w", err)
	}
	// A state that cannot be read is no certificate: the run gets one
	old, _ := loadState(o.State)
	due := old.NotAfter.Sub(now) <= time.Duration(o.RenewDays)*24*time.Hour
	if old.Thumbprint != "" && !due && slices.Equal(old.Names, o.Names) && st.Has(old.Thumbprint) {
		return Result{Thumbprint: old.Thumbprint, NotAfter: old.NotAfter}, nil
	}
	next, err := get(ctx, o, st, now)
	if err != nil {
		return Result{}, err
	}
	if err := saveState(o.State, next); err != nil {
		st.Remove(next.Thumbprint, next.Key)
		return Result{}, err
	}
	// The certificate before goes with its key, now that the state names the new one
	if old.Thumbprint != "" && old.Thumbprint != next.Thumbprint {
		st.Remove(old.Thumbprint, old.Key)
	}
	return Result{Thumbprint: next.Thumbprint, NotAfter: next.NotAfter, Renewed: true}, nil
}

// check refuses options that a run cannot take.
func (o Options) check() error {
	switch {
	case o.Directory == "":
		return errors.New("acme: no directory")
	case len(o.Names) == 0:
		return errors.New("acme: no DNS names")
	case o.Responder == nil && (o.HTTPPort < 1 || o.HTTPPort > 65535):
		return fmt.Errorf("acme: the HTTP-01 port %d is not from 1 to 65535", o.HTTPPort)
	case o.RenewDays < 0:
		return fmt.Errorf("acme: renew-days %d is below 0", o.RenewDays)
	case o.State == "":
		return errors.New("acme: no state directory")
	}
	return nil
}

// loadState returns the state of the state directory dir.
func loadState(dir string) (state, error) {
	var s state
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return state{}, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return state{}, fmt.Errorf("acme: %s: %w", stateFile, err)
	}
	return s, nil
}

// saveState writes the state s into the state directory dir, in place of the one before.
func saveState(dir string, s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("acme: the state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, stateFile)); err != nil {
		return fmt.Errorf("acme: the state: %w", err)
	}
	return nil
}

// accountKey returns the key of the ACME account in the file path, which the first run makes and
// only its owner reads.
func accountKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, fmt.Errorf("acme: the account key: %w", err)
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("acme: the account key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("acme: %s holds no PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: %s: %w", path, err)
	}
	signer, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("acme: %s is not an ECDSA key", path)
	}
	return signer, nil
}

// client returns the ACME client of the account of the Listener, which trusts the roots of
// o.CAFile for a private service.
func client(o Options) (*acme.Client, error) {
	key, err := accountKey(filepath.Join(o.State, accountFile))
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: o.Directory, UserAgent: "ranz-acme"}
	if o.CAFile != "" {
		b, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("acme: the roots of the service: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("acme: %s holds no PEM certificate", o.CAFile)
		}
		c.HTTPClient = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	return c, nil
}

// issue gets a new certificate of o.Names: the account, the order, the HTTP-01 challenge of each of
// its authorizations, and the certificate of a new key of the store, which goes into the store.
func issue(ctx context.Context, o Options, st Store, now time.Time) (state, error) {
	c, err := client(o)
	if err != nil {
		return state{}, err
	}
	account := &acme.Account{}
	if o.Email != "" {
		account.Contact = []string{"mailto:" + o.Email}
	}
	if _, err := c.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return state{}, fmt.Errorf("acme: the account: %w", err)
	}
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(o.Names...))
	if err != nil {
		return state{}, fmt.Errorf("acme: the order: %w", err)
	}
	resp := o.Responder
	if resp == nil {
		l, err := listenChallenges(o.HTTPPort)
		if err != nil {
			return state{}, err
		}
		defer l.Close()
		resp = l
	}
	if err := authorize(ctx, c, order, resp); err != nil {
		return state{}, err
	}
	// The URL of the order comes with its creation: a service may leave it out of later answers (Pebble does), and
	// the finalization waits on it while the service issues
	uri := order.URI
	if order, err = c.WaitOrder(ctx, uri); err != nil {
		return state{}, fmt.Errorf("acme: the order: %w", err)
	}
	order.URI = uri

	// A new key for each certificate: the key of the certificate before goes with it
	name := fmt.Sprintf("Ranz ACME %s %d", o.Names[0], now.UnixNano())
	key, err := st.NewKey(name)
	if err != nil {
		return state{}, err
	}
	s, err := finalize(ctx, c, order, key, name, o.Names, st)
	if err != nil {
		st.Remove("", name)
		return state{}, err
	}
	return s, nil
}

// finalize asks for the certificate of the order with a request that key signs, and installs it in
// the store linked to the key name.
func finalize(ctx context.Context, c *acme.Client, order *acme.Order, key crypto.Signer, name string, names []string, st Store) (state, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	if err != nil {
		return state{}, fmt.Errorf("acme: the certificate request: %w", err)
	}
	chain, _, err := c.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return state{}, fmt.Errorf("acme: the certificate: %w", err)
	}
	if len(chain) == 0 {
		return state{}, errors.New("acme: the service gave no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return state{}, fmt.Errorf("acme: the certificate: %w", err)
	}
	// The Controller serves the chain, a Node only the certificate that its store links to the key
	if cs, ok := st.(ChainStore); ok {
		err = cs.InstallChain(chain, name)
	} else {
		err = st.Install(chain[0], name)
	}
	if err != nil {
		return state{}, err
	}
	return state{Thumbprint: certgen.Thumbprint(chain[0]), Key: name, NotAfter: leaf.NotAfter, Names: slices.Clone(names)}, nil
}

// challengeListener answers the HTTP-01 challenges of a run that has no Responder: an HTTP server on a
// TCP port of this host, for as long as the run is.
type challengeListener struct {
	mu      sync.Mutex
	answers map[string]string
	srv     *http.Server
}

// listenChallenges starts the server on the TCP port.
func listenChallenges(port int) (*challengeListener, error) {
	l := &challengeListener{answers: map[string]string{}}
	l.srv = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		body, ok := l.answers[r.URL.Path]
		l.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})}
	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("acme: the HTTP-01 challenge cannot listen on TCP port %d: %w", port, err)
	}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

// Put makes body the answer to a GET of path.
func (l *challengeListener) Put(path, body string) {
	l.mu.Lock()
	l.answers[path] = body
	l.mu.Unlock()
}

// Close stops the server.
func (l *challengeListener) Close() {
	_ = l.srv.Close()
}

// authorize answers the HTTP-01 challenge of each authorization of the order that is not valid yet,
// through resp, until the service validated it.
func authorize(ctx context.Context, c *acme.Client, order *acme.Order, resp Responder) error {
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("acme: the authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == "http-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("acme: the authorization of %s offers no HTTP-01 challenge", z.Identifier.Value)
		}
		body, err := c.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return fmt.Errorf("acme: the challenge of %s: %w", z.Identifier.Value, err)
		}
		resp.Put(c.HTTP01ChallengePath(chal.Token), body)
		if _, err := c.Accept(ctx, chal); err != nil {
			return fmt.Errorf("acme: the challenge of %s: %w", z.Identifier.Value, err)
		}
		if _, err := c.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("acme: the authorization of %s: %w", z.Identifier.Value, err)
		}
	}
	return nil
}
