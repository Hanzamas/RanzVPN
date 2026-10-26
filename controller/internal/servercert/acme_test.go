package servercert

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
)

// The ACME source (SDN-92, #397) against Pebble, the test ACME service of Let's Encrypt, as the ACME source of the
// Listener of a node is tested (SDN-45, #238): the step "Controller certificate with ACME" of windows.yml starts Pebble
// at a pinned version (.github/scripts/controller-acme.ps1) and names it in the environment. Without Pebble the test
// is skipped, and the step fails when it was.
const (
	pebbleDirectory  = "RANZ_PEBBLE_DIRECTORY"      // the URL of its ACME directory
	pebbleRoots      = "RANZ_PEBBLE_ROOTS"          // the PEM file with the certificate of its test CA, which signs its own TLS certificate
	pebbleManagement = "RANZ_PEBBLE_MANAGEMENT"     // the URL of its management interface, which gives the root of the certificates it issues
	pebblePort       = "RANZ_PEBBLE_CHALLENGE_PORT" // the TCP port where it validates an HTTP-01 challenge
)

// handshakeOf makes the TLS server of m, which serves the certificate that m has now, and a client that trusts roots
// and asks for host, shake hands, and returns what the client says.
func handshakeOf(m *Manager, roots *x509.CertPool, host string) error {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Server(c1, &tls.Config{GetCertificate: m.GetCertificate}).Handshake() }()
	return tls.Client(c2, &tls.Config{RootCAs: roots, ServerName: host}).Handshake()
}

// pebbleRoot returns a pool with the root of the certificates that Pebble issues, which its management interface gives.
func pebbleRoot(t *testing.T, management, minica string) *x509.CertPool {
	t.Helper()
	b, err := os.ReadFile(minica)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(b) {
		t.Fatalf("%s holds no PEM certificate", minica)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust}}}
	resp, err := hc.Get(management + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	root, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the root of the certificates of Pebble: %s, %v", resp.Status, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatalf("the root of the certificates of Pebble is no PEM certificate: %s", root)
	}
	return pool
}

// acmeManager returns a Manager of the key key that keeps its ACME certificates in dir, whose clock runs ahead of the
// real one by skew nanoseconds. With plain it answers the challenges through the plain HTTP port of the Controller.
func acmeManager(t *testing.T, dir string, key crypto.Signer, plain bool, skew *atomic.Int64) *Manager {
	t.Helper()
	self, err := keys.SelfSigned(key)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{SelfSigned: self, Key: key, Dir: dir, Challenges: plain, Now: func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }})
}

// The Controller serves a certificate that an ACME service issued, for its own key, so that the TLS fingerprint that the
// Nodes pinned stays: the chain that the service gave is served and a client that trusts the root of the service takes
// it, a restart keeps the certificate in place of asking again, a certificate that is due is renewed, and a name that
// the service refuses is refused with the reason while the certificate in use stays. Both ways of answering the
// challenge are run: through the plain HTTP port of the Controller, and through a port that the run listens on.
func TestServesACertificateOfAnACMEService(t *testing.T) {
	directory := os.Getenv(pebbleDirectory)
	if directory == "" {
		t.Skipf("%s is not set: the step Controller certificate with ACME of windows.yml starts Pebble and sets it", pebbleDirectory)
	}
	roots, management := os.Getenv(pebbleRoots), os.Getenv(pebbleManagement)
	challengePort, err := strconv.Atoi(os.Getenv(pebblePort))
	if roots == "" || management == "" || err != nil {
		t.Fatalf("%s goes with %s, %s and %s, the TCP port of the challenge", pebbleDirectory, pebbleRoots, pebbleManagement, pebblePort)
	}
	trusted := pebbleRoot(t, management, roots)

	for _, c := range []struct {
		name  string
		plain bool
	}{
		{"answered by the plain HTTP port of the Controller", true},
		{"answered by a port of its own", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			key := ecKey(t)
			dir := t.TempDir()
			var skew atomic.Int64
			m := acmeManager(t, dir, key, c.plain, &skew)
			if c.plain {
				ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(challengePort)))
				if err != nil {
					t.Fatal(err)
				}
				srv := &http.Server{Handler: port.Redirect("443", m), ReadHeaderTimeout: 10 * time.Second}
				go func() { _ = srv.Serve(ln) }()
				t.Cleanup(func() { _ = srv.Close() })
			}
			setting := Setting{ACME: &ACME{Directory: directory, Names: []string{"localhost"}, HTTPPort: uint16(challengePort), CAFile: roots}}

			// The service issues, and the Controller serves the chain for the key that it has
			own := m.Fingerprint()
			l, err := m.Load(ctx, setting)
			if err != nil {
				t.Fatal(err)
			}
			if l.Info.Source != SourceACME || l.Info.Fingerprint != own || !slices.Contains(l.Info.Names, "localhost") || len(l.Cert.Certificate) < 2 || l.Info.SelfSigned || l.Setting == nil {
				t.Fatalf("the certificate is %+v with %d certificates in its chain, want one of the service for the key with the fingerprint %s", l.Info, len(l.Cert.Certificate), own)
			}
			m.Adopt(l)
			if err := handshakeOf(m, trusted, "localhost"); err != nil {
				t.Errorf("a client that trusts the root of the service: %v", err)
			}
			if err := handshakeOf(m, x509.NewCertPool(), "localhost"); err == nil {
				t.Errorf("a client that trusts no root took the certificate of the service")
			}

			// It is not due: asking again gives the same certificate, and so does a restart
			first := m.Info()
			m.renew(ctx)
			if got := m.Info(); got.Thumbprint != first.Thumbprint {
				t.Errorf("a look at a certificate that is not due changed it: %s, was %s", got.Thumbprint, first.Thumbprint)
			}
			restarted, err := acmeManager(t, dir, key, c.plain, &skew).Load(ctx, setting)
			if err != nil || restarted.Info.Thumbprint != first.Thumbprint {
				t.Errorf("after a restart: %+v, %v, want the certificate of before, %s", restarted.Info, err, first.Thumbprint)
			}

			// It is due ten days before its end: the service issues another, for the same key
			skew.Store(int64(time.Until(first.NotAfter) - 10*24*time.Hour))
			m.mu.Lock()
			m.nextACME = time.Time{}
			m.mu.Unlock()
			m.renew(ctx)
			renewed := m.Info()
			if renewed.Thumbprint == first.Thumbprint || renewed.Fingerprint != own || renewed.Source != SourceACME {
				t.Fatalf("the renewed certificate is %+v, want another certificate than %s for the key with the fingerprint %s", renewed, first.Thumbprint, own)
			}
			if err := handshakeOf(m, trusted, "localhost"); err != nil {
				t.Errorf("a client that trusts the root of the service takes the renewed certificate: %v", err)
			}
			if files, err := filepath.Glob(filepath.Join(dir, "acme", "*.pem")); err != nil || len(files) != 1 || filepath.Base(files[0]) != renewed.Thumbprint+".pem" {
				t.Errorf("the chains that are kept are %v (%v), want the one of the renewed certificate alone", files, err)
			}

			// A name that the service does not issue for is refused with the reason, and the certificate in use stays
			_, err = m.Load(ctx, Setting{ACME: &ACME{Directory: directory, Names: []string{"blocked-domain.example"}, HTTPPort: uint16(challengePort), CAFile: roots}})
			refusedWith(t, "a name that the service refuses", err, "gave no certificate")
			if got := m.Info(); got.Thumbprint != renewed.Thumbprint {
				t.Errorf("a refused name changed the certificate to %s, want %s", got.Thumbprint, renewed.Thumbprint)
			}
		})
	}
}
