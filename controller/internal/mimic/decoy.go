package mimic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// The own decoy (ADR-0023, decoy mode 1): an HTTPS site that the server sidecar runs on a loopback
// address. The REALITY listener splices every connection that is no Ranz client to it, so a prober
// sees an ordinary site with a landing page and a certificate that a CA issued for its domain. It is
// the same page that the admin surface serves to clients outside the allowlist (ADR-0021).

// defaultPage is the landing page of a decoy without a page of its own.
const defaultPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>body{font-family:sans-serif;margin:3em auto;max-width:36em;padding:0 1em;color:#333}</style>
</head>
<body>
<h1>Welcome</h1>
<p>This site is being set up. Please come back soon.</p>
</body>
</html>
`

// fileCertCheck is how often the certificate files of the decoy are looked at for a change.
const fileCertCheck = 10 * time.Second

// decoy is a running own decoy.
type decoy struct {
	addr string // where it listens
	srv  *http.Server
	done chan struct{}
}

// startDecoy runs the own decoy that cfg describes.
func startDecoy(cfg decoyConfig, log *slog.Logger) (*decoy, error) {
	tlsCfg, err := decoyTLS(cfg, log)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return nil, fmt.Errorf("the decoy cannot listen on %s: %w", cfg.listen, err)
	}
	d := &decoy{
		addr: ln.Addr().String(),
		srv: &http.Server{
			Handler:           landing(cfg.page),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		},
		done: make(chan struct{}),
	}
	go func() {
		defer close(d.done)
		// ServeTLS returns http.ErrServerClosed once close ran
		if err := d.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the decoy site stopped", "err", err)
		}
	}()
	return d, nil
}

// close stops the decoy and its connections.
func (d *decoy) close() {
	d.srv.Close()
	<-d.done
}

// landing answers a request for the page with the page, and every other path with a 404.
func landing(page []byte) http.Handler {
	if len(page) == 0 {
		page = []byte(defaultPage)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(page)
	})
}

// decoyTLS is the TLS configuration of the decoy, with the certificate from the source that cfg
// names.
func decoyTLS(cfg decoyConfig, log *slog.Logger) (*tls.Config, error) {
	switch {
	case cfg.acme != nil:
		return acmeTLS(cfg.name, cfg.acme)
	case cfg.certFile != "":
		fc, err := newFileCert(cfg.certFile, cfg.keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{GetCertificate: fc.get}, nil
	}
	cert, err := selfSignedCert(cfg.name)
	if err != nil {
		return nil, err
	}
	log.Warn("the decoy has a self-signed certificate: a prober that checks the chain sees it", "name", cfg.name)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// acmeTLS gets the certificate of name from an ACME service, as the autocert package does, and keeps
// it renewed. The first handshake for the name starts the order; the TLS-ALPN-01 challenge reaches
// the decoy through the REALITY listener, which splices the connection of the ACME service to it.
func acmeTLS(name string, a *ACME) (*tls.Config, error) {
	client := &acme.Client{DirectoryURL: a.Directory}
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, fmt.Errorf("the ca_file of the ACME service: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the ca_file %s holds no certificate", a.CAFile)
		}
		client.HTTPClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		}
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(a.CacheDir),
		HostPolicy: autocert.HostWhitelist(name),
		Email:      a.Email,
		Client:     client,
	}
	return m.TLSConfig(), nil
}

// selfSignedCert makes the certificate of a decoy that is only a stand-in for a real one: a P-256
// key, valid for 30 days for name.
func selfSignedCert(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// fileCert is a certificate and key in files that an ACME client of the operator renews: the
// decoy presents the pair as it reads them, and reads them again when one of them changed.
type fileCert struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     *tls.Certificate
	certTime time.Time
	keyTime  time.Time
	checked  time.Time
}

func newFileCert(certFile, keyFile string) (*fileCert, error) {
	f := &fileCert{certFile: certFile, keyFile: keyFile}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

// load reads the pair; the caller holds the lock, or is the only one that has f.
func (f *fileCert) load() error {
	cert, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return fmt.Errorf("the certificate of the decoy: %w", err)
	}
	ci, err := os.Stat(f.certFile)
	if err != nil {
		return err
	}
	ki, err := os.Stat(f.keyFile)
	if err != nil {
		return err
	}
	f.cert, f.certTime, f.keyTime, f.checked = &cert, ci.ModTime(), ki.ModTime(), time.Now()
	return nil
}

// get is the GetCertificate of the decoy. A pair that cannot be read is left as it was: the
// certificate before it is better than none.
func (f *fileCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.checked) >= fileCertCheck {
		f.checked = time.Now()
		ci, cerr := os.Stat(f.certFile)
		ki, kerr := os.Stat(f.keyFile)
		if cerr == nil && kerr == nil && (!ci.ModTime().Equal(f.certTime) || !ki.ModTime().Equal(f.keyTime)) {
			f.load()
		}
	}
	return f.cert, nil
}
