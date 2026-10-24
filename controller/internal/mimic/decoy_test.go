package mimic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The own decoy (ADR-0023, decoy mode 1): a site that the sidecar runs, with a landing page and a
// certificate. A connection that is no Ranz client is spliced to it, so the prober sees an ordinary
// site. The certificate comes from ACME (acme_test.go), from files, or is self-signed in tests.

// proberClient is the HTTP client of a prober: it asks the sidecar at addr for the site testName, takes
// any certificate and opens a connection for each request.
func proberClient(addr string) *http.Client {
	return &http.Client{
		Timeout: testTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{ServerName: testName, InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
}

// fetch makes a request and returns the answer with its body and the certificate of the site.
func fetch(t *testing.T, c *http.Client, method, path string) (*http.Response, string, *x509.Certificate) {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+testName+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := readAll(resp)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp, body, resp.TLS.PeerCertificates[0]
}

func readAll(resp *http.Response) (string, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(resp.Body)
	return b.String(), err
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A prober that reaches the own decoy sees a landing page, a 404 for the rest and the certificate of the
// name; the decoy never answers like the sidecar, and the key of the server is nowhere in it. The
// client that proves the key gets its stream through the same listener.
func TestOwnDecoyServesItsLandingPage(t *testing.T) {
	private, public := keyPair(t)
	s := ownSettings(private)
	s.Decoy.Page = "<h1>Landing page of the decoy</h1>"
	// The library probes the decoy before the first client, as it does outside a test
	srv, data := runServer(t, s, Options{})
	if !strings.HasPrefix(srv.ready.Decoy, "127.0.0.1:") {
		t.Errorf("the decoy listens on %q, want a loopback address", srv.ready.Decoy)
	}
	addr := srv.ready.Listen
	c := proberClient(addr)

	resp, body, cert := fetch(t, c, http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK || body != s.Decoy.Page {
		t.Errorf("the landing page is %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("the content type is %q", got)
	}
	if err := cert.VerifyHostname(testName); err != nil {
		t.Errorf("the certificate of the decoy is not for the name: %v", err)
	}
	if cert.Subject.String() != cert.Issuer.String() || time.Until(cert.NotAfter) > 31*24*time.Hour {
		t.Errorf("the self-signed certificate of a test is %s issued by %s until %v", cert.Subject, cert.Issuer, cert.NotAfter)
	}

	if resp, body, _ = fetch(t, c, http.MethodGet, "/index.html"); resp.StatusCode != http.StatusOK || body != s.Decoy.Page {
		t.Errorf("/index.html is %d %q", resp.StatusCode, body)
	}
	if resp, _, _ = fetch(t, c, http.MethodGet, "/vpn"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/vpn is %d, want 404", resp.StatusCode)
	}
	if resp, _, _ = fetch(t, c, http.MethodPost, "/"); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("a POST is %d with Allow %q, want 405", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if resp, body, _ = fetch(t, c, http.MethodHead, "/"); resp.StatusCode != http.StatusOK || body != "" {
		t.Errorf("a HEAD is %d with a body of %q", resp.StatusCode, body)
	}
	waitFor(t, "five probes", func() bool { return srv.counters().Probes == 5 })

	_, _, spliced := fetch(t, c, http.MethodGet, "/")
	if cert.SerialNumber.Cmp(spliced.SerialNumber) != 0 {
		t.Error("the certificate of the decoy changed between two requests")
	}

	conn, binding, err := dialLink(pipeOf(t, srv, public, addr), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	noiseOver(t, conn, st.conn, binding)
}

// pipeOf starts a client sidecar for the server at addr and returns its data pipe.
func pipeOf(t *testing.T, _ *sidecarNode, public, addr string) string {
	t.Helper()
	_, pipe := runClient(t, Options{}, linkTo(addr, public))
	return pipe
}

// writePair writes the certificate and the private key of pair as PEM files in dir.
func writePair(t *testing.T, dir string, pair tls.Certificate, certFile, keyFile string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The certificate of the own decoy may be in files that the operator's ACME client renews: the decoy
// presents the pair, reads it again when a file changed, and keeps the pair it has when what it finds is
// no pair.
func TestOwnDecoyReadsItsCertificateFromFiles(t *testing.T) {
	old := fileCertCheck
	fileCertCheck = 20 * time.Millisecond
	t.Cleanup(func() { fileCertCheck = old })

	dir := t.TempDir()
	first, err := selfSignedCert(testName)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, dir, first, "decoy.pem", "decoy.key")

	private, _ := keyPair(t)
	s := ownSettings(private)
	s.Decoy.SelfSigned = false
	s.Decoy.CertFile, s.Decoy.KeyFile = filepath.Join(dir, "decoy.pem"), filepath.Join(dir, "decoy.key")
	s.Decoy.PageFile = filepath.Join(dir, "page.html")
	if err := os.WriteFile(s.Decoy.PageFile, []byte("<p>the page of a file</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, _ := runServer(t, s, Options{skipDetect: true})
	c := proberClient(srv.ready.Listen)

	_, body, cert := fetch(t, c, http.MethodGet, "/")
	if body != "<p>the page of a file</p>" || !bytes.Equal(cert.Raw, first.Certificate[0]) {
		t.Fatalf("the decoy serves %q with a certificate that is not the one of the file", body)
	}

	// The operator's ACME client renews the pair: both files change
	second, err := selfSignedCert(testName)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, dir, second, "decoy.pem", "decoy.key")
	later := time.Now().Add(time.Hour)
	for _, name := range []string{"decoy.pem", "decoy.key"} {
		if err := os.Chtimes(filepath.Join(dir, name), later, later); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the renewed certificate", func() bool {
		_, _, cert := fetch(t, c, http.MethodGet, "/")
		return bytes.Equal(cert.Raw, second.Certificate[0])
	})

	// A file that is no certificate is left alone: the pair the decoy has is better than none
	if err := os.WriteFile(filepath.Join(dir, "decoy.pem"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	evenLater := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "decoy.pem"), evenLater, evenLater); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		time.Sleep(50 * time.Millisecond)
		if _, _, cert := fetch(t, c, http.MethodGet, "/"); !bytes.Equal(cert.Raw, second.Certificate[0]) {
			t.Fatal("the decoy lost its certificate when a file turned bad")
		}
	}
}

// landing answers a request for the page with the page, the rest with a 404, and what is no read with a 405.
func TestLanding(t *testing.T) {
	h := landing(nil)
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/index.html", http.StatusOK},
		{http.MethodHead, "/", http.StatusOK},
		{http.MethodGet, "/other", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodPut, "/index.html", http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.status {
			t.Errorf("%s %s is %d, want %d", c.method, c.path, rec.Code, c.status)
		}
		if c.method == http.MethodGet && c.status == http.StatusOK && !strings.Contains(rec.Body.String(), "<title>Welcome</title>") {
			t.Errorf("the default page is %q", rec.Body.String())
		}
	}
}

func TestSelfSignedCertificate(t *testing.T) {
	pair, err := selfSignedCert("decoy.example")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("decoy.example"); err != nil {
		t.Error(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("the certificate has the key usages %v and the key algorithm %v", cert.ExtKeyUsage, cert.PublicKeyAlgorithm)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Errorf("the certificate is valid from %v to %v", cert.NotBefore, cert.NotAfter)
	}
	// Two certificates are two: the serial numbers differ
	other, err := selfSignedCert("decoy.example")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.Certificate[0], pair.Certificate[0]) {
		t.Error("two self-signed certificates are the same")
	}
}
