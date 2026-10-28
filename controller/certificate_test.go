package controllercmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The certificate of the controller (SDN-92, #397) through ranz controller itself, run in this process: the
// first start serves a self-signed certificate that stays the same across restarts, an operator sets another
// from files, the status and the TLS port follow it, the setting is in the store and is served again after a
// restart, and clearing it gives back the first certificate.

// servedController is a ranz controller that run serves in this process.
type servedController struct {
	t    *testing.T
	tls  string
	api  *api.Client
	done chan error
	stop context.CancelFunc
	logs *bytes.Buffer
}

// runServing starts ranz controller on the data directory dir and the ports of addrs (the TLS port, the
// plain API port, the HTTP API and the Raft port of rqlite), and waits until it serves.
func runServing(t *testing.T, dir string, addrs []string, rqlited []string) *servedController {
	t.Helper()
	cfg, err := parseFlags(append([]string{
		"-data", dir, "-listen", addrs[0], "-api-listen", addrs[1], "-name", "c1",
		"-rqlite", "http://" + addrs[2], "-rqlite-raft", addrs[3],
	}, rqlited...))
	if err != nil {
		t.Fatal(err)
	}
	s := &servedController{t: t, tls: addrs[0], done: make(chan error, 1), logs: &bytes.Buffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	ready := make(chan struct{})
	var rqliteOut bytes.Buffer
	go func() {
		s.done <- run(ctx, cfg, slog.New(slog.NewTextHandler(s.logs, nil)), &rqliteOut, hooks{ready: func() { close(ready) }})
	}()
	select {
	case <-ready:
	case err := <-s.done:
		t.Fatalf("the controller ended before it served: %v\n%s%s", err, s.logs.String(), rqliteOut.String())
	case <-time.After(clusterTimeout):
		cancel()
		<-s.done
		t.Fatalf("the controller did not serve within %v\n%s%s", clusterTimeout, s.logs.String(), rqliteOut.String())
	}
	secret, err := os.ReadFile(filepath.Join(dir, adminTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	s.api = api.NewClient("https://" + addrs[0])
	s.api.Token = strings.TrimSpace(string(secret))
	t.Cleanup(func() { s.end() })
	return s
}

// end stops the controller, once, and returns how run ended.
func (s *servedController) end() error {
	if s.stop == nil {
		return nil
	}
	s.stop()
	s.stop = nil
	return <-s.done
}

// status returns the status that the controller answers.
func (s *servedController) status() api.Status {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := s.api.Status(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	return st
}

// served returns the TLS fingerprint of the certificate that a new connection to the port gets.
func (s *servedController) served() string {
	s.t.Helper()
	c, err := tls.Dial("tcp", s.tls, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close()
	sum := sha256.Sum256(c.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// The controller serves its self-signed certificate while no setting is set, with the same fingerprint at
// every start. A certificate that an operator sets is served by the TLS port and named by the status, the
// store keeps the setting across a restart, a client that trusts the CA of the certificate checks its chain
// for the host, one that trusts no CA is refused unless it pins the fingerprint, and clearing the setting
// gives back the first fingerprint. The file of the data directory that ranz on this host checks a
// loopback address by (AUD1-DT-13, #461) holds the fingerprint that is served at each of these points.
func TestRunServesTheCertificateOfItsSetting(t *testing.T) {
	rqlited := memberRqlited(t)
	addrs := freeAddrs(t, 4)
	dir := t.TempDir()
	ctx := context.Background()
	file := func(want string) {
		t.Helper()
		if got, err := servercert.ReadFingerprint(dir); err != nil || got != want {
			t.Errorf("the fingerprint file of the data directory holds %q, %v, want %q", got, err, want)
		}
	}

	// The self-signed certificate, which stays the same across a restart
	c := runServing(t, dir, addrs, rqlited)
	first := c.status().TLSFingerprint
	if first == "" || c.served() != first {
		t.Fatalf("the status names the fingerprint %q and a new connection gets %s", first, c.served())
	}
	file(first)
	if err := c.end(); err != nil {
		t.Errorf("the controller ended with %v", err)
	}
	c = runServing(t, dir, addrs, rqlited)
	if got := c.status().TLSFingerprint; got != first || c.served() != first {
		t.Fatalf("after a restart the status names %s and a new connection gets %s, want %s as before", got, c.served(), first)
	}
	file(first)
	info, err := c.api.ControllerCertificate(ctx)
	if err != nil || info.Source != servercert.SourceSelfSigned || info.Fingerprint != first {
		t.Fatalf("show with no setting: %+v, %v", info, err)
	}

	// A certificate that a CA signed, for localhost: set from files, served at once
	caKey, err := certgen.NewKey(0)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "Ranz test CA"}, CA: true}, caKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := certgen.NewAuthority(caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	key, err := certgen.NewKey(0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "localhost"}, Hosts: []string{"localhost", "127.0.0.1"}}, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certgen.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certDir := t.TempDir()
	certFile, keyFile := filepath.Join(certDir, "controller.pem"), filepath.Join(certDir, "controller.key")
	if err := os.WriteFile(certFile, certgen.EncodeCertificate(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	fp := hex.EncodeToString(sum[:])
	setting := servercert.Setting{Hosts: []string{"localhost", "127.0.0.1"}, File: &servercert.File{Certificate: certFile, Key: keyFile}}
	res, err := c.api.SetControllerCertificate(ctx, setting, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Fingerprint != fp || res.Certificate.Source != servercert.SourceFile {
		t.Errorf("the replacement is %+v, want the file with the fingerprint %s", res.Certificate, fp)
	}
	if got := c.status().TLSFingerprint; got != fp || c.served() != fp {
		t.Errorf("after the replacement the status names %s and a new connection gets %s, want %s", got, c.served(), fp)
	}
	file(fp)

	// A client with no fingerprint checks the chain: the CA that signed the certificate makes it good, any
	// other CA is refused; with the fingerprint a client takes it as it is, and the first fingerprint is refused
	url := "https://localhost:" + portOf(t, c.tls)
	trusting := func(roots *x509.CertPool) *api.Client {
		client := api.NewClient(url)
		client.Token = c.api.Token
		client.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
		return client
	}
	if st, err := trusting(caPool).Status(ctx); err != nil || st.TLSFingerprint != fp {
		t.Errorf("a client that trusts the CA of the certificate: %+v, %v", st, err)
	}
	otherCA, err := certgen.NewKey(0)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "Another CA"}, CA: true}, otherCA, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(other)
	if _, err := trusting(pool).Status(ctx); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("a client that trusts another CA: %v, want the certificate to be refused", err)
	}
	pinned := api.NewClient("https://" + c.tls)
	pinned.Token = c.api.Token
	if err := pinned.Pin(fp); err != nil {
		t.Fatal(err)
	}
	if st, err := pinned.Status(ctx); err != nil || st.TLSFingerprint != fp {
		t.Errorf("a client that pins the fingerprint: %+v, %v", st, err)
	}
	stale := api.NewClient("https://" + c.tls)
	stale.Token = c.api.Token
	if err := stale.Pin(first); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Status(ctx); err == nil || !strings.Contains(err.Error(), "TLS fingerprint") {
		t.Errorf("a client that pins the fingerprint of the old certificate: %v, want the fingerprint check to fail", err)
	}

	// The setting is in the store: a restart serves it again
	if err := c.end(); err != nil {
		t.Errorf("the controller ended with %v", err)
	}
	c = runServing(t, dir, addrs, rqlited)
	if got := c.status().TLSFingerprint; got != fp || c.served() != fp {
		t.Fatalf("after a restart the status names %s and a new connection gets %s, want %s of the setting", got, c.served(), fp)
	}
	file(fp)

	// A setting that does not work leaves the certificate in use: the key of a file that is gone
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	_, err = c.api.SetControllerCertificate(ctx, setting, false)
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest || !strings.Contains(refused.Message, "private key file cannot be read") {
		t.Errorf("a setting whose key file is gone: %v, want it refused with the reason", err)
	}
	if got := c.status().TLSFingerprint; got != fp {
		t.Errorf("a refused setting changed the certificate to %s, want %s", got, fp)
	}
	file(fp)

	// Clearing the setting gives back the self-signed certificate of the first start, also after a restart
	if res, err = c.api.ClearControllerCertificate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Fingerprint != first || c.status().TLSFingerprint != first || c.served() != first {
		t.Errorf("after clear the certificate is %+v, the status names %s and a new connection gets %s, want %s", res.Certificate, c.status().TLSFingerprint, c.served(), first)
	}
	file(first)
	if err := c.end(); err != nil {
		t.Errorf("the controller ended with %v", err)
	}
	c = runServing(t, dir, addrs, rqlited)
	if got := c.status().TLSFingerprint; got != first || c.served() != first {
		t.Errorf("after the last restart the status names %s and a new connection gets %s, want %s", got, c.served(), first)
	}
	file(first)
}

// portOf returns the port of the host:port address addr.
func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
