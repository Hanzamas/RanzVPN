package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// startCertController runs a controller that serves the certificate of a servercert.Manager, as ranz controller
// does, with its API on a TLS test server. It returns the server, the tokens, the secret of the admin token and the
// TLS fingerprint of the self-signed certificate that the Manager serves first.
func startCertController(t *testing.T) (*httptest.Server, *rbac.Tokens, string, string) {
	t.Helper()
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	self, err := keys.SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	m := servercert.New(servercert.Config{Store: st, SelfSigned: self, Key: tlsKey, Dir: t.TempDir()})
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key, Certificates: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { admin = s; return nil }); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(api.Handler(c, tokens, api.Status{ControlAddress: "127.0.0.1:443"}))
	t.Cleanup(srv.Close)
	return srv, tokens, admin, m.Fingerprint()
}

// certFiles makes a certificate for host and writes it and its key as PEM files, as ranz cert does, in a new
// directory. It returns the two files and the TLS fingerprint of the certificate.
func certFiles(t *testing.T, host string) (certFile, keyFile, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: host}, Hosts: []string{host}}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certgen.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "controller.pem"), filepath.Join(dir, "controller.key")
	if err := os.WriteFile(certFile, certgen.EncodeCertificate(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, keys.Fingerprint(tls.Certificate{Leaf: leaf})
}

// TestControllerCertCommands runs the commands of the certificate of the controller (SDN-92, #397) against a
// controller: show prints the self-signed certificate with no key, set takes a certificate and its key from files and
// show prints it, a certificate that is refused comes back as the reason while the one in use stays, clear gives
// back the self-signed certificate, and a viewer may show and nothing else.
func TestControllerCertCommands(t *testing.T) {
	ctx := context.Background()
	srv, tokens, admin, first := startCertController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	run := func(args ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := do(ctx, cli, append([]string{"controller-cert"}, args...), &out); err != nil {
			t.Fatalf("ranz controller-cert %s: %v", strings.Join(args, " "), err)
		}
		return out.Bytes()
	}
	shown := func() servercert.Info {
		t.Helper()
		return userDecode[servercert.Info](t, run("show"))
	}
	noKey := func(what string, out []byte) {
		t.Helper()
		if bytes.Contains(out, []byte("PRIVATE KEY")) || bytes.Contains(bytes.ToUpper(out), []byte("BEGIN ")) {
			t.Errorf("%s printed key material or a PEM block:\n%s", what, out)
		}
	}

	// Nothing is set: the self-signed certificate of the controller
	out := run("show")
	noKey("show", out)
	if info := userDecode[servercert.Info](t, out); info.Source != servercert.SourceSelfSigned || info.Fingerprint != first || !info.SelfSigned || info.Setting != nil || info.Thumbprint == "" {
		t.Errorf("show with no setting printed %+v, want the self-signed certificate with the fingerprint %s", info, first)
	}

	// A certificate from files, for the host that the nodes use
	certFile, keyFile, fp := certFiles(t, "pc-a.example.com")
	out = run("set", "-host", "pc-a.example.com", "-cert", certFile, "-key", keyFile)
	noKey("set", out)
	changed := userDecode[controller.CertificateChange](t, out)
	// The certificate of the file is self-signed, as certFiles makes it
	if c := changed.Certificate; c.Source != servercert.SourceFile || c.Fingerprint != fp || !c.SelfSigned || c.Setting == nil || c.Setting.File == nil ||
		c.Setting.File.Certificate != certFile || !reflect.DeepEqual(c.Names, []string{"pc-a.example.com"}) {
		t.Errorf("set printed %+v, want the certificate of the file with the fingerprint %s", c, fp)
	}
	if len(changed.Pinned) != 0 || len(changed.Unpinned) != 0 {
		t.Errorf("set printed the nodes %v and %v, want none: no node is connected", changed.Pinned, changed.Unpinned)
	}
	out = run("show")
	noKey("show after set", out)
	if info := userDecode[servercert.Info](t, out); !reflect.DeepEqual(info, changed.Certificate) {
		t.Errorf("show printed %+v after set, want what set printed: %+v", info, changed.Certificate)
	}
	code, body := direct(t, srv, admin, http.MethodGet, "/api/v1/controller-certificate", "")
	if code != http.StatusOK || !reflect.DeepEqual(answer(t, run("show")), answer(t, body)) {
		t.Errorf("show printed something else than GET /api/v1/controller-certificate answered (%d): %s", code, body)
	}

	// A certificate that is refused: the reason comes back, the certificate in use stays
	otherCert, otherKey, _ := certFiles(t, "pc-a.example.com")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-host", "pc-a.example.com", "-cert", otherCert, "-key", keyFile}, "does not belong to the certificate"},
		{[]string{"-host", "pc-b.example.com", "-cert", otherCert, "-key", otherKey}, `does not name the host "pc-b.example.com"`},
		{[]string{"-cert", otherCert, "-key", otherKey}, "the setting names no host"},
		{[]string{"-host", "pc-a.example.com", "-cert", filepath.Join(filepath.Dir(otherCert), "gone.pem"), "-key", otherKey}, "the certificate file cannot be read"},
		{[]string{"-host", "pc-a.example.com", "-ksp", "0123456789ABCDEF0123456789ABCDEF01234567"}, ""},
	} {
		err := do(ctx, cli, append([]string{"controller-cert", "set"}, c.args...), io.Discard)
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest || !strings.Contains(refused.Message, c.want) {
			t.Errorf("ranz controller-cert set %s: %v, want it refused with %q", strings.Join(c.args, " "), err, c.want)
		}
		if got := shown(); got.Fingerprint != fp {
			t.Errorf("after the refusal of %s the certificate is %s, want %s of the one in use", strings.Join(c.args, " "), got.Fingerprint, fp)
		}
	}

	// A command that is wrong is refused before the call
	for _, args := range [][]string{
		{},
		{"show", "now"},
		{"set"},
		{"set", "-cert", certFile, "-ksp", "0123456789ABCDEF0123456789ABCDEF01234567"},
		{"set", "-key", keyFile},
		{"set", "-cert", certFile, "extra"},
		{"set", "-acme", "ctl.example.com", "-acme-http-port", "70000"},
		{"clear", "extra"},
		{"renew"},
	} {
		if err := do(ctx, cli, append([]string{"controller-cert"}, args...), io.Discard); err == nil {
			t.Errorf("ranz controller-cert %s: no error, want it refused", strings.Join(args, " "))
		}
	}
	if err := do(ctx, cli, []string{"controller-cert", "show", "now"}, io.Discard); !errors.Is(err, errUsage) {
		t.Errorf("ranz controller-cert show now: %v, want the usage", err)
	}

	// A viewer reads the certificate and may not change it
	viewer := &api.Client{URL: srv.URL, Token: createToken(t, tokens, "viewer-1", rbac.Viewer), HTTP: srv.Client()}
	if err := do(ctx, viewer, []string{"controller-cert", "show"}, io.Discard); err != nil {
		t.Errorf("a viewer: ranz controller-cert show: %v", err)
	}
	for _, args := range [][]string{
		{"controller-cert", "set", "-host", "pc-a.example.com", "-cert", certFile, "-key", keyFile},
		{"controller-cert", "clear"},
	} {
		var denied *api.Error
		if err := do(ctx, viewer, args, io.Discard); !errors.As(err, &denied) || denied.Status != http.StatusForbidden {
			t.Errorf("a viewer: ranz %s: %v, want 403", strings.Join(args, " "), err)
		}
	}
	if got := shown(); got.Fingerprint != fp {
		t.Errorf("the certificate is %s after the calls of a viewer, want %s", got.Fingerprint, fp)
	}

	// Clear gives back the self-signed certificate of the first start
	out = run("clear")
	noKey("clear", out)
	if c := userDecode[controller.CertificateChange](t, out).Certificate; c.Source != servercert.SourceSelfSigned || c.Fingerprint != first || c.Setting != nil {
		t.Errorf("clear printed %+v, want the self-signed certificate with the fingerprint %s", c, first)
	}
	if got := shown(); got.Source != servercert.SourceSelfSigned || got.Fingerprint != first {
		t.Errorf("show printed %+v after clear, want the self-signed certificate", got)
	}
	if got := userDecode[controller.CertificateChange](t, run("clear")).Certificate; got.Fingerprint != first {
		t.Errorf("clear with nothing set printed %+v, want the self-signed certificate again", got)
	}
}
