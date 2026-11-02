package mimic

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// The own decoy with a certificate from an ACME service (ADR-0023, decoy mode 1): the decoy asks the
// service for a certificate of its name with the TLS-ALPN-01 challenge, which the service validates by
// connecting to the port of the REALITY listener. That connection is no Ranz client, so the listener
// splices it to the decoy, which answers it. The service here is a small one that speaks RFC 8555 to
// the ACME client that the decoy uses, with a CA of its own.

// acmeServer is the ACME service of the test.
type acmeServer struct {
	domain string
	srv    *httptest.Server
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey

	mu sync.Mutex
	// dial is where the challenge is validated: the address of the REALITY listener.
	dial string
	// thumb is the thumbprint of the key of the account (RFC 7638), which the key authorization holds.
	thumb string
	// token is the token of the challenge.
	token string
	// started is set when the validation starts, so that it starts once.
	started bool
	// authz and order are the statuses of the authorization and of the order.
	authz string
	order string
	// chain is the PEM chain of the certificate once it is issued.
	chain []byte
	// nonces counts the nonces that were given out.
	nonces int
	// problem says why the validation failed.
	problem string
	// requests are the requests that arrived, for the message of a failure.
	requests []string
}

func newACMEServer(t *testing.T, domain string) *acmeServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ranz test ACME CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a := &acmeServer{domain: domain, ca: ca, caKey: key, token: "token-of-the-test-challenge", authz: "pending", order: "pending"}
	a.srv = httptest.NewTLSServer(a.handler())
	t.Cleanup(a.srv.Close)
	return a
}

func (a *acmeServer) setDial(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dial = addr
}

// report says what the service saw, for the message of a failure.
func (a *acmeServer) report() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return fmt.Sprintf("the ACME service saw %q; authorization %s, order %s, validation problem %q", a.requests, a.authz, a.order, a.problem)
}

func (a *acmeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", a.directory)
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/acct", a.account)
	mux.HandleFunc("/order", a.newOrder)
	mux.HandleFunc("/order/1", a.getOrder)
	mux.HandleFunc("/authz/1", a.authorization)
	mux.HandleFunc("/chal/1", a.challenge)
	mux.HandleFunc("/finalize/1", a.finalize)
	mux.HandleFunc("/cert/1", a.certificate)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.nonces++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", a.nonces))
		a.requests = append(a.requests, r.Method+" "+r.URL.Path)
		a.mu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

func base(r *http.Request) string {
	return "https://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// readJWS reads the protected header and the payload of a request. The test service does not check the
// signature: the client that it serves is the code under test, and the rest of RFC 8555 is what is checked.
func readJWS(r *http.Request) (protected map[string]any, payload []byte, err error) {
	var jws struct {
		Protected string
		Payload   string
	}
	if err = json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil, nil, err
	}
	header, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(header, &protected); err != nil {
		return nil, nil, err
	}
	payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
	return protected, payload, err
}

func (a *acmeServer) directory(w http.ResponseWriter, r *http.Request) {
	u := base(r)
	writeJSON(w, http.StatusOK, map[string]string{
		"newNonce":   u + "/nonce",
		"newAccount": u + "/acct",
		"newOrder":   u + "/order",
		"revokeCert": u + "/revoke",
		"keyChange":  u + "/keychange",
	})
}

func (a *acmeServer) account(w http.ResponseWriter, r *http.Request) {
	protected, _, err := readJWS(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jwk, _ := protected["jwk"].(map[string]any)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	a.mu.Lock()
	a.thumb = base64.RawURLEncoding.EncodeToString(sum[:])
	a.mu.Unlock()
	w.Header().Set("Location", base(r)+"/acct/1")
	writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
}

func (a *acmeServer) orderBody(r *http.Request) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	body := map[string]any{
		"status":         a.order,
		"expires":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": a.domain}},
		"authorizations": []string{base(r) + "/authz/1"},
		"finalize":       base(r) + "/finalize/1",
	}
	if a.order == "valid" {
		body["certificate"] = base(r) + "/cert/1"
	}
	return body
}

func (a *acmeServer) newOrder(w http.ResponseWriter, r *http.Request) {
	_, payload, err := readJWS(r)
	var req struct {
		Identifiers []struct{ Type, Value string }
	}
	if err != nil || json.Unmarshal(payload, &req) != nil || len(req.Identifiers) != 1 || req.Identifiers[0].Value != a.domain {
		http.Error(w, "an order for something else than the name of the decoy", http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", base(r)+"/order/1")
	writeJSON(w, http.StatusCreated, a.orderBody(r))
}

func (a *acmeServer) getOrder(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.orderBody(r))
}

func (a *acmeServer) authorization(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	status, token := a.authz, a.token
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"identifier": map[string]string{"type": "dns", "value": a.domain},
		"challenges": []map[string]string{{"type": "tls-alpn-01", "url": base(r) + "/chal/1", "token": token, "status": status}},
	})
}

func (a *acmeServer) challenge(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	start := !a.started
	a.started = true
	token := a.token
	a.mu.Unlock()
	if start {
		go a.validate()
	}
	writeJSON(w, http.StatusOK, map[string]string{"type": "tls-alpn-01", "url": base(r) + "/chal/1", "token": token, "status": "processing"})
}

// validate is the validation of the challenge: the service connects as the CA would, and the result
// moves the authorization and the order on.
func (a *acmeServer) validate() {
	err := a.checkChallenge()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.authz, a.problem = "invalid", err.Error()
		return
	}
	a.authz, a.order = "valid", "ready"
}

// checkChallenge connects to the port of the REALITY listener with the name and the protocol
// acme-tls/1, and checks the certificate that answers (RFC 8737): it has the name, and the
// extension acmeIdentifier holds the SHA-256 of the key authorization.
func (a *acmeServer) checkChallenge() error {
	a.mu.Lock()
	dial, thumb, token := a.dial, a.thumb, a.token
	a.mu.Unlock()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", dial, &tls.Config{
		ServerName: a.domain, NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "acme-tls/1" {
		return fmt.Errorf("the protocol is %q, not acme-tls/1", state.NegotiatedProtocol)
	}
	cert := state.PeerCertificates[0]
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != a.domain {
		return fmt.Errorf("the challenge certificate is for %v", cert.DNSNames)
	}
	want := sha256.Sum256([]byte(token + "." + thumb))
	for _, e := range cert.Extensions {
		if !e.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			continue
		}
		var digest []byte
		if _, err := asn1.Unmarshal(e.Value, &digest); err != nil {
			return err
		}
		if !bytes.Equal(digest, want[:]) {
			return errors.New("the acmeIdentifier extension holds another key authorization")
		}
		return nil
	}
	return errors.New("the challenge certificate has no acmeIdentifier extension")
}

func (a *acmeServer) finalize(w http.ResponseWriter, r *http.Request) {
	_, payload, err := readJWS(r)
	var req struct{ CSR string }
	if err == nil {
		err = json.Unmarshal(payload, &req)
	}
	var der []byte
	if err == nil {
		der, err = base64.RawURLEncoding.DecodeString(req.CSR)
	}
	var csr *x509.CertificateRequest
	if err == nil {
		csr, err = x509.ParseCertificateRequest(der)
	}
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: a.domain},
		DNSNames:     []string{a.domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, a.ca, csr.PublicKey, a.caKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.ca.Raw})...)
	a.mu.Lock()
	a.chain, a.order = chain, "valid"
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, a.orderBody(r))
}

func (a *acmeServer) certificate(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	chain := a.chain
	a.mu.Unlock()
	if chain == nil {
		http.Error(w, "no certificate yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(chain)
}

// freeAddr is a loopback address for the listener of a sidecar that starts later: no other test of the run holds it until
// the test ends, and it is no port that the system hands out as the source port of a connection (rqlitetest.Addrs, CI-FLAKE-4,
// #581), as the port of a listener that was closed would be.
func freeAddr(t *testing.T) string {
	t.Helper()
	return rqlitetest.Addrs(t, 1)[0]
}

// The own decoy gets a certificate for its name from an ACME service with the TLS-ALPN-01 challenge
// through the REALITY listener, keeps it in its cache, and shows it to a prober, who checks it against
// the root of the service. The client that proves the key gets its stream from the same listener.
func TestOwnDecoyGetsItsCertificateFromACME(t *testing.T) {
	acme := newACMEServer(t, testName)
	caFile := filepath.Join(t.TempDir(), "acme-ca.pem")
	httpsCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: acme.srv.Certificate().Raw})
	if err := os.WriteFile(caFile, httpsCert, 0o600); err != nil {
		t.Fatal(err)
	}

	// The listener has its address before it starts, because the service validates through it while
	// the sidecar is still starting: the library probes the decoy for the first time then, and its
	// handshake is the one that asks for the certificate
	addr := freeAddr(t)
	acme.setDial(addr)
	private, public := keyPair(t)
	s := ownSettings(private)
	s.Listen = addr
	s.Decoy.SelfSigned = false
	cache := filepath.Join(t.TempDir(), "acme-cache")
	s.Decoy.ACME = &ACME{Directory: acme.srv.URL + "/dir", Email: "operator@example.com", CacheDir: cache, CAFile: caFile}
	srv, data := runServer(t, s, Options{})

	roots := x509.NewCertPool()
	roots.AddCert(acme.ca)
	conn, err := proberDial(addr, testName, roots)
	if err != nil {
		t.Fatalf("the prober cannot verify the certificate of the decoy against the root of the ACME service: %v\n%s", err, acme.report())
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != testName || cert.Issuer.CommonName != "Ranz test ACME CA" {
		t.Errorf("the certificate is for %v, issued by %q", cert.DNSNames, cert.Issuer.CommonName)
	}
	resp, body := get(t, conn, testName, "/")
	conn.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>Welcome</title>") {
		t.Errorf("the landing page is %d %q", resp.StatusCode, body)
	}

	// The service validated the challenge through the listener, which counted its connection as a prober
	acme.mu.Lock()
	validated := acme.authz == "valid" && acme.order == "valid"
	acme.mu.Unlock()
	if !validated {
		t.Errorf("the ACME service did not issue the certificate: %s", acme.report())
	}
	if s := srv.counters(); s.Probes == 0 {
		t.Errorf("the listener counted %+v: the validation of the service is a connection that is no client", s)
	}

	// The account key and the certificate are in the cache, so that a restart asks for nothing
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !strings.Contains(strings.Join(names, " "), "acme_account") || !strings.Contains(strings.Join(names, " "), testName) {
		t.Errorf("the cache of the decoy holds %q", names)
	}

	// The same listener takes a client that proves the key
	_, pipe := runClient(t, Options{}, linkTo(addr, public))
	link, binding, err := dialLink(pipe, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	st := data.next(t)
	defer st.conn.Close()
	noiseOver(t, link, st.conn, binding)
}
