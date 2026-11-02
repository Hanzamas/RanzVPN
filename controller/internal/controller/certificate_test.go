package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The certificate of the controller (SDN-92, #397) on the conformance seam: one controller whose TLS port
// serves the certificate of a servercert.Manager, with stand-in Nodes that pin the TLS fingerprint of the
// controller as a Node with Controller settings does (SDN-90).

// certHarness is one controller on a database of its own (rqlitetest.Fresh), whose TLS port gets its
// certificate from a Manager.
type certHarness struct {
	t     *testing.T
	st    *store.Store
	c     *controller.Controller
	m     *servercert.Manager
	key   *keys.Soft // the Noise static key of the controller
	ln    net.Listener
	port  *port.Server
	api   *api.Client // with the admin token
	addr  string
	serve chan error
}

// newCertHarness returns a controller that waits wait for the nodes to acknowledge a new fingerprint.
func newCertHarness(t *testing.T, wait time.Duration) *certHarness {
	t.Helper()
	rq := rqlitetest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
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
	log := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	m := servercert.New(servercert.Config{Store: st, SelfSigned: self, Key: tlsKey, Dir: t.TempDir(), Poll: 20 * time.Millisecond, Log: log})
	m.Start(context.Background())
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key, Log: log, LicenceKeys: []ed25519.PublicKey{testVendor.Public().(ed25519.PublicKey)},
		Certificates: m, CertificateWait: wait})
	if err != nil {
		t.Fatal(err)
	}
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(secret string) error { admin = secret; return nil }); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &certHarness{t: t, st: st, c: c, m: m, key: key, ln: ln, addr: ln.Addr().String(), serve: make(chan error, 1)}
	h.port = &port.Server{
		TLS:     &tls.Config{GetCertificate: m.GetCertificate},
		Control: c.ServeStream,
		HTTP:    api.Handler(c, tokens, api.Status{ControlAddress: h.addr, TLSFingerprint: keys.Fingerprint(self)}),
		Log:     log,
	}
	go func() { h.serve <- h.port.Serve(ln) }()
	h.api = h.client(admin)
	t.Cleanup(h.stop)
	return h
}

// client returns a client of the API that calls with the token secret.
func (h *certHarness) client(secret string) *api.Client {
	c := api.NewClient("https://" + h.addr)
	c.Token = secret
	return c
}

func (h *certHarness) stop() {
	h.ln.Close()
	if err := <-h.serve; err != nil {
		h.t.Errorf("Serve: %v", err)
	}
	h.port.Close()
	h.c.Close()
	h.m.Close()
	h.st.Close()
}

// certNode is a stand-in Node that pins a TLS fingerprint, and keeps what it learns as a Node does
// across a restart: the Node object stays, only its stream ends and starts again.
type certNode struct {
	*nodesim.Node
	name   string
	cancel context.CancelFunc
	done   chan error
}

// startNode starts the stream of the Node name, which pins the TLS fingerprint fingerprint.
func (h *certHarness) startNode(name string, key keys.Static, fingerprint string) *certNode {
	n := &certNode{name: name, Node: &nodesim.Node{Key: key, Controller: h.addr, ControllerKey: h.key.Public(), TLSFingerprint: fingerprint, Capabilities: capsServer}}
	n.serve()
	h.t.Cleanup(n.halt)
	return n
}

func (n *certNode) serve() {
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel, n.done = cancel, make(chan error, 1)
	done := n.done
	go func() { done <- n.Serve(ctx) }()
}

// halt ends the stream, as a Node does that stops.
func (n *certNode) halt() {
	if n.done != nil {
		n.cancel()
		<-n.done
		n.done = nil
	}
}

// hellos counts the streams that the Node opened: a Hello is the first frame of each.
func (n *certNode) hellos() int {
	count := 0
	for _, f := range n.Frames() {
		if f.Direction == nodesim.Sent && f.Message.GetHello() != nil {
			count++
		}
	}
	return count
}

// sawFingerprints reports whether an update that the Node received named exactly these TLS fingerprints.
func (n *certNode) sawFingerprints(want ...string) bool {
	for _, f := range n.Frames() {
		if f.Direction != nodesim.Received {
			continue
		}
		for _, o := range f.Message.GetUpdate().GetSet() {
			if slices.Equal(o.GetNode().GetControllerTls(), want) {
				return true
			}
		}
	}
	return false
}

// stateFingerprints returns the TLS fingerprints that the NodeConfig of the state of the Node holds.
func (n *certNode) stateFingerprints() []string {
	_, st := n.State()
	for _, o := range st {
		if node := o.GetNode(); node != nil {
			return node.GetControllerTls()
		}
	}
	return nil
}

// certWait waits until cond holds.
func certWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v", what, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// nodes returns what the API says of the nodes, by name.
func (h *certHarness) nodes() map[string]controller.NodeStatus {
	h.t.Helper()
	list, err := h.api.Nodes(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]controller.NodeStatus{}
	for _, n := range list {
		out[n.Name] = n
	}
	return out
}

// waitConnected waits until each node is connected and has acknowledged its latest Generation.
func (h *certHarness) waitConnected(names ...string) {
	h.t.Helper()
	certWait(h.t, fmt.Sprintf("%v to be connected at their acknowledged Generation", names), func() bool {
		all := h.nodes()
		for _, name := range names {
			if n, ok := all[name]; !ok || !n.Connected || n.Generation == 0 || n.AckedGeneration != n.Generation {
				return false
			}
		}
		return true
	})
}

// served returns the TLS fingerprint of the certificate that a new connection to the port gets.
func (h *certHarness) served() string {
	h.t.Helper()
	c, err := tls.Dial("tcp", h.addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	sum := sha256.Sum256(c.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// certIntent is the intent of the tests: a VRF with its Network and the Nodes named.
func certIntent(nodes map[string]keys.Static) intent.Document {
	rs := []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1280}`)},
		{Kind: intent.KindNetwork, Name: "corp-lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`)},
	}
	for name, k := range nodes {
		spec := fmt.Sprintf(`{"publicKey": %q, "vrfs": ["corp"]}`, base64.StdEncoding.EncodeToString(k.Public()))
		rs = append(rs, intent.Resource{Kind: intent.KindNode, Name: name, Spec: json.RawMessage(spec)})
	}
	return intent.Document{Resources: rs}
}

// certFiles writes a new certificate of the hosts, valid from now for days days (3650 when 0), with its key,
// as the files that `ranz cert` writes, and returns their paths and the TLS fingerprint of the certificate.
func certFiles(t *testing.T, dir, name string, now time.Time, days int, hosts ...string) (cert, key, fingerprint string) {
	t.Helper()
	k, err := certgen.NewKey(0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: hosts[0]}, Hosts: hosts, Now: now, Days: days}, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certgen.EncodeKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(cert, certgen.EncodeCertificate(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return cert, key, hex.EncodeToString(sum[:])
}

// fileSetting is the setting of a certificate in files for the host localhost.
func fileSetting(cert, key string) servercert.Setting {
	return servercert.Setting{Hosts: []string{"localhost"}, File: &servercert.File{Certificate: cert, Key: key}}
}

// refusedBy checks that err is an answer of the API with the status and a message that holds want.
func refusedBy(t *testing.T, what string, err error, status int, want string) {
	t.Helper()
	var refused *api.Error
	if !errors.As(err, &refused) {
		t.Errorf("%s: %v, want an answer of the API", what, err)
		return
	}
	if refused.Status != status || !strings.Contains(refused.Message, want) {
		t.Errorf("%s: %d %q, want %d with %q", what, refused.Status, refused.Message, status, want)
	}
}

// The Controller serves the certificate of its setting on its TLS port to the connections that come after it,
// and keeps the ones that are up: a stand-in Node that is connected during the replacement stays connected, and
// a Node that pinned the fingerprint of the old certificate reaches the Controller with the new one, because
// the new fingerprint reached it over its control stream before the certificate was served. A certificate that
// is refused changes nothing; a Node that is not connected makes the replacement wait for force.
func TestCertificateReplacementReachesPinnedNodes(t *testing.T) {
	h := newCertHarness(t, 10*time.Second)
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := h.api.Apply(ctx, certIntent(map[string]keys.Static{"branch-1": keyBranch1, "branch-2": keyBranch2})); err != nil {
		t.Fatal(err)
	}

	// Without a setting the Controller serves its self-signed certificate and sends the Nodes no fingerprint
	info, err := h.api.ControllerCertificate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := info.Fingerprint
	if info.Source != servercert.SourceSelfSigned || !info.SelfSigned || info.Setting != nil || h.served() != old {
		t.Fatalf("without a setting the certificate is %+v, and a new connection gets %s", info, h.served())
	}
	b1 := h.startNode("branch-1", keyBranch1, old)
	b2 := h.startNode("branch-2", keyBranch2, old)
	h.waitConnected("branch-1", "branch-2")
	for _, n := range []*certNode{b1, b2} {
		if fps := n.stateFingerprints(); len(fps) != 0 || !slices.Equal(n.Fingerprints(), []string{old}) {
			t.Errorf("%s holds the fingerprints %v of its state and %v of its settings before any setting", n.name, fps, n.Fingerprints())
		}
	}

	// A certificate that is refused changes nothing: not what is served, not the Generation of a Node
	generations := map[string]uint64{"branch-1": h.nodes()["branch-1"].Generation, "branch-2": h.nodes()["branch-2"].Generation}
	cert, key, fp := certFiles(t, dir, "ctl", time.Now(), 0, "localhost")
	_, strange, _ := certFiles(t, dir, "strange", time.Now(), 0, "localhost")
	_, err = h.api.SetControllerCertificate(ctx, fileSetting(cert, strange), false)
	refusedBy(t, "a key that does not match", err, http.StatusBadRequest, "does not belong to the certificate")
	expired, expiredKey, _ := certFiles(t, dir, "expired", time.Now().AddDate(-1, 0, 0), 30, "localhost")
	_, err = h.api.SetControllerCertificate(ctx, fileSetting(expired, expiredKey), false)
	refusedBy(t, "an expired certificate", err, http.StatusBadRequest, "has expired")
	_, err = h.api.SetControllerCertificate(ctx, servercert.Setting{Hosts: []string{"ctl.example.com"}, File: &servercert.File{Certificate: cert, Key: key}}, false)
	refusedBy(t, "a certificate for another host", err, http.StatusBadRequest, `does not name the host "ctl.example.com" that the Nodes use: it names localhost`)
	if info, err = h.api.ControllerCertificate(ctx); err != nil || info.Fingerprint != old || h.served() != old {
		t.Fatalf("after three refusals the certificate is %+v, %v, and a new connection gets %s", info, err, h.served())
	}
	for name, gen := range generations {
		if got := h.nodes()[name]; got.Generation != gen {
			t.Errorf("%s is at Generation %d after refusals, was at %d", name, got.Generation, gen)
		}
	}

	// The replacement: both Nodes acknowledged the new fingerprint before the certificate was served
	hellos := map[string]int{"branch-1": b1.hellos(), "branch-2": b2.hellos()}
	res, err := h.api.SetControllerCertificate(ctx, fileSetting(cert, key), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Source != servercert.SourceFile || res.Certificate.Fingerprint != fp || res.Certificate.Fingerprint == old {
		t.Errorf("the replacement is %+v, want the file with the fingerprint %s, not %s", res.Certificate, fp, old)
	}
	if !slices.Equal(res.Pinned, []string{"branch-1", "branch-2"}) || len(res.Unpinned) != 0 {
		t.Errorf("the Nodes that took the new fingerprint are %v, and %v did not", res.Pinned, res.Unpinned)
	}
	for _, n := range []*certNode{b1, b2} {
		if !n.sawFingerprints(old, fp) {
			t.Errorf("%s was not sent the fingerprint of the new certificate with the one in use", n.name)
		}
	}
	certWait(t, "the Nodes to keep the new fingerprint alone", func() bool {
		return slices.Equal(b1.Fingerprints(), []string{fp}) && slices.Equal(b2.Fingerprints(), []string{fp})
	})

	// The connections that were up are up, and the next ones get the new certificate
	if b1.hellos() != hellos["branch-1"] || b2.hellos() != hellos["branch-2"] {
		t.Errorf("a Node reconnected during the replacement: %d and %d streams, were %d and %d", b1.hellos(), b2.hellos(), hellos["branch-1"], hellos["branch-2"])
	}
	h.waitConnected("branch-1", "branch-2")
	if got := h.served(); got != fp {
		t.Errorf("a new connection gets the fingerprint %s, want %s of the new certificate", got, fp)
	}
	if info, err = h.api.ControllerCertificate(ctx); err != nil || info.Fingerprint != fp || info.Source != servercert.SourceFile {
		t.Errorf("show: %+v, %v", info, err)
	}
	if b, err := json.Marshal(info); err != nil || strings.Contains(string(b), "PRIVATE") {
		t.Errorf("show printed %s, %v: it must hold no key", b, err)
	}

	// A Node that pinned the old fingerprint reconnects: it keeps the ones the Controller sent. One that was never
	// told is refused at the TLS session, before it sends anything.
	b1.halt()
	// The Controller lists the stream that just ended as connected until it reads its end: wait until it lists branch-1 as
	// gone, and then for the Hello of the new stream, so that the connected branch-1 below is the one with the new Hello
	certWait(t, "the Controller to list branch-1 as gone", func() bool { return !h.nodes()["branch-1"].Connected })
	b1.serve()
	certWait(t, "branch-1 to open a new stream", func() bool { return b1.hellos() > hellos["branch-1"] })
	h.waitConnected("branch-1")
	if b1.hellos() != hellos["branch-1"]+1 {
		t.Errorf("branch-1 opened %d streams, want one more than %d", b1.hellos(), hellos["branch-1"])
	}
	if _, err := control.DialPinned(ctx, h.addr, keyBranch1, h.key.Public(), old); !errors.Is(err, nodecontroller.ErrFingerprint) {
		t.Errorf("a Node that was not told of the new fingerprint: %v, want the fingerprint check to fail", err)
	}

	// A Node that is not connected could not be told: the replacement waits for force and names it
	if _, err := h.api.Apply(ctx, certIntent(map[string]keys.Static{"branch-3": fixedKey(97)})); err != nil {
		t.Fatal(err)
	}
	cert2, key2, fp2 := certFiles(t, dir, "ctl2", time.Now(), 0, "localhost")
	_, err = h.api.SetControllerCertificate(ctx, fileSetting(cert2, key2), false)
	refusedBy(t, "a Node that is not connected", err, http.StatusConflict, "branch-3")
	if got := h.served(); got != fp {
		t.Errorf("a refused replacement changed the certificate: a new connection gets %s, want %s", got, fp)
	}
	certWait(t, "the Nodes that were told to take the fingerprint again", func() bool {
		return slices.Equal(b1.Fingerprints(), []string{fp}) && slices.Equal(b2.Fingerprints(), []string{fp})
	})
	res, err = h.api.SetControllerCertificate(ctx, fileSetting(cert2, key2), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Fingerprint != fp2 || !slices.Equal(res.Pinned, []string{"branch-1", "branch-2"}) || !slices.Equal(res.Unpinned, []string{"branch-3"}) {
		t.Errorf("the replacement with force is %+v, pinned %v, not %v", res.Certificate, res.Pinned, res.Unpinned)
	}
	// branch-3 pinned the old fingerprint and was not told: it is refused; with the new one it joins
	if _, err := control.DialPinned(ctx, h.addr, fixedKey(97), h.key.Public(), fp); !errors.Is(err, nodecontroller.ErrFingerprint) {
		t.Errorf("a Node that was left out: %v, want the fingerprint check to fail", err)
	}
	conn, err := control.DialPinned(ctx, h.addr, fixedKey(97), h.key.Public(), fp2)
	if err != nil {
		t.Errorf("a Node that was given the new fingerprint by hand: %v", err)
	} else {
		conn.Close()
	}

	// Clearing the setting serves the self-signed certificate again, with the same care for the Nodes
	res, err = h.api.ClearControllerCertificate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Source != servercert.SourceSelfSigned || res.Certificate.Fingerprint != old || h.served() != old {
		t.Errorf("after clear the certificate is %+v, and a new connection gets %s, want %s", res.Certificate, h.served(), old)
	}
	if !b1.sawFingerprints(fp2, old) {
		t.Error("branch-1 was not sent the fingerprint of the self-signed certificate with the one in use before the clear")
	}
	certWait(t, "the Nodes to keep the fingerprint of the self-signed certificate alone", func() bool {
		return slices.Equal(b1.Fingerprints(), []string{old}) && slices.Equal(b2.Fingerprints(), []string{old})
	})
	b1.halt()
	b1.serve()
	h.waitConnected("branch-1", "branch-2")

	// The changes are in the events, and a viewer reads the certificate and changes nothing
	events, err := h.api.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, e := range events {
		if e.Type == event.ControllerCertificateChanged && strings.Contains(e.Message, `"admin"`) {
			changed++
		}
	}
	if changed != 3 {
		t.Errorf("the events hold %d changes of the certificate by the admin token, want 3: %+v", changed, events)
	}
	viewer, err := h.api.CreateToken(ctx, "viewer-1", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	v := h.client(viewer.Secret)
	if got, err := v.ControllerCertificate(ctx); err != nil || got.Fingerprint != old {
		t.Errorf("a viewer reads the certificate: %+v, %v", got, err)
	}
	_, err = v.SetControllerCertificate(ctx, fileSetting(cert, key), false)
	refusedBy(t, "a viewer sets the certificate", err, http.StatusForbidden, "needs the role operator")
	_, err = v.ClearControllerCertificate(ctx, false)
	refusedBy(t, "a viewer clears the setting", err, http.StatusForbidden, "needs the role operator")
}

// A certificate with the key of the one in use has the same TLS fingerprint, so the Nodes have nothing new to
// pin: the replacement does not wait for them, it is not refused for a Node that is not connected, and the
// stream of a Node that is stays up. The ACME certificate of the Controller is one.
func TestCertificateOfTheSameKeyNeedsNoFingerprint(t *testing.T) {
	h := newCertHarness(t, 10*time.Second)
	ctx := context.Background()
	if _, err := h.api.Apply(ctx, certIntent(map[string]keys.Static{"branch-1": keyBranch1, "branch-2": keyBranch2})); err != nil {
		t.Fatal(err)
	}
	old := h.m.Fingerprint()
	b1 := h.startNode("branch-1", keyBranch1, old)
	h.waitConnected("branch-1")
	hellos := b1.hellos()

	// A certificate for the TLS key of the Controller itself
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "localhost"}, Hosts: []string{"localhost"}}, h.m.SelfSigned().Cert.PrivateKey.(*ecdsa.PrivateKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certgen.EncodeKey(h.m.SelfSigned().Cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "same.pem"), filepath.Join(dir, "same.key")
	if err := os.WriteFile(cert, certgen.EncodeCertificate(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := h.api.SetControllerCertificate(ctx, fileSetting(cert, key), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Fingerprint != old || res.Certificate.Source != servercert.SourceFile || len(res.Pinned) != 0 || len(res.Unpinned) != 0 {
		t.Errorf("the replacement is %+v, pinned %v, unpinned %v: the fingerprint stays and nothing is sent", res.Certificate, res.Pinned, res.Unpinned)
	}
	// branch-2 is not connected, and the replacement was not refused for it
	h.waitConnected("branch-1")
	if b1.hellos() != hellos {
		t.Errorf("branch-1 reconnected during the replacement: %d streams, was %d", b1.hellos(), hellos)
	}
	certWait(t, "branch-1 to hold the fingerprint of the setting", func() bool { return slices.Equal(b1.Fingerprints(), []string{old}) })
	if got := h.served(); got != old {
		t.Errorf("a new connection gets %s, want %s", got, old)
	}
	b1.halt()
	b1.serve()
	h.waitConnected("branch-1")
}

// A controller that serves one fixed certificate has no setting to show, set or clear.
func TestNoCertificateWithoutAManager(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.api.ControllerCertificate(ctx)
	refusedBy(t, "show", err, http.StatusNotImplemented, "one fixed certificate")
	_, err = h.api.SetControllerCertificate(ctx, servercert.Setting{Hosts: []string{"localhost"}, KSP: strings.Repeat("AB", 20)}, false)
	refusedBy(t, "set", err, http.StatusNotImplemented, "one fixed certificate")
	_, err = h.api.ClearControllerCertificate(ctx, false)
	refusedBy(t, "clear", err, http.StatusNotImplemented, "one fixed certificate")
	_, err = h.api.SetControllerCertificate(ctx, servercert.Setting{}, false)
	refusedBy(t, "set with no source", err, http.StatusBadRequest, "exactly one source")
}
