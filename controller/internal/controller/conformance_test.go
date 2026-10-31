// Controller conformance with the node simulator (#176 "Testing Decisions", SDN-2 #178): each
// test applies intent through the HTTP API and checks the control messages that simulated nodes
// receive and acknowledge against the golden files in testdata (prototext, compared as
// messages). The API and the control streams share one TLS port, as in the controller, so every
// test also goes through the ALPN routing of internal/port. The harness calls the API with the
// admin token that the first start of the controller creates (rbac_test.go tests the roles).
// -update rewrites the golden files.
// With RANZ_CONTROL_WIRE set to a directory, the tests also write every frame as it went over
// the wire, for the nanopb round trip of CI (tests/control/nanopb_roundtrip.c).
package controller_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

var rewrite = flag.Bool("update", false, "rewrite the golden files instead of comparing with them")

// waitTimeout bounds every wait for something the controller or a node does.
const waitTimeout = 20 * time.Second

// The static keys of the simulated nodes: fixed, so the golden files can hold the peer keys.
// The publicKey of each Node resource in testdata is the X25519 public key of these.
var (
	keyBranch1 = fixedKey(1)   // B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=
	keyBranch2 = fixedKey(33)  // WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=
	keyUnknown = fixedKey(65)  // in no Node resource
	keyLab1    = fixedKey(97)  // JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=
	keyRelay1  = fixedKey(129) // iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc=
)

// quietTimeout is how long a test waits for a frame that must not come.
const quietTimeout = 300 * time.Millisecond

// TestApplySendsGeneration1 is the first criterion of #178: applying a VRF, a Network and a
// Node makes the simulator receive generation 1 and acknowledge it.
func TestApplySendsGeneration1(t *testing.T) {
	h := newHarness(t)
	res := h.apply("apply1.json")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("apply1.json changed %+v, want %+v", res.Nodes, want)
	}
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	h.checkState(b1)
}

// TestYAMLAndJSONGiveTheSameGeneration applies apply1.yaml, the intent of apply1.json in YAML:
// the node receives the same generation 1, the golden file of TestApplySendsGeneration1, and
// the stored intent is the same JSON.
func TestYAMLAndJSONGiveTheSameGeneration(t *testing.T) {
	fromJSON := newHarness(t)
	fromJSON.apply("apply1.json")
	fromYAML := newHarness(t)
	res := fromYAML.apply("apply1.yaml")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("apply1.yaml changed %+v, want %+v", res.Nodes, want)
	}
	if a, b := fromJSON.resources(), fromYAML.resources(); a != b {
		t.Errorf("the intent of apply1.yaml differs from the one of apply1.json:\n--- YAML\n%s\n--- JSON\n%s", b, a)
	}
	b1 := fromYAML.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	fromYAML.waitNode("branch-1", 1, true)
}

// TestSecondApplySendsDelta is the second criterion of #178: a second apply sends only the
// delta, as generation 2. A delete sends the removal as the next generation.
func TestSecondApplySendsDelta(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)

	res := h.apply("apply2.json")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "branch-2", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("apply2.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "apply2-branch-1", b1.update(t))
	b2 := h.sim("branch-2", keyBranch2)
	golden(t, "apply2-branch-2", b2.update(t))
	h.waitNode("branch-1", 2, true)
	h.waitNode("branch-2", 1, true)

	if _, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-dmz"); err != nil {
		t.Fatal(err)
	}
	golden(t, "delete-branch-1", b1.update(t))
	golden(t, "delete-branch-2", b2.update(t))
	h.waitNode("branch-1", 3, true)
	h.waitNode("branch-2", 2, true)
	h.checkState(b1)
	h.checkState(b2)
}

// TestIntentSurvivesRestart is the third criterion of #178: the controller keeps its intent, the
// generations and the acknowledgements across a restart of the controller and of rqlite.
func TestIntentSurvivesRestart(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.apply("apply2.json")
	golden(t, "apply2-branch-1", b1.update(t))
	h.waitNode("branch-1", 2, true)
	before := h.resources()

	h.stop()
	if err := b1.end(t); err == nil {
		t.Error("the stream of branch-1 ended without an error when the controller stopped")
	}
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()

	if after := h.resources(); after != before {
		t.Errorf("the intent after the restart differs:\n--- after\n%s\n--- before\n%s", after, before)
	}
	nodes, err := h.api.Nodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []controller.NodeStatus{
		{Name: "branch-1", Generation: 2, AckedGeneration: 2, Capabilities: capability.FromProto(capsServer)},
		{Name: "branch-2", Generation: 1},
	}
	if a, b := asJSON(t, nodes), asJSON(t, want); a != b {
		t.Errorf("the nodes after the restart are %s, want %s", a, b)
	}

	// branch-1 reconnects at generation 2, which it applied, so it gets nothing until the
	// next change; then the delta from generation 2.
	b1.start(h)
	h.waitNode("branch-1", 2, true)
	h.apply("apply3.json")
	golden(t, "restart-branch-1", b1.update(t))
	h.waitNode("branch-1", 3, true)
	h.checkState(b1)
}

// TestRefusals checks that the controller refuses a node it does not know and a node of a
// schema version it does not serve, with the reason and a message.
func TestRefusals(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")

	stranger := h.sim("stranger", keyUnknown)
	golden(t, "refuse-unknown-node", stranger.refusal(t))

	old := h.newSim("branch-1", keyBranch1)
	old.Version = 7
	old.start(h)
	golden(t, "refuse-schema-version", old.refusal(t))
}

// TestControllersReachSchema2Nodes checks the Controllers message of schema version 2 (SDN-17):
// a node of version 2 receives the Controller resources of the intent before its first update
// and again when they change, without a new generation; a node of version 1, which does not have
// the message, receives none and the same updates as before.
func TestControllersReachSchema2Nodes(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	h.apply("controllers1.json")
	b1 := h.newSim("branch-1", keyBranch1)
	b1.Version = controlpb.SchemaVersion_SCHEMA_VERSION_2
	b1.start(h)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	got := received(b1)
	if len(got) < 2 || got[0].GetControllers() == nil {
		t.Fatalf("branch-1 received %d frames, and the first is not a Controllers message: %v", len(got), got)
	}
	golden(t, "controllers1-branch-1", got[0])
	if l := b1.Learned(); len(l) != 2 || l[0].Address != "192.0.2.1:443" || l[1].Address != "192.0.2.2:443" {
		t.Errorf("branch-1 learned the controllers %+v", l)
	}

	if _, err := h.api.Delete(context.Background(), intent.KindController, "c2"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for len(b1.Learned()) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("branch-1 did not learn within %v that c2 was deleted: %+v", waitTimeout, b1.Learned())
		}
		time.Sleep(20 * time.Millisecond)
	}
	got = received(b1)
	golden(t, "controllers2-branch-1", got[len(got)-1])
	h.waitNode("branch-1", 1, true)

	h.apply("apply2.json")
	golden(t, "apply2-branch-1", b1.update(t))
	b2 := h.sim("branch-2", keyBranch2)
	golden(t, "apply2-branch-2", b2.update(t))
	h.waitNode("branch-1", 2, true)
	h.waitNode("branch-2", 1, true)
	for _, m := range received(b2) {
		if m.GetControllers() != nil {
			t.Errorf("branch-2, a node of schema version 1, received a Controllers message:\n%s", show(m))
		}
	}
	h.checkState(b1)
	h.checkState(b2)
}

// TestRelaysAndSignals is CORE-S5-2 (#78) at the controller: a node gets a Relay object for each
// relay of its VRFs, and the controller carries a Signal from a node to a peer with the bytes of
// its envelope as they came and the sender's name, drops one for a node that is no peer, and
// leaves it to the receiver to refuse an altered or forged envelope.
func TestRelaysAndSignals(t *testing.T) {
	h := newHarness(t)
	h.apply("apply-relay.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	lab := h.sim("lab-1", keyLab1)
	relay := h.sim("relay-1", keyRelay1)
	golden(t, "relay-branch-1", b1.update(t))
	b2.update(t)
	lab.update(t)
	relay.update(t)
	for _, name := range []string{"branch-1", "branch-2", "lab-1", "relay-1"} {
		h.waitNode(name, 1, true)
	}

	// A signal of branch-1 for lab-1, which shares no VRF with it, is dropped; one for branch-2
	// arrives as it was sealed, named after its sender.
	payload := []byte("the relay assignment and the candidates of branch-1")
	env, err := control.Seal(control.KindSignal, keyBranch1, keyBranch2.Public(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b1.Signal("lab-1", env); err != nil {
		t.Fatal(err)
	}
	if err := b1.Signal("branch-2", env); err != nil {
		t.Fatal(err)
	}
	sig := b2.signal(t)
	if sig.GetPeer() != "branch-1" || !bytes.Equal(sig.GetEnvelope(), env) {
		t.Errorf("branch-2 got a Signal from %q of %d bytes, want branch-1's %d bytes as they were sealed", sig.GetPeer(), len(sig.GetEnvelope()), len(env))
	}
	from, got, err := control.Open(control.KindSignal, sig.GetEnvelope(), keyBranch2)
	if err != nil || !bytes.Equal(from, keyBranch1.Public()) || !bytes.Equal(got, payload) {
		t.Errorf("branch-2 opened sender %x and %q: %v", from, got, err)
	}
	lab.quiet(t)

	// The controller passes an altered envelope on as it came; the receiver refuses it.
	altered := bytes.Clone(env)
	altered[len(altered)-1] ^= 1
	if err := b1.Signal("branch-2", altered); err != nil {
		t.Fatal(err)
	}
	sig = b2.signal(t)
	if !bytes.Equal(sig.GetEnvelope(), altered) {
		t.Error("the controller changed the bytes of an envelope")
	}
	if _, _, err := control.Open(control.KindSignal, sig.GetEnvelope(), keyBranch2); err == nil {
		t.Error("branch-2 opened an altered envelope")
	}

	// relay-1 forges a signal in branch-1's name: the controller names its real sender, and the
	// envelope does not open.
	forged, err := control.Seal(control.KindSignal, keyRelay1, keyBranch2.Public(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	copy(forged[1:33], keyBranch1.Public())
	if err := relay.Signal("branch-2", forged); err != nil {
		t.Fatal(err)
	}
	sig = b2.signal(t)
	if sig.GetPeer() != "relay-1" {
		t.Errorf("the forged Signal came named after %q, not its sender relay-1", sig.GetPeer())
	}
	if _, _, err := control.Open(control.KindSignal, sig.GetEnvelope(), keyBranch2); err == nil {
		t.Error("branch-2 opened an envelope forged in branch-1's name")
	}

	// A Signal without an envelope ends the stream of its sender.
	if err := lab.Signal("relay-1", nil); err != nil {
		t.Fatal(err)
	}
	golden(t, "refuse-signal", lab.refusal(t))
}

// TestApplyRejectsInvalidIntent checks that an invalid intent changes nothing and the answer
// names every problem.
func TestApplyRejectsInvalidIntent(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	before := h.resources()
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"mtu": 1000}`)},
		{Kind: intent.KindNetwork, Name: "lab-net", Spec: json.RawMessage(`{"vrf": "nowhere"}`)},
		{Kind: intent.KindNode, Name: "Bad_Name"},
	}}
	_, err := h.api.Apply(context.Background(), doc)
	if err == nil {
		t.Fatal("the invalid intent was applied")
	}
	for _, want := range []string{`Node "Bad_Name": the name must be`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name %q", err, want)
		}
	}
	doc.Resources = doc.Resources[:2]
	_, err = h.api.Apply(context.Background(), doc)
	if err == nil {
		t.Fatal("the invalid intent was applied")
	}
	for _, want := range []string{`VRF "lab": mtu 1000 is not between 1280 and 65535`, `Network "lab-net": VRF "nowhere" does not exist`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name %q", err, want)
		}
	}
	if after := h.resources(); after != before {
		t.Errorf("an invalid apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
}

// harness is one controller on a database of its own, with the control stream and the HTTP API on one
// TLS port, as ranz-controller runs them. Its controller verifies licence keys that testVendor
// signed (licence_test.go). The database is an empty one of an rqlited that the tests share
// (rqlitetest.Fresh), or of an rqlited of the test's own for a test that called rqlitetest.Own first:
// one that stops, restarts or joins h.rq, reads its data directory, restores a backup into it or runs
// the members of a cluster on it. A test that has a harness runs in parallel with the others that do
// (rqlitetest.Fresh makes it), so it keeps no state outside its harness, never calls t.Parallel itself and
// does not use t.Setenv or t.Chdir; a test that cannot run beside another calls rqlitetest.Alone first.
type harness struct {
	t       *testing.T
	rq      *sidecar.Rqlited
	key     *keys.Soft    // the controller's Noise static key
	tlsKey  crypto.Signer // the key of its TLS certificate
	version string        // of the controller, version.Version when empty
	st      *store.Store
	c       *controller.Controller
	ln      net.Listener
	port    *port.Server
	api     *api.Client // with the admin token
	admin   string      // the secret of the admin token rbac.FirstAdmin
	serve   chan error
	// schema is the control schema version the controller runs as from its next start,
	// controller.SchemaVersion when it is unspecified.
	schema controlpb.SchemaVersion
	// revPath is the update channel's path for the signed revocation list (ADR-0036, SEC-5 #283),
	// empty when the harness delivers none.
	revPath string
	// defaults has the first start create the intent of a first install (SDN-3 #179), with the
	// ULA of VRF default drawn from random.
	defaults bool
	random   io.Reader
	// tune changes the Config of the controller before each start, for a test that needs a
	// setting the others leave at its default (telemetry_test.go).
	tune func(*controller.Config)
	// sealer is what the store of each start seals the secrets with, as the sealing key of the host does
	// (store.SetSealer), none when it is nil: the PresharedKeys of the Devices (devicekeys_test.go).
	sealer store.Sealer
	// limits are the limits for a source of the TLS port (AUD1-DT-3, #451), the defaults when they are zero.
	limits port.Limits
}

func newHarness(t *testing.T) *harness {
	return newHarnessAt(t, "")
}

// newHarnessAt returns a harness whose controller is of version v, which the fallback licence
// of an expired subscription must cover.
func newHarnessAt(t *testing.T, v string) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), version: v}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

// newHarnessRevocations returns a harness whose controller reads the signed revocation list the
// update channel delivers to h.revPath (ADR-0036, SEC-5 #283); the file need not exist yet.
func newHarnessRevocations(t *testing.T) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), revPath: filepath.Join(t.TempDir(), "revocations.sig")}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) start() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	st, err := store.Open(ctx, h.rq.URL())
	if err != nil {
		h.t.Fatal(err)
	}
	if h.sealer != nil {
		st.SetSealer(h.sealer, nil)
	}
	log := slog.New(slog.NewTextHandler(testWriter{h.t}, nil))
	cfg := controller.Config{Store: st, Key: h.key, Log: log, Schema: h.schema,
		LicenceKeys: []ed25519.PublicKey{testVendor.Public().(ed25519.PublicKey)}, Version: h.version, Revocations: h.revPath,
		Defaults: h.defaults, Random: h.random}
	if h.tune != nil {
		h.tune(&cfg)
	}
	c, err := controller.New(ctx, cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	cert, err := keys.SelfSigned(h.tlsKey)
	if err != nil {
		h.t.Fatal(err)
	}
	tokens := rbac.New(st)
	// The first start creates the admin token; a restart finds it in the store.
	if _, err := tokens.Bootstrap(ctx, func(secret string) error { h.admin = secret; return nil }); err != nil {
		h.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	h.st, h.c, h.ln = st, c, ln
	h.port = &port.Server{
		TLS:     &tls.Config{Certificates: []tls.Certificate{cert}},
		Control: c.ServeStream,
		HTTP: api.Handler(c, tokens, api.Status{ControlAddress: ln.Addr().String(), TLSFingerprint: keys.Fingerprint(cert),
			ReadRefusals: func() port.Refusals { return h.port.Refusals() }}),
		Log:    log,
		Limits: h.limits,
	}
	h.serve = make(chan error, 1)
	go func() { h.serve <- h.port.Serve(ln) }()
	h.api = h.client(h.admin)
}

// client returns a client of the API that calls with the token secret, none when it is empty.
func (h *harness) client(secret string) *api.Client {
	c := api.NewClient("https://" + h.ln.Addr().String())
	c.Token = secret
	return c
}

func (h *harness) stop() {
	if h.c == nil {
		return
	}
	h.ln.Close()
	if err := <-h.serve; err != nil {
		h.t.Errorf("Serve: %v", err)
	}
	h.port.Close()
	h.c.Close()
	h.st.Close()
	h.c = nil
}

// apply applies the intent document testdata/file, YAML or JSON, as `ranz apply -f` does.
func (h *harness) apply(file string) controller.ApplyResult {
	h.t.Helper()
	res, err := h.tryApply(file)
	if err != nil {
		h.t.Fatalf("applying %s: %v", file, err)
	}
	return res
}

// tryApply applies the intent document testdata/file and returns the answer of the API.
func (h *harness) tryApply(file string) (controller.ApplyResult, error) {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		h.t.Fatal(err)
	}
	doc, err := intent.ParseDocument(b)
	if err != nil {
		h.t.Fatalf("%s: %v", file, err)
	}
	return h.api.Apply(context.Background(), doc)
}

// resources returns the intent as the API reports it, as JSON.
func (h *harness) resources() string {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

// waitNode waits until the API reports that node name acknowledged generation gen and is
// connected or not.
func (h *harness) waitNode(name string, gen uint64, connected bool) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		nodes, err := h.api.Nodes(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		for _, n := range nodes {
			if n.Name == name && n.AckedGeneration == gen && n.Generation == gen && n.Connected == connected {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("node %s did not reach generation %d acknowledged (connected %v) within %v: %+v", name, gen, connected, waitTimeout, nodes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkState checks that the state the simulated node built from its updates is the full state
// that the controller's intent compiles to for it, with the Nodes that the licence in force
// covers.
func (h *harness) checkState(s *sim) {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		h.t.Fatal(err)
	}
	lic, err := h.api.Licence(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	states, err := desired.Compile(in.Capped(lic.Nodes))
	if err != nil {
		h.t.Fatal(err)
	}
	gen, got := s.State()
	if want := states[s.name]; !desired.Equal(got, want) {
		h.t.Errorf("%s: the state at generation %d differs from the compiled intent:\n--- node\n%s\n--- intent\n%s",
			s.name, gen, show(desired.Full(got, gen)), show(desired.Full(want, gen)))
	}
}

// sim is a simulated node of a test and the stream it runs.
type sim struct {
	*nodesim.Node
	name   string
	cancel context.CancelFunc
	done   chan error // receives how the stream ended; nil while no stream runs
}

// newSim returns a simulated node that has no stream yet; start runs one.
func (h *harness) newSim(name string, key keys.Static) *sim {
	s := &sim{Node: &nodesim.Node{Key: key, ControllerKey: h.key.Public(), Capabilities: capsServer, Updates: make(chan *controlpb.Update, 16), Signals: make(chan *controlpb.Signal, 16)}, name: name}
	h.t.Cleanup(func() {
		s.halt()
		dumpWire(h.t, s)
	})
	return s
}

// sim returns a simulated node with a stream to the controller.
func (h *harness) sim(name string, key keys.Static) *sim {
	s := h.newSim(name, key)
	s.start(h)
	return s
}

func (s *sim) start(h *harness) {
	ctx, cancel := context.WithCancel(context.Background())
	s.Controller = h.ln.Addr().String()
	s.cancel, s.done = cancel, make(chan error, 1)
	done := s.done
	go func() { done <- s.Run(ctx) }()
}

func (s *sim) halt() {
	if s.done != nil {
		s.cancel()
		<-s.done
		s.done = nil
	}
}

// end waits for the stream to end and returns how it ended.
func (s *sim) end(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.done:
		s.cancel()
		s.done = nil
		return err
	case <-time.After(waitTimeout):
		t.Fatalf("%s: the stream did not end within %v", s.name, waitTimeout)
	}
	return nil
}

// update waits for the next update the node applied and returns it as the control message it
// came in.
func (s *sim) update(t *testing.T) *controlpb.ControlMessage {
	t.Helper()
	select {
	case u := <-s.Updates:
		return &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Update{Update: u}}
	case err := <-s.done:
		s.done = nil
		t.Fatalf("%s: the stream ended before the next update: %v", s.name, err)
	case <-time.After(waitTimeout):
		t.Fatalf("%s: no update within %v", s.name, waitTimeout)
	}
	return nil
}

// signal waits for the next Signal that the controller forwarded to the node.
func (s *sim) signal(t *testing.T) *controlpb.Signal {
	t.Helper()
	select {
	case sig := <-s.Signals:
		return sig
	case err := <-s.done:
		s.done = nil
		t.Fatalf("%s: the stream ended before the next signal: %v", s.name, err)
	case <-time.After(waitTimeout):
		t.Fatalf("%s: no signal within %v", s.name, waitTimeout)
	}
	return nil
}

// quiet checks that no Signal reaches the node within quietTimeout.
func (s *sim) quiet(t *testing.T) {
	t.Helper()
	select {
	case sig := <-s.Signals:
		t.Errorf("%s: got a Signal from %q that the controller should have dropped", s.name, sig.GetPeer())
	case <-time.After(quietTimeout):
	}
}

// refusal waits for the controller to refuse the node and returns the Refuse as the control
// message it came in.
func (s *sim) refusal(t *testing.T) *controlpb.ControlMessage {
	t.Helper()
	err := s.end(t)
	var refused *nodesim.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("%s: the stream ended with %v, not a refusal", s.name, err)
	}
	return &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Refuse{Refuse: refused.Refuse}}
}

// received returns the frames that s received from the controller, in order.
func received(s *sim) []*controlpb.ControlMessage {
	var out []*controlpb.ControlMessage
	for _, f := range s.Frames() {
		if f.Direction == nodesim.Received {
			out = append(out, f.Message)
		}
	}
	return out
}

// golden compares m with testdata/<name>.txtpb, or writes it there under -update.
func golden(t *testing.T, name string, m *controlpb.ControlMessage) {
	t.Helper()
	path := filepath.Join("testdata", name+".txtpb")
	got := show(m)
	if *rewrite {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &controlpb.ControlMessage{}
	if err := prototext.Unmarshal(b, want); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if !proto.Equal(m, want) {
		t.Errorf("%s: the control message differs from the golden file\n--- got\n%s\n--- want\n%s", path, got, show(want))
	}
}

// dumpWire writes each frame of s to the directory that RANZ_CONTROL_WIRE names, one file per
// frame: <test>-<node>-<index>-<recv|sent>.bin.
func dumpWire(t *testing.T, s *sim) {
	dir := os.Getenv("RANZ_CONTROL_WIRE")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Error(err)
		return
	}
	for i, f := range s.Frames() {
		way := "recv"
		if f.Direction == nodesim.Sent {
			way = "sent"
		}
		path := filepath.Join(dir, fmt.Sprintf("%s-%s-%02d-%s.bin", t.Name(), s.name, i, way))
		if err := os.WriteFile(path, f.Bytes, 0o644); err != nil {
			t.Error(err)
		}
	}
}

func show(m proto.Message) string {
	b, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func equalGenerations(a, b []controller.NodeGeneration) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fixedKey returns the static key whose private key is the 32 bytes first, first+1, ...
func fixedKey(first byte) *keys.Soft {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = first + byte(i)
	}
	k, err := keys.NewSoft(priv)
	if err != nil {
		panic(err)
	}
	return k
}

// testWriter sends the controller's log to the test log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimSuffix(string(b), "\n"))
	return len(b), nil
}
