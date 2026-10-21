// Controller conformance with the node simulator (#176 "Testing Decisions", SDN-2 #178): each
// test applies intent through the HTTP API and checks the control messages that simulated nodes
// receive and acknowledge against the golden files in testdata (prototext, compared as
// messages). The API and the control streams share one TLS port, as in the controller, so every
// test also goes through the ALPN routing of internal/port. -update rewrites the golden files.
// With RANZ_CONTROL_WIRE set to a directory, the tests also write every frame as it went over
// the wire, for the nanopb round trip of CI (tests/control/nanopb_roundtrip.c).
package controller_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
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
	keyBranch1 = fixedKey(1)  // B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=
	keyBranch2 = fixedKey(33) // WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=
	keyUnknown = fixedKey(65) // in no Node resource
)

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

// harness is one controller on its own rqlite, with the control stream and the HTTP API on one
// TLS port, as ranz-controller runs them.
type harness struct {
	t      *testing.T
	rq     *sidecar.Rqlited
	key    *keys.Soft    // the controller's Noise static key
	tlsKey crypto.Signer // the key of its TLS certificate
	st     *store.Store
	c      *controller.Controller
	ln     net.Listener
	port   *port.Server
	api    *api.Client
	serve  chan error
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, rq: rqlitetest.Start(t)}
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
	log := slog.New(slog.NewTextHandler(testWriter{h.t}, nil))
	c, err := controller.New(ctx, controller.Config{Store: st, Key: h.key, Log: log})
	if err != nil {
		h.t.Fatal(err)
	}
	cert, err := keys.SelfSigned(h.tlsKey)
	if err != nil {
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
		HTTP:    api.Handler(c, api.Status{ControlAddress: ln.Addr().String(), TLSFingerprint: keys.Fingerprint(cert)}),
		Log:     log,
	}
	h.serve = make(chan error, 1)
	go func() { h.serve <- h.port.Serve(ln) }()
	h.api = api.NewClient("https://" + ln.Addr().String())
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
// that the controller's intent compiles to for it.
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
	states, err := desired.Compile(in)
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
	s := &sim{Node: &nodesim.Node{Key: key, ControllerKey: h.key.Public(), Capabilities: capsServer, Updates: make(chan *controlpb.Update, 16)}, name: name}
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
