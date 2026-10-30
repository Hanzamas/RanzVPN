// The limits of what a node sends the controller (CS-4 of docs/threat-model.md, AUD1-DT-2 #450) at
// the controller conformance seam: a Hello over its limit, a frame of an admitted node over the limit
// of its kind, and the cap on the streams that wait for a Hello. The streams of these tests are raw
// ones (control.Dial and the frames the test writes), not simulated nodes, so that the frames over a
// limit are not among the ones that the nanopb round trip of CI decodes (RANZ_CONTROL_WIRE).
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newWaitingHarness returns a harness whose controller caps the streams that wait for a Hello as w
// does.
func newWaitingHarness(t *testing.T, w *control.Waiting) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) { c.Waiting = w }}
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

// dial opens a control stream to the controller as the node with the key key, which has said no Hello.
func (h *harness) dial(key keys.Static) (*control.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	return control.Dial(ctx, h.ln.Addr().String(), key, h.key.Public())
}

// rawStream is dial for a stream that must open; it closes with the test.
func (h *harness) rawStream(key keys.Static) *control.Conn {
	h.t.Helper()
	conn, err := h.dial(key)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close() })
	return conn
}

// rawStreamEventually is rawStream for a stream that the cap may still refuse while the streams that
// ended give their places back: it tries again until one opens.
func (h *harness) rawStreamEventually(key keys.Static) *control.Conn {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		conn, err := h.dial(key)
		if err == nil {
			h.t.Cleanup(func() { conn.Close() })
			return conn
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("no stream opened within %v: %v", waitTimeout, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sayHello sends the Hello of a node of schema version 1 with the Capabilities capsServer on conn.
func (h *harness) sayHello(conn *control.Conn) {
	h.t.Helper()
	hello := &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, Capabilities: capsServer}
	if _, err := conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: hello}}); err != nil {
		h.t.Fatal(err)
	}
}

// waitConnected waits until the API reports that the node name has a control stream, or has none.
func (h *harness) waitConnected(name string, connected bool) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for h.node(name).Connected != connected {
		if time.Now().After(deadline) {
			h.t.Fatalf("node %s did not reach connected %v within %v", name, connected, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// endOf reads conn until the stream ends and returns the Refuse that the controller sent before the
// end, nil when it closed the stream without one.
func endOf(t *testing.T, conn *control.Conn) *controlpb.Refuse {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	var refuse *controlpb.Refuse
	for {
		m, _, err := conn.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the stream did not end within %v", waitTimeout)
		}
		if err != nil {
			return refuse
		}
		if r := m.GetRefuse(); r != nil {
			refuse = r
		}
	}
}

// withUnknown returns m with a field of n bytes that no message has, which a reader of a protocol
// buffer takes in and ignores: m itself, but a larger frame.
func withUnknown(m *controlpb.ControlMessage, n int) *controlpb.ControlMessage {
	m.ProtoReflect().SetUnknown(protoreflect.RawFields(protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), make([]byte, n))))
	return m
}

// TestHelloOverItsLimit is the second criterion of #450 for the Hello: a Hello over MaxHello gets a
// Refuse or a close, admits no node, and the controller serves the node that keeps to the limit next.
func TestHelloOverItsLimit(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	conn := h.rawStream(keyBranch1)
	// A Hello with a key of the WireGuard interface of MaxHello bytes
	hello := &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, Capabilities: &controlpb.Capabilities{WireguardKey: make([]byte, control.MaxHello)}}
	if _, err := conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: hello}}); err != nil {
		t.Fatal(err)
	}
	if r := endOf(t, conn); r != nil && r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_PROTOCOL {
		t.Errorf("the controller answered a Hello over its limit with %s, want a Refuse for a protocol error, or a close", r.GetReason())
	}
	if n := h.node("branch-1"); n.Connected || n.Capabilities != nil {
		t.Errorf("a Hello over its limit admitted the node: %+v", n)
	}

	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
}

// TestFrameOverItsLimitClosesTheStream is the second criterion of #450 for the frames of an admitted
// node: a frame over the limit of its kind, one that the controller took before, closes the stream,
// with a Refuse for a protocol error or none, and the node connects again at once.
func TestFrameOverItsLimitClosesTheStream(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	// Each counter takes 5 bytes of the frame at least, so a Telemetry message of these is over MaxTelemetry
	peers := make([]*controlpb.PeerCounters, control.MaxTelemetry/4)
	for i := range peers {
		peers[i] = &controlpb.PeerCounters{Peer: "b"}
	}
	leases := make([]*controlpb.Lease, 9000)
	for i := range leases {
		leases[i] = &controlpb.Lease{Mac: []byte{2, 0, 0, 0, 0, 1}, Address: []byte{10, 10, 0, 7}}
	}
	for _, k := range []struct {
		name string
		msg  *controlpb.ControlMessage
	}{
		{"an Ack", withUnknown(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Ack{Ack: &controlpb.Ack{Generation: 1}}}, 100)},
		{"a Signal", withUnknown(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Signal{Signal: &controlpb.Signal{Peer: "branch-2", Envelope: make([]byte, 1000)}}}, 1500)},
		{"a Telemetry message", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Telemetry{Telemetry: &controlpb.Telemetry{Peers: peers}}}},
		{"a Leases message", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Leases{Leases: &controlpb.Leases{Network: "corp-lan", Leases: leases}}}},
	} {
		conn := h.rawStream(keyBranch1)
		h.sayHello(conn)
		h.waitConnected("branch-1", true)
		// The controller closes the stream at the first byte of the frame, so the write of a large
		// one may fail for it: what the test checks is that the stream ends
		_, _ = conn.Write(k.msg)
		if r := endOf(t, conn); r != nil && r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_PROTOCOL {
			t.Errorf("the controller answered %s over its limit with %s, want a Refuse for a protocol error, or a close", k.name, r.GetReason())
		}
		h.waitConnected("branch-1", false)
	}

	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
}

// TestStreamsThatWaitForAHelloAreCapped is the third criterion of #450: with the caps at 5 in all and
// 2 for a source, the third stream of the source that waits for its Hello is closed before its
// handshake and counted, in ranz_control_refused_total; a stream that closes, and one that says
// Hello, give their places back.
func TestStreamsThatWaitForAHelloAreCapped(t *testing.T) {
	h := newWaitingHarness(t, control.NewWaiting(5, 2))
	h.apply("apply1.json")
	first, second := h.rawStream(keyBranch1), h.rawStream(keyBranch1)

	if conn, err := h.dial(keyBranch1); err == nil {
		conn.Close()
		t.Fatal("a third stream of one source was served while two of its streams wait for their Hello")
	}
	h.waitMetrics(`ranz_control_refused_total{reason="all"} 0`, `ranz_control_refused_total{reason="source"} 1`)

	// A stream that closes gives its place back ...
	first.Close()
	h.rawStreamEventually(keyBranch1).Close()
	// ... and so does one that says Hello: it waits no more, so two others can
	h.sayHello(second)
	h.waitConnected("branch-1", true)
	h.rawStreamEventually(keyBranch1)
	h.rawStreamEventually(keyBranch1)
}
