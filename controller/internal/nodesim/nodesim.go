// Package nodesim is the node simulator of #176 "Testing Decisions": a protocol-only node, with
// no Wintun and no data plane, that opens the control stream to the controller, reports the
// Capabilities of the host it simulates, applies the updates it receives to the state it holds
// and acknowledges each generation, and sends and receives the Signals between peers
// (ADR-0015). It is the test seam of every controller ticket: tests apply intent through the API
// and assert the control messages each simulated node receives.
//
// Against a controller cluster (SDN-17), Serve keeps the node on a stream as a node does: it
// goes from member to member until one leads, and keeps its state while no member is reachable.
package nodesim

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// Direction tells which end sent a frame.
type Direction int

const (
	Received Direction = iota // controller to node
	Sent                      // node to controller
)

// Frame is one frame of the stream as it went over the wire.
type Frame struct {
	Direction Direction
	Bytes     []byte
	Message   *controlpb.ControlMessage
}

// RefusedError is the end of a stream that the controller refused.
type RefusedError struct {
	Refuse *controlpb.Refuse
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("refused by the controller: %s: %s", e.Refuse.GetReason(), e.Refuse.GetMessage())
}

// retryPause is the pause of Serve before the next stream, unless a standby named the leader.
const retryPause = 200 * time.Millisecond

// Endpoint is a controller that a node can open its stream to.
type Endpoint struct {
	Address string // host:port of the controller's port
	Key     []byte // the controller's static public key
}

// Node is one simulated node. It keeps its state and its generation across streams, like a
// node that keeps forwarding on its last applied generation while no controller is reachable.
type Node struct {
	Key           keys.Static // the node's static key
	Controller    string      // host:port of the controller's port
	ControllerKey []byte      // the controller's static public key
	// TLSFingerprint, when it is set, is the TLS fingerprint of the Controller settings of a Node
	// (SDN-90): the certificate of every controller must have it, as the Node checks it.
	TLSFingerprint string
	// Controllers are the members of a controller cluster that Serve tries, after the ones
	// the cluster named in its last Controllers message and before Controller.
	Controllers []Endpoint
	// Version is the schema version of the Hello, SCHEMA_VERSION_1 when it is unspecified. It
	// may change between two streams only, as a node that was upgraded.
	Version controlpb.SchemaVersion
	// Capabilities are the ones the Hello reports for the simulated host (ADR-0033); nil
	// reports none.
	Capabilities *controlpb.Capabilities
	// Updates receives every update the node applied, after the node sent its Ack. When it is
	// nil, nothing is delivered.
	Updates chan *controlpb.Update
	// Signals receives every Signal that the controller forwarded to the node: peer names the
	// node that sent it. When it is nil, nothing is delivered.
	Signals chan *controlpb.Signal
	// Operations answers the live operations that the controller sends the node (SDN-50, operations.go).
	// A node reports the Capability operations only when it has one, and the controller sends no
	// Operation to a node that does not; the simulator ends its stream at an Operation that it has no
	// handler for, as a node ends its stream at a frame that it does not know.
	Operations OperationHandler
	// OnAck, when it is set, is called with the generation after the node sent its Ack of it, on the goroutine of the
	// stream (the Fleet of the scale scenario takes the instant of each Ack so, scale.go).
	OnAck func(generation uint64)
	// NoFrames keeps the node from recording the frames of its stream, so Frames returns none: a Fleet of thousands of
	// nodes has no use for them, and they would hold every update twice.
	NoFrames bool

	mu      sync.Mutex
	state   desired.State
	gen     uint64
	frames  []Frame
	learned []Endpoint // from the last Controllers message
	// pins are the TLS fingerprints that the last state named (SDN-92), nil before the first
	pins []string
	// report is what the node reports about itself after its Hello (mimic.go; SDN-94), nil for nothing
	report *controlpb.Pins
	// The stream that Run serves, nil while it serves none
	conn *control.Conn
}

// Run opens one control stream to Controller and serves it: the Hello, then each Update applied
// and acknowledged. It returns when the stream ends, with a *RefusedError if the controller
// refused the node, or when ctx ends.
func (n *Node) Run(ctx context.Context) error {
	return n.run(ctx, Endpoint{Address: n.Controller, Key: n.ControllerKey})
}

// Serve keeps the node on a control stream until ctx ends, as a node does: it opens a stream to
// one controller after the other (the members the cluster named in its last Controllers
// message, then Controllers, then Controller) and, as a node of schema version 2, goes straight
// to the leader that a standby names when it refuses the node. Between two streams, also while
// no controller is reachable, the node keeps its state and so forwards on the last generation it
// applied. Serve returns ctx.Err().
func (n *Node) Serve(ctx context.Context) error {
	next := ""
	for i := 0; ; i++ {
		eps := n.endpoints()
		if len(eps) == 0 {
			return errors.New("nodesim: no controller to open a stream to")
		}
		ep := eps[i%len(eps)]
		if next != "" {
			if j := slices.IndexFunc(eps, func(e Endpoint) bool { return e.Address == next }); j >= 0 {
				ep, i = eps[j], j
			}
			next = ""
		}
		err := n.run(ctx, ep)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var refused *RefusedError
		if errors.As(err, &refused) && n.version() >= controlpb.SchemaVersion_SCHEMA_VERSION_2 &&
			refused.Refuse.GetReason() == controlpb.RefuseReason_REFUSE_REASON_NOT_LEADER &&
			refused.Refuse.GetLeader() != "" && refused.Refuse.GetLeader() != ep.Address {
			next = refused.Refuse.GetLeader()
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryPause):
		}
	}
}

// Learned returns the controllers that the cluster named in its last Controllers message.
func (n *Node) Learned() []Endpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.learned)
}

func (n *Node) run(ctx context.Context, ep Endpoint) error {
	conn, err := n.dial(ctx, ep)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()
	n.mu.Lock()
	n.conn = conn
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.conn = nil
		n.mu.Unlock()
	}()

	version := n.version()
	n.mu.Lock()
	hello := &controlpb.Hello{SchemaVersion: version, AppliedGeneration: n.gen, Capabilities: n.Capabilities}
	n.mu.Unlock()
	if err := n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: hello}}); err != nil {
		return err
	}
	// The keys that the node reports about itself (mimic.go; SDN-94)
	if err := n.sendKeys(conn); err != nil {
		return err
	}
	for {
		m, b, err := conn.Read()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		n.record(Frame{Direction: Received, Bytes: b, Message: m})
		switch body := m.GetBody().(type) {
		case *controlpb.ControlMessage_Update:
			if err := n.apply(body.Update); err != nil {
				return err
			}
			ack := &controlpb.Ack{Generation: body.Update.GetGeneration()}
			if err := n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Ack{Ack: ack}}); err != nil {
				return err
			}
			if n.OnAck != nil {
				n.OnAck(ack.GetGeneration())
			}
			if n.Updates != nil {
				select {
				case n.Updates <- body.Update:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		case *controlpb.ControlMessage_Signal:
			if n.Signals != nil {
				select {
				case n.Signals <- body.Signal:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		case *controlpb.ControlMessage_Refuse:
			return &RefusedError{Refuse: body.Refuse}
		case *controlpb.ControlMessage_Operation:
			// A live operation of an operator (SDN-50, operations.go)
			if err := n.operate(conn, body.Operation); err != nil {
				return err
			}
		case *controlpb.ControlMessage_Controllers:
			if version < controlpb.SchemaVersion_SCHEMA_VERSION_2 {
				return errors.New("nodesim: the controller sent a Controllers message to a node of schema version 1, which does not have it")
			}
			n.learn(body.Controllers)
		default:
			return errors.New("nodesim: the controller sent a frame that is neither an Update, a Signal, a Controllers message, an Operation nor a Refuse")
		}
	}
}

// version returns the schema version of the Hello.
func (n *Node) version() controlpb.SchemaVersion {
	if n.Version == controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED {
		return controlpb.SchemaVersion_SCHEMA_VERSION_1
	}
	return n.Version
}

// endpoints returns the controllers that Serve tries, in order, each once.
func (n *Node) endpoints() []Endpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []Endpoint
	for _, ep := range slices.Concat(n.learned, n.Controllers, []Endpoint{{Address: n.Controller, Key: n.ControllerKey}}) {
		if ep.Address != "" && !slices.ContainsFunc(out, func(e Endpoint) bool { return e.Address == ep.Address }) {
			out = append(out, ep)
		}
	}
	return out
}

func (n *Node) learn(m *controlpb.Controllers) {
	var eps []Endpoint
	for _, c := range m.GetControllers() {
		eps = append(eps, Endpoint{Address: c.GetAddress(), Key: c.GetPublicKey()})
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.learned = eps
}

// Signal sends the controller a Signal with envelope for the node peer, on the stream that Run
// serves.
func (n *Node) Signal(peer string, envelope []byte) error {
	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return errors.New("nodesim: no stream to send a Signal on")
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Signal{Signal: &controlpb.Signal{Peer: peer, Envelope: envelope}}})
}

// Telemetry sends the controller the summary t (SDN-16) on the stream that Run serves.
func (n *Node) Telemetry(t *controlpb.Telemetry) error {
	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return errors.New("nodesim: no stream to send Telemetry on")
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Telemetry{Telemetry: t}})
}

// State returns the generation the node applied last and its state then.
func (n *Node) State() (uint64, desired.State) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gen, n.state
}

// Frames returns every frame the node sent and received, in order.
func (n *Node) Frames() []Frame {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Frame(nil), n.frames...)
}

func (n *Node) apply(u *controlpb.Update) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	next, err := desired.Apply(n.state, n.gen, u)
	if err != nil {
		return fmt.Errorf("nodesim: %w", err)
	}
	n.state, n.gen = next, u.GetGeneration()
	// A Node that pinned the fingerprint takes the ones of the state before it acknowledges it
	n.learnFingerprints(next)
	return nil
}

func (n *Node) send(conn *control.Conn, m *controlpb.ControlMessage) error {
	b, err := conn.Write(m)
	if err != nil {
		return err
	}
	n.record(Frame{Direction: Sent, Bytes: b, Message: m})
	return nil
}

func (n *Node) record(f Frame) {
	if n.NoFrames {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.frames = append(n.frames, f)
}
