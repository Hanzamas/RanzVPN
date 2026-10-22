// Package nodesim is the node simulator of #176 "Testing Decisions": a protocol-only node, with
// no Wintun and no data plane, that opens the control stream to the controller, reports the
// Capabilities of the host it simulates, applies the updates it receives to the state it holds
// and acknowledges each generation. It is the test seam of every controller ticket: tests apply
// intent through the API and assert the control messages each simulated node receives.
package nodesim

import (
	"context"
	"errors"
	"fmt"
	"sync"

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

// Node is one simulated node. It keeps its state and its generation across streams, like a
// node that keeps forwarding on its last applied generation while no controller is reachable.
type Node struct {
	Key           keys.Static // the node's static key
	Controller    string      // host:port of the controller's port
	ControllerKey []byte      // the controller's static public key
	// Version is the schema version of the Hello, SCHEMA_VERSION_1 when it is unspecified.
	Version controlpb.SchemaVersion
	// Capabilities are the ones the Hello reports for the simulated host (ADR-0033); nil
	// reports none.
	Capabilities *controlpb.Capabilities
	// Updates receives every update the node applied, after the node sent its Ack. When it is
	// nil, nothing is delivered.
	Updates chan *controlpb.Update

	mu     sync.Mutex
	state  desired.State
	gen    uint64
	frames []Frame
}

// Run opens one control stream and serves it: the Hello, then each Update applied and
// acknowledged. It returns when the stream ends, with a *RefusedError if the controller refused
// the node, or when ctx ends.
func (n *Node) Run(ctx context.Context) error {
	conn, err := control.Dial(ctx, n.Controller, n.Key, n.ControllerKey)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()

	version := n.Version
	if version == controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED {
		version = controlpb.SchemaVersion_SCHEMA_VERSION_1
	}
	n.mu.Lock()
	hello := &controlpb.Hello{SchemaVersion: version, AppliedGeneration: n.gen, Capabilities: n.Capabilities}
	n.mu.Unlock()
	if err := n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: hello}}); err != nil {
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
			if n.Updates != nil {
				select {
				case n.Updates <- body.Update:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		case *controlpb.ControlMessage_Refuse:
			return &RefusedError{Refuse: body.Refuse}
		default:
			return errors.New("nodesim: the controller sent a frame that is neither an Update nor a Refuse")
		}
	}
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
	n.mu.Lock()
	defer n.mu.Unlock()
	n.frames = append(n.frames, f)
}
