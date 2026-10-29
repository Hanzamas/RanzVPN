package control

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// The limits of the frames that a node sends the controller (CS-4 of docs/threat-model.md,
// AUD1-DT-2 #450). The controller reads little before it knows the Node: the first frame of a
// stream, the Hello, has a limit of its own, and each frame of a Node that the controller admitted
// has the limit of its kind. The limits sit beside proto/ranz/control/v1/control.options, which
// sizes the messages of the C node: each one is above the largest frame that the sizes of that file
// allow for its kind, so a node that keeps to them never meets one, and TestLimitsHoldTheOptions
// computes those frames from the file and fails when a size outgrows its limit. Raise a limit with
// the size.
const (
	// MaxHello is the largest Hello. The largest that a node can make is 91 bytes: the schema version,
	// the generation applied last and the Capabilities, whose largest field is the 32-byte key of the
	// WireGuard interface.
	MaxHello = 1 << 10
	// MaxAck is the largest Ack. The generation is a varint of 10 bytes at most, so an Ack is 13 bytes
	// at most.
	MaxAck = 64
	// MaxSignal is the largest Signal: the name of a peer, 63 characters at most (Signal.peer), and an
	// envelope of MaxEnvelope bytes (Signal.envelope), about 1.1 kB.
	MaxSignal = MaxEnvelope + 1<<10
	// MaxTelemetry is the largest Telemetry message: the counters of 64 peers, 16 VRFs, 32 rules and
	// 64 Devices, 32 flow records and 8 events, and the BGP peering of the standard mode, 64 peers with
	// 32 learned prefixes each (Telemetry of control.options; SDN-77), about 106 kB.
	MaxTelemetry = 112 << 10
	// MaxLeases is the largest Leases message: the 1024 leases of one responder (Leases.leases of
	// control.options), about 95 kB.
	MaxLeases = 128 << 10
	// MaxOperationResult is the largest OperationResult (SDN-50): the 512 entries of one table
	// (OperationResult.entries of control.options) and the 256 characters of its message, about 57 kB.
	MaxOperationResult = 64 << 10
	// MaxPins is the largest Pins message (SDN-94): the 32-byte public key of the mimic server of the node
	// (Pins.mimic_key of control.options), 36 bytes with its tag and lengths.
	MaxPins = 64
)

const (
	// The kind of a frame that a node sends after its Hello is told by the first byte of the frame:
	// the tag of its one field, a field of ControlMessage.body (control.proto) of the wire type of a
	// message. TestLimitsHoldTheOptions checks the numbers against the schema.
	fieldAck       = 3
	fieldSignal    = 5
	fieldTelemetry = 7
	fieldLeases    = 8
	// fieldOperationResult is the field of the answer of a node to an Operation (SDN-50)
	fieldOperationResult = 10
	// fieldPins is the field of the keys that a node reports about itself (SDN-94)
	fieldPins = 11

	// frameChunk is the size by which a frame grows as its bytes arrive, which makes it the small
	// buffer that a stream holds beyond the bytes that its peer sent (readFrame).
	frameChunk = 4 << 10
)

// ErrFrameTooLarge is wrapped by the error of Conn.Read for a frame that is larger than the limit of
// its place in the stream: the Hello of a node, a frame of a kind of a node, or a frame of the
// controller. Of such a frame the length is read, and the first byte when the limit depends on the
// kind, and nothing more.
var ErrFrameTooLarge = errors.New("control: a frame is larger than its limit")

// frameLimit is how large the next frame of a stream may be.
type frameLimit struct {
	// max is the largest frame of any kind: a length above it fails before a byte of the frame is read.
	max int
	// what names the frame in the error of one that is over max.
	what string
	// kind, when it is not nil, gives the limit of the frame that starts with the byte first, which
	// tells its kind, and the name of that kind. It is asked once the first byte of the frame is read.
	kind func(first byte) (limit int, what string)
}

var (
	// handshakeFrame limits the messages of the Noise handshake.
	handshakeFrame = frameLimit{max: maxHandshakeFrame, what: "a Noise handshake message"}
	// controllerFrame limits the frames that a node takes from the controller: the largest is an
	// Update with the whole state of the node.
	controllerFrame = frameLimit{max: MaxFrame, what: "a frame of the controller"}
	// helloFrame limits the first frame that the controller takes from a node.
	helloFrame = frameLimit{max: MaxHello, what: "a Hello"}
	// nodeFrame limits the frames that the controller takes from a node after its Hello; MaxLeases is
	// the largest of the limits of the kinds.
	nodeFrame = frameLimit{max: MaxLeases, what: "a frame of a node", kind: nodeKind}
)

// nodeKind gives the limit of a frame that a node sends after its Hello, and what to call it, from
// the first byte of the frame. A frame of a kind that a node does not send there, a Hello again or a
// frame of the controller, is refused by the controller whatever it holds, so it gets the least
// limit, the one of a Hello.
func nodeKind(first byte) (limit int, what string) {
	if num, typ, n := protowire.ConsumeTag([]byte{first}); n > 0 && typ == protowire.BytesType {
		switch num {
		case fieldAck:
			return MaxAck, "an Ack"
		case fieldSignal:
			return MaxSignal, "a Signal"
		case fieldTelemetry:
			return MaxTelemetry, "a Telemetry message"
		case fieldLeases:
			return MaxLeases, "a Leases message"
		case fieldOperationResult:
			return MaxOperationResult, "an OperationResult"
		case fieldPins:
			return MaxPins, "a Pins message"
		}
	}
	return MaxHello, "a frame of a kind that a node does not send after its Hello"
}

// tooLarge is the error of a frame of n bytes, of the kind what, over its limit.
func tooLarge(n uint32, limit int, what string) error {
	return fmt.Errorf("%w: %s of %d bytes, and the limit is %d", ErrFrameTooLarge, what, n, limit)
}

// frame reads the next frame of the stream with the limit of its place in it: on the controller's end
// the Hello, then the frames of a node by their kind; on a node's end the frames of the controller.
// c.rmu is held.
func (c *Conn) frame() ([]byte, error) {
	switch {
	case !c.fromNode:
		return readFrame(c.r, controllerFrame)
	case !c.hello:
		b, err := readFrame(c.r, helloFrame)
		c.hello = err == nil
		return b, err
	default:
		return readFrame(c.r, nodeFrame)
	}
}
