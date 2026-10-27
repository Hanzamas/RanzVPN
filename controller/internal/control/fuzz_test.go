package control

import (
	"bytes"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// The fuzz tests of the control package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the controller workflow runs with go test -fuzz.

// FuzzOpen opens the input as an envelope of each kind (Open) for the receiving node and the relay
// of the known answers, so that a seed is an envelope that opens.
func FuzzOpen(f *testing.F) {
	for _, s := range []string{signalEnvelope, bindEnvelope} {
		b, err := hex.DecodeString(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	receiver, err := keys.NewSoft(fixed(33))
	if err != nil {
		f.Fatal(err)
	}
	relay, err := keys.NewSoft(fixed(129))
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, env []byte) {
		for _, c := range []struct {
			kind byte
			key  keys.Static
		}{{KindSignal, receiver}, {KindBind, relay}, {KindBound, receiver}} {
			sender, payload, err := Open(c.kind, env, c.key)
			if err != nil {
				continue
			}
			if len(sender) != envelopeHeader-1 || len(payload) > len(env) {
				t.Fatalf("an envelope of %d bytes opens to a sender of %d bytes and a payload of %d", len(env), len(sender), len(payload))
			}
		}
	})
}

// FuzzRead reads the input as the frames of a control stream, as Conn.Read reads them on the
// controller's end after the handshake: a 4-byte big-endian length and one ControlMessage, until
// the input ends. The first frame is the Hello and has MaxHello bytes at most, each later frame the
// limit of its kind (limits.go), and a frame over its limit ends the input. A message that decodes
// must encode again.
func FuzzRead(f *testing.F) {
	var seed bytes.Buffer
	for _, m := range []*controlpb.ControlMessage{
		{Body: &controlpb.ControlMessage_Hello{Hello: &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, AppliedGeneration: 7}}},
		{Body: &controlpb.ControlMessage_Ack{Ack: &controlpb.Ack{Generation: 7}}},
		{Body: &controlpb.ControlMessage_Signal{Signal: &controlpb.Signal{Peer: "branch-2", Envelope: []byte{4, 1, 2, 3}}}},
		{Body: &controlpb.ControlMessage_Telemetry{Telemetry: &controlpb.Telemetry{Rules: []*controlpb.RuleCounters{{VrfId: 10, Rule: "default-allow-all", PacketCount: 22, ByteCount: 3300}}}}},
		{Body: &controlpb.ControlMessage_Leases{Leases: &controlpb.Leases{Network: "corp-lan", Leases: []*controlpb.Lease{{Mac: []byte{2, 0, 0, 0, 0, 1}, Address: []byte{10, 10, 0, 7}, ExpiresMs: 1760000000000, HostName: "laptop"}}}}},
	} {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		if err := writeFrame(&seed, b); err != nil {
			f.Fatal(err)
		}
	}
	if err := writeFrame(&seed, nil); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x08})
	// The length of a frame of 16 MiB, and of a Hello of one byte over its limit
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x04, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := &Conn{r: bytes.NewReader(data), fromNode: true}
		for first := true; ; first = false {
			m, b, err := c.Read()
			if err != nil {
				if b == nil {
					return
				}
				// A frame that is no message: the next one may be
				continue
			}
			limit := MaxHello
			if !first && len(b) > 0 {
				limit, _ = nodeKind(b[0])
			}
			if len(b) > limit {
				t.Fatalf("a frame of %d bytes was taken, over its limit of %d", len(b), limit)
			}
			if _, err := proto.Marshal(m); err != nil {
				t.Fatalf("a frame that decodes does not encode again: %v", err)
			}
		}
	})
}
