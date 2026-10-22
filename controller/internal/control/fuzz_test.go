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

// FuzzRead reads the input as the frames of a control stream, as Conn.Read reads them after the
// handshake: a 4-byte big-endian length and one ControlMessage, until the input ends. A message
// that decodes must encode again.
func FuzzRead(f *testing.F) {
	hello, err := proto.MarshalOptions{Deterministic: true}.Marshal(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: &controlpb.Hello{
		SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, AppliedGeneration: 7,
	}}})
	if err != nil {
		f.Fatal(err)
	}
	var seed bytes.Buffer
	if err := writeFrame(&seed, hello); err != nil {
		f.Fatal(err)
	}
	if err := writeFrame(&seed, nil); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x08})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		for {
			b, err := readFrame(r, MaxFrame)
			if err != nil {
				return
			}
			m := &controlpb.ControlMessage{}
			if err := proto.Unmarshal(b, m); err != nil {
				continue
			}
			if _, err := proto.Marshal(m); err != nil {
				t.Fatalf("a frame that decodes does not encode again: %v", err)
			}
		}
	})
}
