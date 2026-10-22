package control

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// The known answers of the envelopes, the same as in coretest's envelope test of the C node
// (src/coretest/envelope.c), computed by an implementation of the Noise framework that is neither:
// a signal from branch-1 (the scalar 1, 2, ..., 32) to branch-2 (33, 34, ...) and a bind from
// branch-1 to the relay of the scalar 129, 130, ..., each with the ephemeral scalar 97, 98, ...
const (
	signalPayload  = "01010102030405060708883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c7700000000000000000000ffffc000020a1b58020100000000000000000000ffff0a00000213880200000000000000000000ffffc63364079c41"
	signalEnvelope = "0407a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49529bf345ba812669a43343fe55f5bdebfa1fd20846a6b5d96b0efe2ebaabc1b2f8e61fd05853d2e30edaa0107cab08f15d22975a1970ba0956de502d94c629a92543f49c5206a51e61b47e1c6263a7345cae0aa14d13bfd2d6f1f2049ea5a1ef584e6d2014829b4ea20ba9afc1f865290e2a82"
	bindPayload    = "011122334455667788"
	bindEnvelope   = "0207a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad498b4b5ccb906d23b5b95c9a9b3beeb6779a7126787517d53658"
)

// fixed returns the 32 bytes first, first+1, ...
func fixed(first byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func fixedSoft(t *testing.T, first byte) *keys.Soft {
	t.Helper()
	k, err := keys.NewSoft(fixed(first))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEnvelopeKnownAnswer seals the signal and the bind of the known answers with flynn/noise and
// gets the bytes that the C node seals, then opens them.
func TestEnvelopeKnownAnswer(t *testing.T) {
	sender, receiver, relay := fixedSoft(t, 1), fixedSoft(t, 33), fixedSoft(t, 129)

	env, err := Seal(KindSignal, sender, receiver.Public(), unhex(t, signalPayload), bytes.NewReader(fixed(97)))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(env); got != signalEnvelope {
		t.Errorf("the signal envelope is\n%s\nwant\n%s", got, signalEnvelope)
	}
	from, payload, err := Open(KindSignal, env, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(from, sender.Public()) || hex.EncodeToString(payload) != signalPayload {
		t.Errorf("the receiver opened sender %x and payload %x", from, payload)
	}

	env, err = Seal(KindBind, sender, relay.Public(), unhex(t, bindPayload), bytes.NewReader(fixed(97)))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(env); got != bindEnvelope {
		t.Errorf("the bind envelope is\n%s\nwant\n%s", got, bindEnvelope)
	}
	if _, payload, err := Open(KindBind, env, relay); err != nil || hex.EncodeToString(payload) != bindPayload {
		t.Errorf("the relay opened %x, %v", payload, err)
	}
}

// TestEnvelopeRefusals checks that an envelope with any bit flipped, of another kind, for another
// node, or forged in another node's name does not open.
func TestEnvelopeRefusals(t *testing.T) {
	sender, receiver, other := fixedSoft(t, 1), fixedSoft(t, 33), fixedSoft(t, 65)
	payload := unhex(t, signalPayload)
	env, err := Seal(KindSignal, sender, receiver.Public(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range env {
		for bit := 0; bit < 8; bit++ {
			altered := bytes.Clone(env)
			altered[i] ^= 1 << bit
			if _, _, err := Open(KindSignal, altered, receiver); err == nil {
				t.Fatalf("an envelope with bit %d of byte %d flipped opens", bit, i)
			}
		}
	}
	if _, _, err := Open(KindBind, env, receiver); err == nil {
		t.Error("a signal opens as a bind")
	}
	if _, _, err := Open(KindSignal, env, other); err == nil {
		t.Error("a node other than the receiver opens the envelope")
	}
	if _, _, err := Open(KindSignal, env[:len(env)-1], receiver); err == nil {
		t.Error("a truncated envelope opens")
	}

	// other seals with sender's public key in the envelope
	forged := bytes.Clone(env)
	sealed, err := Seal(KindSignal, other, receiver.Public(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	copy(forged, sealed)
	copy(forged[1:envelopeHeader], sender.Public())
	if _, _, err := Open(KindSignal, forged, receiver); err == nil {
		t.Error("an envelope forged in the sender's name opens")
	}

	// A fresh ephemeral key for every envelope
	again, err := Seal(KindSignal, sender, receiver.Public(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again[envelopeHeader:envelopeHeader+32], env[envelopeHeader:envelopeHeader+32]) {
		t.Error("two envelopes have the same ephemeral key")
	}
}
