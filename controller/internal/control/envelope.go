package control

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// The envelopes of the peer layer of the C node (src/Core/PeerSignal.c, ADR-0015): a bind, a
// bound or a signal, sealed by the sending node's static key to the receiving node's with the
// Noise one-way pattern K, Noise_K_25519_AESGCM_SHA256. Only the receiving node can open one, and
// only the holder of the sender's private key can make one. An envelope is its kind, the sender's
// static public key, then the one message of K: the ephemeral public key, the ciphertext of the
// payload and the tag. The prologue is envelopePrologue followed by the kind. The controller
// carries signals between nodes (Signal) without opening them; the node simulator seals and opens
// them here, and the C node and this file hold one known answer (envelope_test.go).
const (
	// KindBind is the kind of a bind: a node binds to a relay.
	KindBind = 2
	// KindBound is the kind of a bound: the relay's answer.
	KindBound = 3
	// KindSignal is the kind of a signal: a node's relay assignment and ICE candidates for a peer.
	KindSignal = 4
	// MaxEnvelope is the largest envelope (Signal.envelope of control.options).
	MaxEnvelope = 1024

	envelopePrologue = "ranz peer 1"
	// envelopeHeader is the kind and the sender's static key; envelopeTag the AES-GCM tag.
	envelopeHeader = 1 + 32
	envelopeTag    = 16
)

// envelopeState is the Noise handshake state of one envelope of kind, with the static key key and
// the other end's static public key peer.
func envelopeState(kind byte, key keys.Static, peer []byte, initiator bool, random io.Reader) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(staticDH{key: key}, noise.CipherAESGCM, noise.HashSHA256),
		Random:        random,
		Pattern:       noise.HandshakeK,
		Initiator:     initiator,
		Prologue:      append([]byte(envelopePrologue), kind),
		StaticKeypair: noise.DHKey{Private: staticMarker, Public: key.Public()},
		PeerStatic:    peer,
	})
}

// Seal returns the envelope of kind that carries payload from the node of the static key key to
// the node of the static public key peer. random draws the ephemeral key; crypto/rand when nil.
func Seal(kind byte, key keys.Static, peer, payload []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	hs, err := envelopeState(kind, key, peer, true, random)
	if err != nil {
		return nil, fmt.Errorf("control: envelope: %w", err)
	}
	env := append([]byte{kind}, key.Public()...)
	env, _, _, err = hs.WriteMessage(env, payload)
	if err != nil {
		return nil, fmt.Errorf("control: envelope: %w", err)
	}
	if len(env) > MaxEnvelope {
		return nil, fmt.Errorf("control: an envelope of %d bytes is larger than %d", len(env), MaxEnvelope)
	}
	return env, nil
}

// Open returns the sender's static public key and the payload of the envelope env of kind for the
// node of the static key key. It fails for an envelope of another kind, and for one that is
// forged, altered in any byte or sealed for another node.
func Open(kind byte, env []byte, key keys.Static) (sender, payload []byte, err error) {
	if len(env) < envelopeHeader+32+envelopeTag || len(env) > MaxEnvelope {
		return nil, nil, fmt.Errorf("control: an envelope of %d bytes", len(env))
	}
	if env[0] != kind {
		return nil, nil, fmt.Errorf("control: an envelope of kind %d, not %d", env[0], kind)
	}
	sender = bytes.Clone(env[1:envelopeHeader])
	hs, err := envelopeState(kind, key, sender, false, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("control: envelope: %w", err)
	}
	payload, _, _, err = hs.ReadMessage(nil, env[envelopeHeader:])
	if err != nil {
		return nil, nil, errors.New("control: the envelope does not open: forged, altered or for another node")
	}
	return sender, payload, nil
}
