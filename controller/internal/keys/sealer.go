package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
)

// The sealing of the secrets that the controller's store holds (AUD1-DT-10, #458). The store keeps
// the secrets of its export and audit targets, the HMAC key of a webhook and the bearer token of an
// OTLP endpoint, and a backup of the store holds them too. A Sealer keeps them in a form that only
// the controller's own key opens, a key of the key storage provider on Windows whose private half
// never leaves it: whoever reads the disk, a snapshot of the machine or a backup reads sealed text,
// not the secrets.
//
// The seal is a sealed box. Seal makes an X25519 key pair for each secret, agrees a secret with the
// public key of the sealing key, derives an AES-256-GCM key from it by HKDF-SHA256 and forgets the
// private half of the pair. Open asks the sealing key for the same agreement (Static.DH, which runs
// inside the provider on Windows), so sealing needs the public key and opening needs the private
// one. The label of a secret names where the store keeps it and is authenticated with it, so a sealed
// secret that is copied to another row does not open there.

// sealInfo is the context of the key derivation, so that no other use of an X25519 key of the
// controller gives the same keys.
const sealInfo = "ranz controller store secret v1"

// The parts of a sealed secret: the public key of the pair that sealed it, the nonce, and the
// ciphertext with its tag.
const (
	sealedKeyLen   = 32
	sealedNonceLen = 12
	sealedTagLen   = 16
)

// ErrNotSealed marks bytes that this key did not seal under that label: a secret of another host, of
// another label, one that was changed, or no sealed secret at all.
var ErrNotSealed = errors.New("keys: not a secret that this key sealed under this label")

// Sealer seals secrets to a key of the controller and opens them with it.
type Sealer struct {
	key Static
}

// NewSealer returns the Sealer of the sealing key key.
func NewSealer(key Static) *Sealer {
	return &Sealer{key: key}
}

// sealAEAD returns the AES-256-GCM AEAD under the key that HKDF derives from the agreed secret
// shared, with the two public keys of the agreement as its salt.
func sealAEAD(shared, ephemeral, sealing []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, slices.Concat(ephemeral, sealing), sealInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return cipher.NewGCM(block)
}

// Seal seals plain under label and returns the sealed bytes: the public key of the pair that sealed
// them, the nonce and the ciphertext. Sealing the same secret twice gives different bytes.
func (s *Sealer) Seal(label string, plain []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(s.key.Public())
	if err != nil {
		return nil, fmt.Errorf("keys: the sealing key: %w", err)
	}
	pair, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	shared, err := pair.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	aead, err := sealAEAD(shared, pair.PublicKey().Bytes(), s.key.Public())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sealedNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	out := slices.Concat(pair.PublicKey().Bytes(), nonce)
	return aead.Seal(out, nonce, plain, []byte(label)), nil
}

// Open opens bytes that Seal made under label. Bytes that this key did not seal under that label, or
// that were changed, fail with ErrNotSealed.
func (s *Sealer) Open(label string, sealed []byte) ([]byte, error) {
	if len(sealed) < sealedKeyLen+sealedNonceLen+sealedTagLen {
		return nil, ErrNotSealed
	}
	pair, rest := sealed[:sealedKeyLen], sealed[sealedKeyLen:]
	shared, err := s.key.DH(pair)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSealed, err)
	}
	aead, err := sealAEAD(shared, pair, s.key.Public())
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, rest[:sealedNonceLen], rest[sealedNonceLen:], []byte(label))
	if err != nil {
		return nil, ErrNotSealed
	}
	return plain, nil
}
