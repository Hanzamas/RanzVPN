package activation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// The Enterprise feature blob (ADR-0036 amendment of 2026-10-22, SEC-6 #285). The Enterprise
// feature code or data ships sealed in the release, and opens only with the feature key that the
// activation service holds and releases against an Enterprise token (handleFeatureKey). The key
// reaches the install in memory only (Install.featureKey), so a release without an Enterprise
// activation carries the blob but cannot open it.
//
// The seal is AES-256-GCM under a key derived from the feature key by SHA-256, so a feature key of
// any length (the service holds an arbitrary secret) seals and opens the blob, and the random nonce
// is prefixed to the ciphertext.

// featureAEAD returns the AES-256-GCM AEAD under a key derived from the feature key by SHA-256.
func featureAEAD(featureKey []byte) (cipher.AEAD, error) {
	if len(featureKey) == 0 {
		return nil, errors.New("activation: no feature key to seal the Enterprise blob with")
	}
	sum := sha256.Sum256(featureKey)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	return cipher.NewGCM(block)
}

// SealFeature seals the Enterprise feature blob plaintext under the feature key. The vendor seals
// the Enterprise feature this way and ships the sealed blob in the release; the blob opens only with
// the same feature key, which the activation service holds and releases against an Enterprise token.
func SealFeature(featureKey, plaintext []byte) ([]byte, error) {
	aead, err := featureAEAD(featureKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenFeature opens a blob sealed by SealFeature with the feature key. A wrong or absent key fails,
// so the Enterprise feature stays sealed without the server-held key.
func OpenFeature(featureKey, blob []byte) ([]byte, error) {
	aead, err := featureAEAD(featureKey)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, fmt.Errorf("%w: the sealed feature blob is shorter than a nonce", ErrInvalid)
	}
	nonce, ciphertext := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: the Enterprise feature blob does not open with this key", ErrInvalid)
	}
	return plaintext, nil
}
