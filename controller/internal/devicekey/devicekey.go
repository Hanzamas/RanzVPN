// Package devicekey holds the cryptography of the keys of the WireGuard Devices (SDN-82 #377, spec #374):
// the key pair that the controller makes for a Device, the seal that keeps the PresharedKey of a Device
// at rest, and the QR code of the finished configuration of a Device. The controller (internal/controller,
// devicekeys.go) decides what it keeps and what it shows, and this package works on the bytes, so each
// part has its tests, and the one that reads stored bytes its fuzz test, apart from the controller.
package devicekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// NewPair draws a WireGuard key pair from random: a private key clamped as wg genkey writes one, and
// its public key, KeySize bytes each. The caller wipes the private key when it is done with it.
func NewPair(random io.Reader) (private, public []byte, err error) {
	private = make([]byte, intent.KeySize)
	if _, err := io.ReadFull(random, private); err != nil {
		return nil, nil, err
	}
	private[0] &= 248
	private[31] = private[31]&127 | 64
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		clear(private)
		return nil, nil, err
	}
	return private, k.PublicKey().Bytes(), nil
}

// sealLabel names the point that the static key of the controller does its Diffie-Hellman with, after a
// hash, to give the key that seals the PresharedKeys: only the holder of the static key finds the shared
// secret, the controller asks the key storage provider for it instead of reading the key, and nothing of
// it is stored. The node derives its WireGuard key the same way (NodeWireGuard.c).
const sealLabel = "ranz controller: the key that seals the PresharedKeys of the Devices, version 1"

// sealInfo is the HKDF context of the AES key, and sealVersion the first byte of a sealed key.
const (
	sealInfo    = "ranz controller device keys, AES-256-GCM"
	sealVersion = 1
)

// A Sealer seals the PresharedKeys of the Devices and opens them again: AES-256-GCM under a key that
// comes from the static key of the controller by a Diffie-Hellman with a fixed point and HKDF, so the
// store, a backup of it or a copy of the disk does not give a PresharedKey. The additional data of a
// sealed key is the name of its Device, so a sealed key moved to another Device does not open. A Sealer
// is safe for concurrent use.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer returns the Sealer under the key that the static key gives. The static key may sit in the
// key storage provider: the Sealer asks it for the Diffie-Hellman and never reads the key.
func NewSealer(key keys.Static) (*Sealer, error) {
	if key == nil {
		return nil, errors.New("the controller has no static key")
	}
	point := sha256.Sum256([]byte(sealLabel))
	shared, err := key.DH(point[:])
	if err != nil {
		return nil, fmt.Errorf("the static key of the controller gives no secret to derive the sealing key from: %w", err)
	}
	defer clear(shared)
	secret, err := hkdf.Key(sha256.New, shared, nil, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// additional returns the additional data of the sealed key of the Device name.
func additional(name string) []byte {
	return []byte("ranz device preshared key\x00" + name)
}

// Seal seals the PresharedKey psk of the Device name: the version, a nonce that random draws and the
// ciphertext with its tag. random must never repeat a nonce under one key, so it is a source of true
// random bytes, crypto/rand.
func (s *Sealer) Seal(name string, psk []byte, random io.Reader) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	sealed := append([]byte{sealVersion}, nonce...)
	return s.aead.Seal(sealed, nonce, psk, additional(name)), nil
}

// Open returns the PresharedKey that Seal sealed for the Device name. It fails for a key of another
// version, one that is altered in any byte, one that was sealed for another Device and one that another
// static key sealed.
func (s *Sealer) Open(name string, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < 1+n+s.aead.Overhead() || sealed[0] != sealVersion {
		return nil, errors.New("not a sealed PresharedKey of this version")
	}
	psk, err := s.aead.Open(nil, sealed[1:1+n], sealed[1+n:], additional(name))
	if err != nil {
		return nil, errors.New("the sealed PresharedKey does not open: another static key sealed it, or it was altered")
	}
	return psk, nil
}
