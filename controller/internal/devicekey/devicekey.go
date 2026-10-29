// Package devicekey holds the cryptography of the keys of the WireGuard Devices (SDN-82 #377, spec #374):
// the key pair that the controller makes for a Device, and the QR code of the finished configuration of a
// Device. The controller (internal/controller, devicekeys.go) decides what it keeps and what it shows, and
// this package works on the bytes, so each part has its tests apart from the controller. The PresharedKey of
// a Device is no part of it: the controller seals it with the Sealer of its store (internal/keys), as it
// seals the secrets of its targets.
package devicekey

import (
	"crypto/ecdh"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
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
