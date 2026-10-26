//go:build windows

package servercert

import (
	"crypto/tls"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// loadKSP returns the certificate with the SHA-1 thumbprint of the My store of the host, with its key
// in the Microsoft Software Key Storage Provider: the key stays there, and the provider signs for
// the handshake. The key must be an ECDSA P-256 key, which `ranz cert -ksp` makes, and the account
// that runs the Controller must be allowed to use it.
func loadKSP(thumbprint string) (tls.Certificate, error) {
	stored, err := certgen.FindInStore(thumbprint)
	if err != nil {
		return tls.Certificate{}, refuse("%v", err)
	}
	key, err := keys.LoadKSP(stored.Key, stored.Machine)
	if err != nil {
		return tls.Certificate{}, refuse("the key %q of the certificate cannot be used in the key storage provider (the account that runs the Controller must be allowed to use it, and it must be an ECDSA P-256 key): %v", stored.Key, err)
	}
	return pair([][]byte{stored.DER}, key)
}
