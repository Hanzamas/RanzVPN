//go:build !windows

package servercert

import (
	"crypto/tls"
)

// loadKSP refuses: the key storage and the certificate store of Windows exist on Windows only.
func loadKSP(thumbprint string) (tls.Certificate, error) {
	return tls.Certificate{}, refuse("a certificate of the key storage can be served on Windows only: use a file or ACME on this host (%s)", thumbprint)
}
