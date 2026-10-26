//go:build !windows

package certgen

// FindInStore returns ErrNoStore.
func FindInStore(thumbprint string) (StoredCertificate, error) {
	return StoredCertificate{}, ErrNoStore
}
