//go:build !windows

package certgen

import "errors"

// ErrNoStore is what the functions for the certificate store return where there is none: off
// Windows.
var ErrNoStore = errors.New("certgen: the Windows certificate store exists on Windows only")

// InstallInStore returns ErrNoStore.
func InstallInStore(der []byte, keyName string, machine bool) error {
	return ErrNoStore
}

// RemoveFromStore returns ErrNoStore.
func RemoveFromStore(thumbprint string, machine bool) error {
	return ErrNoStore
}

// CheckStoredKey returns ErrNoStore.
func CheckStoredKey(thumbprint string, machine bool) error {
	return ErrNoStore
}
