//go:build !windows

package payload

import "errors"

// verifyAuthenticode always refuses: Authenticode signatures are a Windows concept, and ranz
// install (internal/install) exists only on Windows, so a payload is never written on this OS.
func verifyAuthenticode(string) error {
	return errors.New("payload: Authenticode verification is only available on Windows")
}

// verifyCatalogMember always refuses, for the same reason: a catalog is checked by Windows.
func verifyCatalogMember(string, string) error {
	return errors.New("payload: catalog verification is only available on Windows")
}
