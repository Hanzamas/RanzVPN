//go:build !windows

package payload

import "errors"

// verifyAuthenticode always refuses: Authenticode signatures are a Windows concept, and ranz
// install (internal/install) exists only on Windows, so a payload is never written on this OS.
func verifyAuthenticode(string) error {
	return errors.New("payload: Authenticode verification is only available on Windows")
}
