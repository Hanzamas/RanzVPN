//go:build !windows

package controllercmd

import "github.com/Hanzamas/RanzVPN/controller/internal/servercert"

// ReadFingerprint returns the TLS fingerprint in servercert.FingerprintFile of the data directory dir, as
// servercert.ReadFingerprint reads it. The check of who may have written the file is the one of Windows
// (AUD1-DT-14), where C:\ProgramData lets every user make the folder; elsewhere the data directory of the
// service is /var/lib/ranz-controller, which only root can make, and makeDataDir makes it with mode 0700.
func ReadFingerprint(dir string) (string, error) {
	return servercert.ReadFingerprint(dir)
}
