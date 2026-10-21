//go:build !windows

package keys

import (
	"crypto"
	"path/filepath"
)

// Load returns the controller's keys from the data directory dataDir, creating them the first
// time: the Noise static key in controller.key and the ECDSA P-256 TLS key in tls.key, both
// files that only their owner can read.
func Load(dataDir string) (Static, crypto.Signer, error) {
	static, err := LoadSoft(filepath.Join(dataDir, "controller.key"))
	if err != nil {
		return nil, nil, err
	}
	tlsKey, err := loadTLSFile(filepath.Join(dataDir, "tls.key"))
	if err != nil {
		return nil, nil, err
	}
	return static, tlsKey, nil
}
