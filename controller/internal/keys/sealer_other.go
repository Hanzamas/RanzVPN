//go:build !windows

package keys

import "path/filepath"

// LoadSealer returns the Sealer of the controller's sealing key for the data directory dataDir,
// creating the key the first time: an X25519 key in store.key, a file that only its owner can read.
func LoadSealer(dataDir string) (*Sealer, error) {
	key, err := LoadSoft(filepath.Join(dataDir, "store.key"))
	if err != nil {
		return nil, err
	}
	return NewSealer(key), nil
}
