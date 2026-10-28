//go:build windows

package keys

import "fmt"

// LoadSealer returns the Sealer of the controller's sealing key for the data directory dataDir,
// creating the key the first time. As the two keys of Load, it is a persisted key of the Microsoft
// Software Key Storage Provider that is not exportable, named after the data directory (keyName),
// and its Diffie-Hellman runs inside the provider, so the private key never enters the controller's
// memory. It is an X25519 key like the Noise static key, and a key of its own, so that what seals
// the store and what authenticates the control stream are never the same key. The key set is the one
// of keyScope: the machine key set for an administrator's process, the key set of the service's
// account for the service, so a secret that one of the two sealed is not one that the other opens.
func LoadSealer(dataDir string) (*Sealer, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	h, err := openOrCreate(prov, keyName("Store", dataDir), algECDH, curve25519)
	if err != nil {
		freeObject(prov)
		return nil, fmt.Errorf("keys: the sealing key %q: %w", keyName("Store", dataDir), err)
	}
	key, err := newKSPStatic(prov, h)
	if err != nil {
		freeObject(h)
		freeObject(prov)
		return nil, err
	}
	return NewSealer(key), nil
}
