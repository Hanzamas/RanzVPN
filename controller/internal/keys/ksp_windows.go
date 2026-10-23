//go:build windows

package keys

import (
	"crypto"
	"errors"
	"fmt"
)

// kspFlags are the flags of the key set that a key of the provider lives in: the machine key set
// when machine is set, which needs the rights of an administrator, else the key set of the user of
// the process.
func kspFlags(machine bool) uint32 {
	if machine {
		return machineKeyFlag
	}
	return 0
}

// CreateKSP creates the ECDSA P-256 key name in the Microsoft Software Key Storage Provider and
// returns it as the crypto.Signer that crypto/x509 and crypto/tls sign with: the provider makes the
// signature, and the key is not exportable (ADR-0022: certificate keys live in a CNG key storage
// provider). It fails when the provider holds a key of that name, which may belong to another
// certificate. As the keys of Load do, the handles stay open for the life of the process.
func CreateKSP(name string, machine bool) (crypto.Signer, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	existing, err := openKey(prov, name, kspFlags(machine))
	if err == nil {
		freeObject(existing)
		freeObject(prov)
		return nil, fmt.Errorf("keys: the provider holds a key named %q already", name)
	}
	if !errors.Is(err, errBadKeyset) {
		freeObject(prov)
		return nil, fmt.Errorf("keys: the key %q: %w", name, err)
	}
	h, err := createKey(prov, name, algECDSAP256, "", kspFlags(machine), 0)
	if err != nil {
		freeObject(prov)
		return nil, fmt.Errorf("keys: the key %q: %w", name, err)
	}
	signer, err := newKSPSigner(h)
	if err != nil {
		// The key was persisted when it was finalized: a key that nothing can use goes again
		if derr := deleteKey(h); derr != nil {
			freeObject(h)
		}
		freeObject(prov)
		return nil, err
	}
	return signer, nil
}

// LoadKSP returns the ECDSA P-256 key name of the Microsoft Software Key Storage Provider, from
// the key set that CreateKSP made it in, as a crypto.Signer.
func LoadKSP(name string, machine bool) (crypto.Signer, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	h, err := openKey(prov, name, kspFlags(machine))
	if err != nil {
		freeObject(prov)
		return nil, fmt.Errorf("keys: the key %q: %w", name, err)
	}
	signer, err := newKSPSigner(h)
	if err != nil {
		freeObject(h)
		freeObject(prov)
		return nil, err
	}
	return signer, nil
}

// DeleteKSP deletes the key name of the Microsoft Software Key Storage Provider, from the key set
// that CreateKSP made it in. A Signer that CreateKSP or LoadKSP returned for it is of no use after.
func DeleteKSP(name string, machine bool) error {
	prov, err := openProvider()
	if err != nil {
		return err
	}
	defer freeObject(prov)
	h, err := openKey(prov, name, kspFlags(machine))
	if err != nil {
		return fmt.Errorf("keys: the key %q: %w", name, err)
	}
	if err := deleteKey(h); err != nil {
		freeObject(h)
		return err
	}
	return nil
}
