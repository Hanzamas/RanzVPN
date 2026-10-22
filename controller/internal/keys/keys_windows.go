//go:build windows

package keys

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Load returns the controller's keys for the data directory dataDir, creating them the first
// time. The controller follows ADR-0022, which keeps the node identity key in a CNG key storage
// provider: both keys are persisted keys of the Microsoft Software Key Storage Provider, not
// exportable, named after the data directory (keyName), and both are used inside the provider, so
// neither private key enters the controller's memory.
//
//   - The Noise static key is an X25519 key (NCRYPT_ECDH_ALGORITHM with the curve25519 curve
//     name); its Diffie-Hellman is NCryptSecretAgreement (kspStatic).
//   - The TLS key is an ECDSA P-256 key; it signs with NCryptSignHash (kspSigner).
//
// Machine-scope keys need the rights of an administrator: an elevated process keeps the keys in
// the machine scope, and the service, which runs as its virtual account, in the key set of that
// account (keyScope).
func Load(dataDir string) (Static, crypto.Signer, error) {
	// The provider handle stays open with the key handles, for the life of the process.
	prov, err := openProvider()
	if err != nil {
		return nil, nil, err
	}
	hs, err := openOrCreate(prov, keyName("Noise", dataDir), algECDH, curve25519)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: the Noise static key %q: %w", keyName("Noise", dataDir), err)
	}
	static, err := newKSPStatic(prov, hs)
	if err != nil {
		return nil, nil, err
	}
	ht, err := openOrCreate(prov, keyName("TLS", dataDir), algECDSAP256, "")
	if err != nil {
		return nil, nil, fmt.Errorf("keys: the TLS key %q: %w", keyName("TLS", dataDir), err)
	}
	signer, err := newKSPSigner(ht)
	if err != nil {
		return nil, nil, err
	}
	return static, signer, nil
}

// keyName is the provider name of the kind key ("Noise" or "TLS") of the data directory dir: one
// key of each kind per data directory, so two controllers on one host keep apart keys.
func keyName(kind, dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(abs))))
	return "Ranz controller " + kind + " " + hex.EncodeToString(sum[:8])
}

// removeKeys deletes the keys of the data directory dir from the provider (tests).
func removeKeys(dir string) error {
	prov, err := openProvider()
	if err != nil {
		return err
	}
	defer freeObject(prov)
	var errs []error
	for _, kind := range []string{"Noise", "TLS"} {
		h, err := openKey(prov, keyName(kind, dir), keyScope())
		if err == nil {
			err = deleteKey(h)
		}
		if err != nil && !errors.Is(err, errBadKeyset) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
