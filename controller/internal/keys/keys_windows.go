//go:build windows

package keys

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sealedKeyFile is the Noise static key in the data directory, sealed with DPAPI.
const sealedKeyFile = "controller.key.dpapi"

// dpapiEntropy is the optional entropy of the sealed key, so that a blob another program sealed
// with the machine key does not open as the controller key.
var dpapiEntropy = []byte("ranz-controller noise static key")

// Load returns the controller's keys for the data directory dataDir, creating them the first
// time. The controller follows ADR-0022, which keeps the node identity key in a CNG key storage
// provider:
//
//   - The TLS key is an ECDSA P-256 key of the Microsoft Software Key Storage Provider, machine
//     scope and not exportable, named after the data directory (tlsKeyName). It signs inside the
//     provider and never enters the controller's memory.
//   - The Noise static key is X25519, which that provider does not keep as a persisted key (CI
//     records what it answers: TestKSPX25519Probe). It is the file controller.key.dpapi in the
//     data directory, sealed with DPAPI in machine scope (CryptProtectData), which the directory's
//     ACL keeps to SYSTEM, the Administrators and its owner; the controller opens it at start.
//
// Machine-scope keys need the rights of an administrator or of LocalSystem, the account of the
// service.
func Load(dataDir string) (Static, crypto.Signer, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, nil, err
	}
	// The provider handle stays open with the key handle, for the life of the process.
	h, err := openOrCreate(prov, tlsKeyName(dataDir), algECDSAP256, "")
	if err != nil {
		freeObject(prov)
		return nil, nil, fmt.Errorf("keys: the TLS key %q: %w", tlsKeyName(dataDir), err)
	}
	signer, err := newKSPSigner(h)
	if err != nil {
		return nil, nil, err
	}
	static, err := loadSealed(filepath.Join(dataDir, sealedKeyFile))
	if err != nil {
		return nil, nil, err
	}
	return static, signer, nil
}

// tlsKeyName is the provider name of the TLS key of the data directory dir: one key per data
// directory, so two controllers on one host keep apart keys.
func tlsKeyName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(abs))))
	return "Ranz controller TLS " + hex.EncodeToString(sum[:8])
}

// removeTLSKey deletes the TLS key of the data directory dir from the provider (tests).
func removeTLSKey(dir string) error {
	prov, err := openProvider()
	if err != nil {
		return err
	}
	defer freeObject(prov)
	h, err := openKey(prov, tlsKeyName(dir), machineKeyFlag)
	if err != nil {
		return err
	}
	return deleteKey(h)
}

// loadSealed returns the static key that the file path holds sealed, and creates the file with a
// new key if it does not exist yet.
func loadSealed(path string) (*Soft, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := GenerateSoft()
		if err != nil {
			return nil, err
		}
		sealed, err := dpapi(k.Private(), true)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, sealed, 0o600); err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	priv, err := dpapi(b, false)
	if err != nil {
		return nil, fmt.Errorf("keys: %s: %w", path, err)
	}
	return NewSoft(priv)
}

// dpapi seals data with DPAPI in machine scope (protect), or opens a sealed blob.
func dpapi(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("keys: DPAPI: no data")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, fmt.Errorf("keys: DPAPI: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}
