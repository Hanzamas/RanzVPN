package control

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/flynn/noise"
)

// LoadKey reads a static key from path, or creates one there the first time. The file holds the
// base64 of the 32-byte X25519 private key and is readable by its owner only (on Windows, the
// directory's ACL protects it).
func LoadKey(path string) (noise.DHKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err := GenerateKey()
		if err != nil {
			return noise.DHKey{}, err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key.Private)+"\n"), 0o600); err != nil {
			return noise.DHKey{}, fmt.Errorf("control: writing the key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("control: reading the key: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("control: the key file %s does not hold base64: %w", path, err)
	}
	return PrivateKey(priv)
}

// PrivateKey returns the key pair of the X25519 private key priv.
func PrivateKey(priv []byte) (noise.DHKey, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("control: %w", err)
	}
	return noise.DHKey{Private: priv, Public: k.PublicKey().Bytes()}, nil
}
