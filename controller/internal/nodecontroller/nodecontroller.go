// Package nodecontroller holds the Controller settings of a Node (SDN-90, #395): the address of the
// Controller's TLS port, its static key and the TLS fingerprint of its certificate, the three values
// that `ranz status` prints on the Controller. `ranz node controller set` checks them with Parse
// before the Node service keeps them in its Configuration store, and the node simulator checks the
// certificate of the Controller with CheckFingerprint, as the Node does.
package nodecontroller

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// KeySize is the size of the static key of a Controller: an X25519 public key.
const KeySize = 32

// Settings are the Controller settings of a Node, in the JSON form of the Node service and of
// `ranz node controller show`.
type Settings struct {
	// Address is host:port of the Controller's TLS port, as a Node reaches it.
	Address string `json:"address"`
	// PublicKey is the base64 of the Controller's static key (publicKey of `ranz status`).
	PublicKey string `json:"publicKey"`
	// TLSFingerprint is the hex SHA-256 of the SubjectPublicKeyInfo of the Controller's TLS
	// certificate (tlsFingerprint of `ranz status`), in lower case.
	TLSFingerprint string `json:"tlsFingerprint"`
}

// Parse checks the three values of the Controller settings and returns them in the form the Node
// keeps: the key in standard base64, the fingerprint in lower case. Its error says which value is
// wrong: an address without a port, a key that is not the base64 of 32 bytes, or a fingerprint
// that is not 64 hex digits.
func Parse(address, publicKey, fingerprint string) (Settings, error) {
	if err := checkAddress(address); err != nil {
		return Settings{}, err
	}
	key, err := parseKey(publicKey)
	if err != nil {
		return Settings{}, err
	}
	fp, err := parseFingerprint(fingerprint)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Address: address, PublicKey: base64.StdEncoding.EncodeToString(key), TLSFingerprint: fp}, nil
}

// Key returns the Controller's static key of settings that Parse returned.
func (s Settings) Key() []byte {
	key, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil || len(key) != KeySize {
		return nil
	}
	return key
}

func checkAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("the address %q of the Controller has no port: give host:port, as the TLS port of ranz status on the Controller, for example 192.168.1.10:443", address)
	}
	if host == "" {
		return fmt.Errorf("the address %q of the Controller has no host: give host:port, for example 192.168.1.10:443", address)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the port %q of the address %q of the Controller is not a number from 1 to 65535", port, address)
	}
	return nil
}

func parseKey(publicKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, fmt.Errorf("the static key %q of the Controller is not base64: give publicKey of ranz status on the Controller", publicKey)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("the static key of the Controller is %d bytes long, not %d: give publicKey of ranz status on the Controller", len(key), KeySize)
	}
	return key, nil
}

func parseFingerprint(fingerprint string) (string, error) {
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if len(fp) != 2*sha256.Size {
		return "", fmt.Errorf("the TLS fingerprint %q of the Controller is not 64 hex digits: give tlsFingerprint of ranz status on the Controller", fingerprint)
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", fmt.Errorf("the TLS fingerprint %q of the Controller is not 64 hex digits: give tlsFingerprint of ranz status on the Controller", fingerprint)
	}
	return fp, nil
}

// Fingerprint returns the TLS fingerprint of a certificate: the hex SHA-256 of its
// SubjectPublicKeyInfo, as the Controller prints it (keys.Fingerprint).
func Fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// ErrFingerprint is the error of CheckFingerprint for a certificate of another key.
var ErrFingerprint = errors.New("the TLS fingerprint check failed")

// CheckFingerprint checks the TLS session st against the fingerprint of the Controller settings, as
// tls.Config.VerifyConnection: the leaf certificate that the Controller presented must have it. Its
// error wraps ErrFingerprint and names both fingerprints.
func CheckFingerprint(st tls.ConnectionState, fingerprint string) error {
	if len(st.PeerCertificates) == 0 {
		return fmt.Errorf("%w: the Controller presented no certificate", ErrFingerprint)
	}
	got := Fingerprint(st.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if got != strings.ToLower(fingerprint) {
		return fmt.Errorf("%w: the certificate of the Controller has the TLS fingerprint %s, not %s of the Controller settings", ErrFingerprint, got, strings.ToLower(fingerprint))
	}
	return nil
}
