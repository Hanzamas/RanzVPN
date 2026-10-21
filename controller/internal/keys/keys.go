// Package keys holds the long-term keys of the controller: the Noise static key of the control
// stream and the key of the TLS certificate on its port (#176, ADR-0022). On Windows the
// controller keeps them out of plain files (keys_windows.go); on Linux, where the controller runs
// in CI only so far, they are files in the data directory that only their owner can read.
package keys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// Static is a Noise static key (X25519): its public half and the Diffie-Hellman with it. The
// private half may stay inside a key storage provider, so the handshake asks the key for the
// Diffie-Hellman instead of reading the private key.
type Static interface {
	Public() []byte
	DH(peer []byte) ([]byte, error)
}

// Soft is a static key held in memory.
type Soft struct {
	priv *ecdh.PrivateKey
}

// GenerateSoft returns a new random static key.
func GenerateSoft() (*Soft, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Soft{priv: k}, nil
}

// NewSoft returns the static key of the 32-byte X25519 private key priv.
func NewSoft(priv []byte) (*Soft, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return &Soft{priv: k}, nil
}

// Public returns the 32-byte public key.
func (k *Soft) Public() []byte {
	return k.priv.PublicKey().Bytes()
}

// Private returns the 32-byte private key.
func (k *Soft) Private() []byte {
	return k.priv.Bytes()
}

// DH returns the X25519 shared secret of k and the public key peer.
func (k *Soft) DH(peer []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("keys: the peer key: %w", err)
	}
	return k.priv.ECDH(pub)
}

// LoadSoft returns the static key in the file path, and creates the file with a new key if it
// does not exist yet. The file is the base64 of the private key, mode 0600. The node simulator
// keeps its key so, and so does the controller on Linux.
func LoadSoft(path string) (*Soft, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := GenerateSoft()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k.Private())+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("keys: %s is not the base64 of a key: %w", path, err)
	}
	return NewSoft(priv)
}

// SelfSigned returns a new self-signed certificate for the TLS key key. A node does not check
// it: the Noise handshake authenticates the controller and is bound to the TLS session
// (ADR-0023). The certificate is made again at every start; its key is the long-term one.
func SelfSigned(key crypto.Signer) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ranz-controller"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keys: certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keys: certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Fingerprint returns the hex SHA-256 of the SubjectPublicKeyInfo of cert: it stays the same
// while the TLS key does, whatever certificate is made for it.
func Fingerprint(cert tls.Certificate) string {
	if cert.Leaf == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// loadTLSFile returns the ECDSA P-256 TLS key in the file path (PKCS #8, PEM), and creates the
// file with a new key, mode 0600, if it does not exist yet.
func loadTLSFile(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keys: %s holds no PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: %s: %w", path, err)
	}
	signer, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: %s is not an ECDSA key", path)
	}
	return signer, nil
}
