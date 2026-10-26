package servercert

import (
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
)

// chainStore is where the ACME client of the Controller keeps the certificate that it gets
// (acmecert.ChainStore): a PEM file of the whole chain for each certificate, named by its thumbprint,
// in a directory of the data directory of the Controller. The key is the TLS key of the Controller,
// which stays where it is: the certificate that the service issues is for that key, so the TLS
// fingerprint of the Controller does not change when it renews. The chain files hold no key.
type chainStore struct {
	dir string
	key crypto.Signer
}

// thumbprintFile is the name of the chain file of a certificate.
var thumbprintFile = regexp.MustCompile(`^[0-9A-F]{40}$`)

// NewKey returns the TLS key of the Controller, whatever the name.
func (s *chainStore) NewKey(string) (crypto.Signer, error) {
	return s.key, nil
}

// Install keeps the certificate der alone, as InstallChain keeps a chain of one.
func (s *chainStore) Install(der []byte, name string) error {
	return s.InstallChain([][]byte{der}, name)
}

// InstallChain keeps the chain, the certificate first, as a PEM file named by the thumbprint of
// the certificate.
func (s *chainStore) InstallChain(chain [][]byte, _ string) error {
	if len(chain) == 0 {
		return errors.New("servercert: no certificate to keep")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("servercert: the directory of the ACME certificates: %w", err)
	}
	var text []byte
	for _, der := range chain {
		text = append(text, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path, ok := s.file(certgen.Thumbprint(chain[0]))
	if !ok {
		return errors.New("servercert: the thumbprint of the certificate is no thumbprint")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, text, 0o600); err != nil {
		return fmt.Errorf("servercert: keeping the ACME certificate: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("servercert: keeping the ACME certificate: %w", err)
	}
	return nil
}

// Has reports whether the chain of the thumbprint is kept and belongs to the key.
func (s *chainStore) Has(thumbprint string) bool {
	_, err := s.load(thumbprint)
	return err == nil
}

// Remove takes the chain of the thumbprint away. The key stays: it is the one of the Controller.
func (s *chainStore) Remove(thumbprint, _ string) {
	if path, ok := s.file(thumbprint); ok {
		_ = os.Remove(path)
	}
}

// file returns the path of the chain file of the thumbprint, false for a thumbprint that is none.
func (s *chainStore) file(thumbprint string) (string, bool) {
	if !thumbprintFile.MatchString(thumbprint) {
		return "", false
	}
	return filepath.Join(s.dir, thumbprint+".pem"), true
}

// load returns the certificate of the chain of the thumbprint, with the key of the Controller.
func (s *chainStore) load(thumbprint string) (tls.Certificate, error) {
	path, ok := s.file(thumbprint)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("%q is no thumbprint", thumbprint)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	var ders [][]byte
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	c, err := pair(ders, s.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return c, nil
}
