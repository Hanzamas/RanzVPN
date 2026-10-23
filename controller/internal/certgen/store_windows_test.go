//go:build windows

package certgen

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// storeTestName returns a name for a key of the provider that no other test or run uses.
func storeTestName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Ranz certgen test " + hex.EncodeToString(b)
}

// A certificate of a key in the Microsoft Software Key Storage Provider goes into the My store of
// the current user, linked to its key: it finds its key as Schannel looks for it when the node
// serves with the certificate, the key signs the handshake of a TLS listener whose certificate it
// is, and RemoveFromStore takes the certificate out again.
func TestKSPCertificateInTheStore(t *testing.T) {
	name := storeTestName(t)
	key, err := keys.CreateKSP(name, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.DeleteKSP(name, false) })
	ca := newCA(t, "Ranz test CA", 0)
	cert, der := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, key, ca)
	thumbprint := Thumbprint(der)
	if err := InstallInStore(der, name, false); err != nil {
		t.Fatal(err)
	}
	removed := false
	t.Cleanup(func() {
		if !removed {
			RemoveFromStore(thumbprint, false)
		}
	})
	if err := CheckStoredKey(thumbprint, false); err != nil {
		t.Errorf("the certificate in the store does not find its key: %v", err)
	}

	addr := serve(t, serverConfig(der, key))
	if got, err := dial(addr, &tls.Config{RootCAs: pool(ca.Cert), ServerName: "localhost"}); err != nil || got != "|ok" {
		t.Errorf("a client that trusts the CA: %q, %v", got, err)
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("the certificate does not verify against its CA: %v", err)
	}

	if err := RemoveFromStore(thumbprint, false); err != nil {
		t.Fatal(err)
	}
	removed = true
	if err := CheckStoredKey(thumbprint, false); err == nil {
		t.Error("the certificate is in the store after RemoveFromStore")
	}
	if err := RemoveFromStore(thumbprint, false); err == nil {
		t.Error("a second RemoveFromStore of the certificate gave no error")
	}
}

// A certificate that is linked to a key that the provider does not hold finds no key: what
// CheckStoredKey checks is the key and not only the link.
func TestCertificateOfAMissingKey(t *testing.T) {
	key := mustKey(t, 0)
	_, der := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, key, nil)
	thumbprint := Thumbprint(der)
	if err := InstallInStore(der, storeTestName(t), false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveFromStore(thumbprint, false) })
	if err := CheckStoredKey(thumbprint, false); err == nil {
		t.Error("a certificate linked to a key that does not exist found a key")
	}
}

// The store takes no empty certificate and no thumbprint that is no hex.
func TestStoreRefusals(t *testing.T) {
	if err := InstallInStore(nil, "key", false); err == nil {
		t.Error("an empty certificate was installed")
	}
	if err := InstallInStore([]byte{1, 2, 3}, "key", false); err == nil {
		t.Error("bytes that are no certificate were installed")
	}
	if err := RemoveFromStore("not hex", false); err == nil {
		t.Error("a thumbprint that is no hex was removed")
	}
	if err := CheckStoredKey("", false); err == nil {
		t.Error("an empty thumbprint was checked")
	}
	if err := CheckStoredKey("00", false); err == nil {
		t.Error("a thumbprint that names no certificate was checked")
	}
}
