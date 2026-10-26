//go:build windows

package servercert

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// kspName returns a name for a key of the provider that no other test or run uses.
func kspName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Ranz servercert test " + hex.EncodeToString(b)
}

// A certificate of the My store whose key is in the Microsoft Software Key Storage Provider is served by its
// thumbprint with its key staying there: the provider signs the handshake of a client that trusts the
// certificate, and the description names the source and holds no key. A thumbprint that no store holds, and a
// certificate whose key the provider does not hold, are refused with the reason.
func TestServesACertificateOfTheKeyStorage(t *testing.T) {
	name := kspName(t)
	key, err := keys.CreateKSP(name, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.DeleteKSP(name, false) })
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := certgen.Thumbprint(der)
	if err := certgen.InstallInStore(der, name, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { certgen.RemoveFromStore(thumbprint, false) })

	m := newManager(t, nil, "")
	l, err := m.Load(context.Background(), Setting{Hosts: []string{"pc-a.example.com"}, KSP: thumbprint})
	if err != nil {
		t.Fatal(err)
	}
	if l.Info.Source != SourceKSP || l.Info.Thumbprint != thumbprint || l.Info.Fingerprint != fingerprintOf(t, der) {
		t.Errorf("the description is %+v", l.Info)
	}
	m.Adopt(l)

	// The provider signs: a client that trusts the certificate takes the handshake of the Manager's certificate
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if err := handshakeOf(m, roots, "pc-a.example.com"); err != nil {
		t.Errorf("a client that trusts the certificate: %v", err)
	}

	_, err = m.Load(context.Background(), Setting{Hosts: []string{"pc-a.example.com"}, KSP: "0000000000000000000000000000000000000001"})
	refusedWith(t, "a thumbprint that no store holds", err, "is in neither store")

	// A certificate that is linked to a key that the provider does not hold
	other := ecKey(t)
	otherDER, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := certgen.InstallInStore(otherDER, kspName(t), false); err != nil {
		t.Fatal(err)
	}
	otherThumbprint := certgen.Thumbprint(otherDER)
	t.Cleanup(func() { certgen.RemoveFromStore(otherThumbprint, false) })
	_, err = m.Load(context.Background(), Setting{Hosts: []string{"pc-a.example.com"}, KSP: otherThumbprint})
	refusedWith(t, "a certificate of a key that is not in the provider", err, "cannot be used in the key storage provider")

	// A certificate that is not for the host
	_, err = m.Load(context.Background(), Setting{Hosts: []string{"pc-b.example.com"}, KSP: thumbprint})
	refusedWith(t, "a certificate for another host", err, `does not name the host "pc-b.example.com"`)
}
