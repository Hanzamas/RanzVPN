package certgen

import "testing"

// The fuzz tests of the certgen package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the ranz workflow runs with go test -fuzz.

// FuzzLoadAuthority reads the input as the PEM text of a CA certificate and the PEM text of its key
// (LoadAuthority), as `ranz cert -signcert` and -signkey take them. The seeds are a CA and its key
// in the form that ranz cert writes, so that a mutation starts from text that loads. An authority
// that loads is a CA with a key, and signs a certificate or says why not.
func FuzzLoadAuthority(f *testing.F) {
	key, err := NewKey(0)
	if err != nil {
		f.Fatal(err)
	}
	der, err := Make(Request{Name: Name{CommonName: "Ranz CA"}, CA: true}, key, nil)
	if err != nil {
		f.Fatal(err)
	}
	keyPEM, err := EncodeKey(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(EncodeCertificate(der), keyPEM)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\n"))
	leafKey, err := NewKey(0)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, certPEM, keyPEM []byte) {
		ca, err := LoadAuthority(certPEM, keyPEM)
		if err != nil {
			return
		}
		if ca.Cert == nil || ca.Key == nil || !ca.Cert.IsCA {
			t.Fatalf("an authority that loads is %+v", ca)
		}
		_, _ = Make(Request{Name: Name{CommonName: "localhost"}}, leafKey, ca)
	})
}
