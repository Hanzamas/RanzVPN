package nodecontroller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

const (
	goodKey         = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	goodFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// The three values of ranz status are taken as they are printed; the fingerprint is kept in lower
// case, so a copy in upper case is the same setting.
func TestParseTakesTheValuesOfRanzStatus(t *testing.T) {
	for _, address := range []string{"192.168.1.10:443", "pc-a.example:5555", "[fd00::1]:443"} {
		s, err := Parse(address, goodKey, strings.ToUpper(goodFingerprint))
		if err != nil {
			t.Fatalf("Parse(%q): %v", address, err)
		}
		if s.Address != address || s.PublicKey != goodKey || s.TLSFingerprint != goodFingerprint {
			t.Errorf("Parse(%q) = %+v", address, s)
		}
		if k := s.Key(); len(k) != KeySize {
			t.Errorf("Key() of %+v is %d bytes", s, len(k))
		}
	}
}

// A wrong value is refused with a message that names which: the address without a port, the key of
// the wrong length, the fingerprint that is not 64 hex digits.
func TestParseSaysWhichValueIsWrong(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	cases := []struct {
		address, key, fingerprint string
		want                      string
	}{
		{"192.168.1.10", goodKey, goodFingerprint, "has no port"},
		{"192.168.1.10:", goodKey, goodFingerprint, "has no port"},
		{":443", goodKey, goodFingerprint, "has no host"},
		{"192.168.1.10:0", goodKey, goodFingerprint, "not a number from 1 to 65535"},
		{"192.168.1.10:65536", goodKey, goodFingerprint, "not a number from 1 to 65535"},
		{"192.168.1.10:https", goodKey, goodFingerprint, "not a number from 1 to 65535"},
		{"192.168.1.10:443", short, goodFingerprint, "31 bytes long, not 32"},
		{"192.168.1.10:443", "not base64!", goodFingerprint, "is not base64"},
		{"192.168.1.10:443", goodKey, goodFingerprint[:63], "not 64 hex digits"},
		{"192.168.1.10:443", goodKey, "zz" + goodFingerprint[2:], "not 64 hex digits"},
	}
	for _, c := range cases {
		_, err := Parse(c.address, c.key, c.fingerprint)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q, %q, %q) = %v, want an error that says %q", c.address, c.key, c.fingerprint, err, c.want)
		}
	}
}

// The fingerprint of a certificate is the one that the Controller prints for it, and a session with a
// certificate of another key fails the check with both fingerprints in its error.
func TestCheckFingerprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(key)
	if err != nil {
		t.Fatal(err)
	}
	want := keys.Fingerprint(cert)
	if got := Fingerprint(cert.Leaf.RawSubjectPublicKeyInfo); got != want {
		t.Fatalf("Fingerprint = %s, the Controller prints %s", got, want)
	}
	st := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}}
	if err := CheckFingerprint(st, strings.ToUpper(want)); err != nil {
		t.Errorf("the certificate of the fingerprint fails the check: %v", err)
	}
	err = CheckFingerprint(st, goodFingerprint)
	if !errors.Is(err, ErrFingerprint) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), goodFingerprint) {
		t.Errorf("a certificate of another key: %v", err)
	}
	if err := CheckFingerprint(tls.ConnectionState{}, want); !errors.Is(err, ErrFingerprint) {
		t.Errorf("a session without a certificate: %v", err)
	}
}

// FuzzParse feeds Parse the three values as an operator types them: it never panics, and what it
// takes is the form the Node keeps, which it takes again unchanged.
func FuzzParse(f *testing.F) {
	f.Add("192.168.1.10:443", goodKey, goodFingerprint)
	f.Add("[fd00::1]:5555", goodKey, strings.ToUpper(goodFingerprint))
	f.Add("host", "", "")
	f.Fuzz(func(t *testing.T, address, key, fingerprint string) {
		s, err := Parse(address, key, fingerprint)
		if err != nil {
			return
		}
		again, err := Parse(s.Address, s.PublicKey, s.TLSFingerprint)
		if err != nil || again != s {
			t.Errorf("Parse took %+v, then not its own form: %+v, %v", s, again, err)
		}
		if !bytes.Equal(s.Key(), again.Key()) || len(s.Key()) != KeySize {
			t.Errorf("the key of %+v is not %d bytes", s, KeySize)
		}
	})
}
