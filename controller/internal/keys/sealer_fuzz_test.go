package keys

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// FuzzSealerOpen feeds Open the bytes that the store holds in place of a sealed secret: anyone who
// can write to the store can put any bytes there. Open must not panic, and what it opens is what
// this key sealed, which seals and opens again to the same secret.
func FuzzSealerOpen(f *testing.F) {
	priv, err := hex.DecodeString(alicePriv)
	if err != nil {
		f.Fatal(err)
	}
	key, err := NewSoft(priv)
	if err != nil {
		f.Fatal(err)
	}
	s := NewSealer(key)
	sealed, err := s.Seal("export:alerts", []byte("hmac-key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add("export:alerts", sealed)
	f.Add("audit:siem", sealed)
	f.Add("export:alerts", sealed[:sealedKeyLen+sealedNonceLen])
	f.Add("", []byte{})
	f.Add("export:alerts", make([]byte, sealedKeyLen+sealedNonceLen+sealedTagLen))
	f.Fuzz(func(t *testing.T, label string, in []byte) {
		plain, err := s.Open(label, in)
		if err != nil {
			return
		}
		again, err := s.Seal(label, plain)
		if err != nil {
			t.Fatalf("Seal of what Open gave: %v", err)
		}
		back, err := s.Open(label, again)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("what Open gave does not seal and open again: %q, %v", back, err)
		}
	})
}
