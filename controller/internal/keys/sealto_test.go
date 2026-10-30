package keys

import (
	"bytes"
	"errors"
	"testing"
)

// What SealTo seals to the public half of a key opens with the Sealer of that key, under its label only,
// and with no other key, as what that Sealer seals itself; a Sealer of the public half alone opens
// nothing, and a public key that is none is refused.
func TestSealTo(t *testing.T) {
	s, other := newTestSealer(t), newTestSealer(t)
	secret := []byte("the private half of a Cluster key")
	sealed, err := SealTo(s.Public(), "cluster_key_copies:c2", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Errorf("the sealed bytes hold the secret: %x", sealed)
	}
	if got, err := s.Open("cluster_key_copies:c2", sealed); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("the Sealer of the key opened %q, %v, want the secret", got, err)
	}
	if _, err := s.Open("cluster_key_copies:c3", sealed); !errors.Is(err, ErrNotSealed) {
		t.Errorf("under another label Open gave %v, want ErrNotSealed", err)
	}
	if _, err := other.Open("cluster_key_copies:c2", sealed); !errors.Is(err, ErrNotSealed) {
		t.Errorf("another key opened it: %v, want ErrNotSealed", err)
	}
	if _, err := NewSealer(publicOnly(s.Public())).Open("cluster_key_copies:c2", sealed); !errors.Is(err, ErrNotSealed) {
		t.Errorf("the public half alone opened it: %v, want ErrNotSealed", err)
	}
	if !bytes.Equal(s.Public(), s.key.Public()) || len(s.Public()) != sealedKeyLen {
		t.Errorf("Public gave %x, want the public half of the key of the Sealer", s.Public())
	}

	// The zero key is of low order: it agrees on nothing, so nothing is sealed to it
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, sealedKeyLen), make([]byte, 33)} {
		if got, err := SealTo(bad, "cluster_key_copies:c2", secret); err == nil {
			t.Errorf("SealTo the key %x gave %x, want an error", bad, got)
		}
	}
}
