package keys

import (
	"bytes"
	"errors"
	"testing"
)

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	key, err := GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	return NewSealer(key)
}

// A secret opens with the key that sealed it, under the label it was sealed with, and the sealed
// bytes show nothing of it: they differ each time, since each secret has a key pair of its own.
func TestSealerRoundTrip(t *testing.T) {
	s := newTestSealer(t)
	secret := []byte("s3cret-hmac-key of a webhook")
	a, err := s.Seal("export:alerts", secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Seal("export:alerts", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two seals of one secret gave the same bytes")
	}
	if bytes.Contains(a, secret) || bytes.Contains(a, []byte("s3cret")) {
		t.Errorf("the sealed bytes hold the secret: %x", a)
	}
	if want := sealedKeyLen + sealedNonceLen + len(secret) + sealedTagLen; len(a) != want {
		t.Errorf("a sealed secret of %d bytes is %d bytes, want %d", len(secret), len(a), want)
	}
	for _, sealed := range [][]byte{a, b} {
		got, err := s.Open("export:alerts", sealed)
		if err != nil || !bytes.Equal(got, secret) {
			t.Errorf("Open gave %q, %v, want the secret", got, err)
		}
	}
	if got, err := s.Open("export:alerts", mustSeal(t, s, "export:alerts", nil)); err != nil || len(got) != 0 {
		t.Errorf("an empty secret came back as %q, %v", got, err)
	}
}

func mustSeal(t *testing.T, s *Sealer, label string, plain []byte) []byte {
	t.Helper()
	sealed, err := s.Seal(label, plain)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// A sealed secret does not open under another label, which is how a secret copied to another row of
// the store stays shut, and it does not open with the key of another host.
func TestSealerLabelAndKey(t *testing.T) {
	s, other := newTestSealer(t), newTestSealer(t)
	sealed := mustSeal(t, s, "export:alerts", []byte("key"))
	for _, label := range []string{"export:other", "audit:alerts", "export:alert", ""} {
		if got, err := s.Open(label, sealed); !errors.Is(err, ErrNotSealed) || got != nil {
			t.Errorf("Open under the label %q gave %q, %v, want ErrNotSealed", label, got, err)
		}
	}
	if got, err := other.Open("export:alerts", sealed); !errors.Is(err, ErrNotSealed) || got != nil {
		t.Errorf("Open with the key of another host gave %q, %v, want ErrNotSealed", got, err)
	}
}

// A change of any byte, in the public key, the nonce, the ciphertext or the tag, is refused, and so
// is anything shorter than a sealed empty secret, or that was never sealed.
func TestSealerRefusesWhatIsNotSealed(t *testing.T) {
	s := newTestSealer(t)
	sealed := mustSeal(t, s, "audit:siem", []byte("a secret"))
	for i := range sealed {
		changed := bytes.Clone(sealed)
		changed[i] ^= 0x01
		if got, err := s.Open("audit:siem", changed); !errors.Is(err, ErrNotSealed) || got != nil {
			t.Fatalf("byte %d changed: Open gave %q, %v, want ErrNotSealed", i, got, err)
		}
	}
	for n := range sealedKeyLen + sealedNonceLen + sealedTagLen {
		if _, err := s.Open("audit:siem", sealed[:n]); !errors.Is(err, ErrNotSealed) {
			t.Errorf("the first %d bytes: Open gave %v, want ErrNotSealed", n, err)
		}
	}
	if _, err := s.Open("audit:siem", sealed[:len(sealed)-1]); !errors.Is(err, ErrNotSealed) {
		t.Errorf("a sealed secret without its last byte: Open gave %v, want ErrNotSealed", err)
	}
	if _, err := s.Open("audit:siem", append(bytes.Clone(sealed), 0)); !errors.Is(err, ErrNotSealed) {
		t.Errorf("a sealed secret with a byte more: Open gave %v, want ErrNotSealed", err)
	}
	// A public key of low order agrees on nothing, and the key refuses it
	zero := append(make([]byte, sealedKeyLen), sealed[sealedKeyLen:]...)
	if _, err := s.Open("audit:siem", zero); !errors.Is(err, ErrNotSealed) {
		t.Errorf("a sealed secret with the zero public key: Open gave %v, want ErrNotSealed", err)
	}
	if _, err := s.Open("audit:siem", bytes.Repeat([]byte{0xa5}, 100)); !errors.Is(err, ErrNotSealed) {
		t.Errorf("bytes that were never sealed: Open gave %v, want ErrNotSealed", err)
	}
}

// The sealing key of a data directory is made the first time and is the same key at the next start,
// so a secret that one start sealed opens at the next, and the key of another data directory does
// not open it.
func TestLoadSealer(t *testing.T) {
	dir := t.TempDir()
	cleanupKeys(t, dir)
	first, err := LoadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := mustSeal(t, first, "export:alerts", []byte("hmac-key"))
	second, err := LoadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := second.Open("export:alerts", sealed); err != nil || string(got) != "hmac-key" {
		t.Errorf("the sealing key at the next start gave %q, %v, want the secret", got, err)
	}

	elsewhere := t.TempDir()
	cleanupKeys(t, elsewhere)
	another, err := LoadSealer(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := another.Open("export:alerts", sealed); !errors.Is(err, ErrNotSealed) {
		t.Errorf("the sealing key of another data directory gave %v, want ErrNotSealed", err)
	}
}
