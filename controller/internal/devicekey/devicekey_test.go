package devicekey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// counting is a source of 64 bytes that count up from first: first, first+1, and so on.
func counting(first byte) io.Reader {
	b := make([]byte, 64)
	for i := range b {
		b[i] = first + byte(i)
	}
	return bytes.NewReader(b)
}

// sealer returns the Sealer of the static key whose private key is 32 bytes of seed.
func sealer(t *testing.T, seed byte) *Sealer {
	t.Helper()
	k, err := keys.NewSoft(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestNewPair: the private key that the controller makes for a Device is clamped as wg genkey clamps one,
// and its public key is the one that WireGuard derives from it: the scalar 1 to 32 that the tests of the
// controller give the node branch-1 has the key that its resources hold (conformance_test.go).
func TestNewPair(t *testing.T) {
	private, public, err := NewPair(counting(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(private) != intent.KeySize || len(public) != intent.KeySize {
		t.Fatalf("the key pair has a private key of %d bytes and a public key of %d", len(private), len(public))
	}
	if private[0]&7 != 0 || private[31]&0x80 != 0 || private[31]&0x40 == 0 {
		t.Errorf("the private key %x is not clamped", private)
	}
	if got, want := base64.StdEncoding.EncodeToString(public), "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="; got != want {
		t.Errorf("the public key of the scalar 1 to 32 is %s, want %s", got, want)
	}

	// Each pair of crypto/rand is a new one
	a, _, err := NewPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := NewPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two key pairs of crypto/rand have the same private key")
	}

	// A source that gives less than a key, or fails, makes no pair
	for name, src := range map[string]io.Reader{
		"a short source":  bytes.NewReader(make([]byte, 31)),
		"an empty source": bytes.NewReader(nil),
		"a failing one":   iotest.ErrReader(errors.New("no entropy")),
	} {
		if private, public, err := NewPair(src); err == nil || private != nil || public != nil {
			t.Errorf("%s gave the key pair %x, %x and %v", name, private, public, err)
		}
	}
}

// TestSealAndOpen: a sealed PresharedKey opens for its Device under the static key that sealed it and
// under no other way, and it is the sealed form that the store holds, which gives the key to nobody.
func TestSealAndOpen(t *testing.T) {
	psk := bytes.Repeat([]byte{0x5a}, intent.KeySize)
	s := sealer(t, 1)
	sealed, err := s.Seal("phone", psk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The version, a nonce of 12 bytes, the key and the tag of 16
	if len(sealed) != 1+12+intent.KeySize+16 || sealed[0] != sealVersion {
		t.Fatalf("the sealed key is %d bytes and starts with %d", len(sealed), sealed[0])
	}
	if bytes.Contains(sealed, psk) {
		t.Error("the sealed key holds the PresharedKey in clear")
	}
	if got, err := s.Open("phone", sealed); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("the sealed key opens to %x, %v, want %x", got, err, psk)
	}

	// A controller that starts again has the same static key, so it opens what the first one sealed
	if got, err := sealer(t, 1).Open("phone", sealed); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("a Sealer of the same static key opens %x, %v, want %x", got, err, psk)
	}

	// A new nonce for each seal
	again, err := s.Seal("phone", psk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again, sealed) {
		t.Error("two seals of one PresharedKey are the same bytes: the nonce is the same")
	}

	// What does not open
	if _, err := s.Open("laptop", sealed); err == nil {
		t.Error("the sealed key of phone opens for laptop")
	}
	if _, err := sealer(t, 2).Open("phone", sealed); err == nil || !strings.Contains(err.Error(), "another static key") {
		t.Errorf("a key sealed under another static key opens or says %v", err)
	}
	for i := range sealed {
		altered := bytes.Clone(sealed)
		altered[i] ^= 0x01
		if _, err := s.Open("phone", altered); err == nil {
			t.Errorf("the sealed key opens with byte %d altered", i)
		}
	}
	for _, c := range []struct {
		what   string
		sealed []byte
	}{
		{"none", nil},
		{"a version byte alone", sealed[:1]},
		{"a key one byte short", sealed[:len(sealed)-1]},
		{"a key with a byte more", append(bytes.Clone(sealed), 0)},
	} {
		if _, err := s.Open("phone", c.sealed); err == nil {
			t.Errorf("a sealed key of %s opens", c.what)
		}
	}
	if _, err := s.Open("phone", append([]byte{sealVersion + 1}, sealed[1:]...)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("a key of another version opens or says %v", err)
	}
}

// TestSealNeedsRandom: a source of nonces that fails seals nothing.
func TestSealNeedsRandom(t *testing.T) {
	s := sealer(t, 1)
	if sealed, err := s.Seal("phone", make([]byte, intent.KeySize), iotest.ErrReader(errors.New("no entropy"))); err == nil || sealed != nil {
		t.Errorf("a failing source sealed %x, %v", sealed, err)
	}
}

// noDH is a static key whose key storage provider refuses the Diffie-Hellman.
type noDH struct{}

func (noDH) Public() []byte { return nil }

func (noDH) DH([]byte) ([]byte, error) { return nil, errors.New("the provider is locked") }

// TestNewSealerRefuses: a controller without a static key, or whose key storage provider refuses the
// Diffie-Hellman, has no Sealer, and the error says why.
func TestNewSealerRefuses(t *testing.T) {
	if s, err := NewSealer(nil); err == nil || s != nil || !strings.Contains(err.Error(), "no static key") {
		t.Errorf("a Sealer of no key is %v, %v", s, err)
	}
	if s, err := NewSealer(noDH{}); err == nil || s != nil || !strings.Contains(err.Error(), "the provider is locked") {
		t.Errorf("a Sealer of a key that refuses the Diffie-Hellman is %v, %v", s, err)
	}
}
