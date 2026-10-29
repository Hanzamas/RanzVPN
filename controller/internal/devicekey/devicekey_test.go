package devicekey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// counting is a source of 64 bytes that count up from first: first, first+1, and so on.
func counting(first byte) io.Reader {
	b := make([]byte, 64)
	for i := range b {
		b[i] = first + byte(i)
	}
	return bytes.NewReader(b)
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
