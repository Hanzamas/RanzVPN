package devicekey

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// The fuzz test of the devicekey package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which the
// controller workflow runs with go test -fuzz.

// FuzzOpen opens the input as the sealed PresharedKey of a Device (Sealer.Open): the bytes of a row of the
// store, which a damaged backup or another program may have written. Only the key that the Sealer sealed
// for the Device phone opens, to the PresharedKey that it sealed, and every other input fails without a
// panic.
func FuzzOpen(f *testing.F) {
	k, err := keys.NewSoft(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		f.Fatal(err)
	}
	s, err := NewSealer(k)
	if err != nil {
		f.Fatal(err)
	}
	psk := bytes.Repeat([]byte{0x5a}, intent.KeySize)
	sealed, err := s.Seal("phone", psk, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("phone", sealed)
	f.Add("laptop", sealed)
	f.Add("phone", sealed[:len(sealed)-1])
	f.Add("phone", append([]byte{sealVersion + 1}, sealed[1:]...))
	f.Add("phone", []byte{sealVersion})
	f.Add("", []byte{})

	f.Fuzz(func(t *testing.T, name string, blob []byte) {
		got, err := s.Open(name, blob)
		if err != nil {
			return
		}
		if name != "phone" || !bytes.Equal(got, psk) {
			t.Fatalf("the sealed key %x opens for %q to %x, and only %x sealed for phone opens, to %x", blob, name, got, sealed, psk)
		}
	})
}
