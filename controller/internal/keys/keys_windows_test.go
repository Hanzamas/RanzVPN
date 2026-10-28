//go:build windows

package keys

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// cleanupKeys deletes the keys of the data directory dir from the provider when the test ends.
func cleanupKeys(t *testing.T, dir string) {
	t.Cleanup(func() {
		if err := removeKeys(dir); err != nil {
			t.Errorf("removing the keys of %s: %v", dir, err)
		}
	})
}

// The X25519 key of the key storage provider agrees with crypto/ecdh (whose X25519 meets RFC
// 7748: TestSoftRFC7748) on the shared secret, in both directions, and refuses a low-order
// point. The provider cannot import a private key, so it cannot take the RFC 7748 vector itself.
func TestKSPStatic(t *testing.T) {
	dir := t.TempDir()
	cleanupKeys(t, dir)
	static, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := static.(*kspStatic); !ok {
		t.Fatalf("the Noise static key is a %T, not a key of the provider", static)
	}
	for range 4 {
		peer, err := GenerateSoft()
		if err != nil {
			t.Fatal(err)
		}
		a, err := static.DH(peer.Public())
		if err != nil {
			t.Fatal(err)
		}
		b, err := peer.DH(static.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("the provider computes the shared secret %x, crypto/ecdh %x", a, b)
		}
	}
	if _, err := static.DH(make([]byte, 32)); err == nil {
		t.Error("a Diffie-Hellman with the zero point gave no error")
	}
}

// The X25519 key of the key storage provider takes every u as X25519 does (RFC 7748 section 5), also the u
// that the provider refuses by default: one outside the prime-order subgroup, one that is no point of the
// curve (a point of its twist), one with bit 255 set and one from p up. The sealing of the PresharedKeys of
// the Devices does its Diffie-Hellman with the hash of a label, which is a point of the curve outside the
// subgroup, and the provider answered "The parameter is incorrect" (the tracer of the Devices found it).
// The provider cannot import a private key, so the secret is checked by the way that the two scalars
// commute: with f the scalar of a key of the test and d the one of the provider, d * (f * u) is f * (d * u).
func TestKSPStaticAnyPoint(t *testing.T) {
	dir := t.TempDir()
	cleanupKeys(t, dir)
	static, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	label := func(s string) []byte {
		h := sha256.Sum256([]byte(s))
		return h[:]
	}
	topBit := make([]byte, 32)
	topBit[0], topBit[31] = 9, 0x80
	// p + 5 is 0xf2, 30 bytes of 0xff and 0x7f
	fromP := bytes.Repeat([]byte{0xff}, 32)
	fromP[0], fromP[31] = 0xf2, 0x7f
	for _, c := range []struct {
		name string
		u    []byte
	}{
		{"a u outside the prime-order subgroup (RFC 7748 section 5.2)", unhex(t, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")},
		{"the hash of the label that seals the PresharedKeys: on the curve, outside the subgroup", label("ranz controller: the key that seals the PresharedKeys of the Devices, version 1")},
		{"the hash of the label of the WireGuard key of a node: no point of the curve", label("ranz wireguard gateway key")},
		{"the base point with bit 255 set", topBit},
		{"p + 5", fromP},
	} {
		secret, err := static.DH(c.u)
		if err != nil {
			t.Errorf("%s: the provider gives no secret: %v", c.name, err)
			continue
		}
		fu, err := f.DH(c.u)
		if err != nil {
			t.Fatalf("%s: crypto/ecdh gives no secret: %v", c.name, err)
		}
		viaD, err := static.DH(fu)
		if err != nil {
			t.Errorf("%s: the provider gives no secret for f * u: %v", c.name, err)
			continue
		}
		viaF, err := f.DH(secret)
		if err != nil {
			t.Fatalf("%s: crypto/ecdh gives no secret for d * u: %v", c.name, err)
		}
		if !bytes.Equal(viaD, viaF) {
			t.Errorf("%s: d * (f * u) is %x, and f * (d * u) is %x", c.name, viaD, viaF)
		}
	}
}
