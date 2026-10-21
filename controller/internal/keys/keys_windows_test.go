//go:build windows

package keys

import (
	"bytes"
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
