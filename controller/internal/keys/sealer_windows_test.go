//go:build windows

package keys

import (
	"bytes"
	"testing"
)

// On Windows the sealing key is a key of the key storage provider, and it is not one of the two
// keys of Load: what seals the store is a key of its own. It agrees with crypto/ecdh on the shared
// secret, as the Noise static key does (TestKSPStatic), so the sealed box that it opens is the one
// that the portable code makes.
func TestKSPSealer(t *testing.T) {
	dir := t.TempDir()
	cleanupKeys(t, dir)
	sealer, err := LoadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	static, ok := sealer.key.(*kspStatic)
	if !ok {
		t.Fatalf("the sealing key is a %T, not a key of the provider", sealer.key)
	}
	noise, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(static.Public(), noise.Public()) {
		t.Error("the sealing key and the Noise static key are one key")
	}

	sealed := mustSeal(t, sealer, "export:alerts", []byte("hmac-key"))
	if bytes.Contains(sealed, []byte("hmac-key")) {
		t.Error("the sealed bytes hold the secret")
	}
	if got, err := sealer.Open("export:alerts", sealed); err != nil || string(got) != "hmac-key" {
		t.Errorf("Open gave %q, %v, want the secret", got, err)
	}
	// The key of the provider is the same key at the next start
	again, err := LoadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Open("export:alerts", sealed); err != nil || string(got) != "hmac-key" {
		t.Errorf("the sealing key at the next start gave %q, %v, want the secret", got, err)
	}
	if _, err := again.Open("audit:alerts", sealed); err == nil {
		t.Error("the secret opened under another label")
	}
}
