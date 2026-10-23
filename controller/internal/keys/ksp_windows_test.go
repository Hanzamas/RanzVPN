//go:build windows

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// kspTestName returns a name for a key of the provider that no other test or run uses.
func kspTestName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Ranz keys test " + hex.EncodeToString(b)
}

// A key that CreateKSP makes signs inside the provider, LoadKSP finds the same key by its name, a
// second CreateKSP of the name is refused, and DeleteKSP removes the key.
func TestKSPKey(t *testing.T) {
	name := kspTestName(t)
	created, err := CreateKSP(name, false)
	if err != nil {
		t.Fatal(err)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			DeleteKSP(name, false)
		}
	})
	pub, ok := created.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the public key is a %T, not an ECDSA key", created.Public())
	}
	digest := sha256.Sum256([]byte("ranz"))
	sig, err := created.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("a signature of the key of the provider does not verify")
	}
	if _, err := CreateKSP(name, false); err == nil {
		t.Error("a second CreateKSP of the name gave no error")
	}
	loaded, err := LoadKSP(name, false)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(loaded.Public()) {
		t.Error("LoadKSP found another key than CreateKSP made")
	}
	if err := DeleteKSP(name, false); err != nil {
		t.Fatal(err)
	}
	deleted = true
	if _, err := LoadKSP(name, false); err == nil {
		t.Error("the key loads after DeleteKSP")
	}
	if err := DeleteKSP(name, false); err == nil {
		t.Error("a second DeleteKSP of the name gave no error")
	}
}
