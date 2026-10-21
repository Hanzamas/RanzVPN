package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// The X25519 test vector of RFC 7748 section 6.1.
const (
	alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	bobPub    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	shared    = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSoftRFC7748(t *testing.T) {
	k, err := NewSoft(unhex(t, alicePriv))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k.Public()); got != alicePub {
		t.Errorf("the public key is %s, want %s", got, alicePub)
	}
	s, err := k.DH(unhex(t, bobPub))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(s); got != shared {
		t.Errorf("the shared secret is %s, want %s", got, shared)
	}
}

// A key file made the first time gives the same key the next time.
func TestLoadSoft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	a, err := LoadSoft(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadSoft(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Error("the key read back differs from the key written")
	}
}

// The controller's keys made the first time are the same keys at the next start, and the TLS key
// signs a certificate that verifies.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cleanupKeys(t, dir)
	static, tlsKey, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	static2, tlsKey2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(static.Public(), static2.Public()) {
		t.Error("the Noise static key changed between two loads")
	}
	pub, ok := tlsKey.Public().(*ecdsa.PublicKey)
	if !ok || !pub.Equal(tlsKey2.Public()) {
		t.Error("the TLS key changed between two loads")
	}
	cert, err := SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.CheckSignatureFrom(cert.Leaf); err != nil {
		t.Errorf("the self-signed certificate does not verify: %v", err)
	}
	digest := sha256.Sum256([]byte("ranz"))
	sig, err := tlsKey2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("a signature of the TLS key does not verify")
	}
	if Fingerprint(cert) == "" {
		t.Error("the certificate has no fingerprint")
	}
}
