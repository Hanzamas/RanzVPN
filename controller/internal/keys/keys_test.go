package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"slices"
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

// normalizeU gives the u-coordinate that RFC 7748 section 5 decodes from 32 bytes, which crypto/ecdh does
// for every u: the point that the normalized u names is the one of the u that was given, so the shared
// secret of a key with either is the same, and the normalized u is below p with bit 255 clear.
func TestNormalizeU(t *testing.T) {
	k, err := NewSoft(unhex(t, alicePriv))
	if err != nil {
		t.Fatal(err)
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// little endian, 32 bytes
	encode := func(v *big.Int) []byte {
		b := v.FillBytes(make([]byte, 32))
		slices.Reverse(b)
		return b
	}
	decode := func(b []byte) *big.Int {
		r := bytes.Clone(b)
		slices.Reverse(r)
		return new(big.Int).SetBytes(r)
	}
	topBit := encode(big.NewInt(9))
	topBit[31] |= 0x80
	hash := sha256.Sum256([]byte("ranz wireguard gateway key"))
	// 0xed, then a 0xfe where p has a 0xff: below p
	belowP := append([]byte{0xed, 0xfe}, append(bytes.Repeat([]byte{0xff}, 29), 0x7f)...)
	// None of them is a point of low order, for which X25519 gives no secret
	for _, c := range []struct {
		name string
		u    []byte
		want int64 // the u that RFC 7748 decodes from it when it is a small one, else 0
	}{
		{"the base point", encode(big.NewInt(9)), 9},
		{"the base point with bit 255 set", topBit, 9},
		{"p - 2, the second largest u below p", encode(new(big.Int).Sub(p, big.NewInt(2))), 0},
		{"p + 5", encode(new(big.Int).Add(p, big.NewInt(5))), 5},
		{"2^255 - 1", encode(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))), 18},
		{"2^256 - 1", bytes.Repeat([]byte{0xff}, 32), 18},
		{"a hash, which has bit 255 set", hash[:], 0},
		{"a u below p that has the low byte of p", belowP, 0},
	} {
		given := bytes.Clone(c.u)
		n := normalizeU(c.u)
		if !bytes.Equal(c.u, given) {
			t.Errorf("%s: normalizeU changed the u that it was given", c.name)
		}
		if len(n) != 32 || n[31]&0x80 != 0 || decode(n).Cmp(p) >= 0 {
			t.Errorf("%s: the normalized u %x has bit 255 set or is not below p", c.name, n)
		}
		if c.want != 0 && decode(n).Cmp(big.NewInt(c.want)) != 0 {
			t.Errorf("%s: the normalized u is %v, want %d", c.name, decode(n), c.want)
		}
		a, errA := k.DH(c.u)
		b, errB := k.DH(n)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Errorf("%s: the shared secret is %x (%v) of the u, and %x (%v) of the normalized u", c.name, a, errA, b, errB)
		}
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
	if err := cert.Leaf.CheckSignature(cert.Leaf.SignatureAlgorithm, cert.Leaf.RawTBSCertificate, cert.Leaf.Signature); err != nil {
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
