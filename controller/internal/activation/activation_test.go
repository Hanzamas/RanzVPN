package activation

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// testKSP returns the software signing key of seed: fixed, so the tests need no random source.
func testKSP(t *testing.T, seed byte) (*SoftKSP, ed25519.PublicKey) {
	t.Helper()
	ksp, err := NewSoftKSP(slices.Repeat([]byte{seed}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return ksp, ksp.Public().(ed25519.PublicKey)
}

var tokenIssued = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func sampleToken() Token {
	return Token{
		LicenceID: "biz-1", Licensee: "Example Ltd", Tier: licence.Business, Nodes: 50,
		Features: licence.Business.Features(), Fingerprint: "fp-a", Issued: tokenIssued, Expires: tokenIssued.Add(time.Hour),
	}
}

// A signed token verifies and holds what was signed, also with the space of a file around it.
func TestSignAndParseToken(t *testing.T) {
	ksp, pub := testKSP(t, 1)
	tok, err := SignToken(ksp, sampleToken())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "tok/") || strings.Count(tok, ".") != 1 {
		t.Errorf("the token %q is not of the form tok/<token>.<signature>", tok)
	}
	_, other := testKSP(t, 2)
	for _, s := range []string{tok, "  " + tok + "\r\n"} {
		got, err := ParseToken(s, []ed25519.PublicKey{other, pub})
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		want := sampleToken()
		if !got.Issued.Equal(want.Issued) || !got.Expires.Equal(want.Expires) {
			t.Errorf("the times are %v..%v, want %v..%v", got.Issued, got.Expires, want.Issued, want.Expires)
		}
		if got.LicenceID != want.LicenceID || got.Tier != want.Tier || got.Nodes != want.Nodes || got.Fingerprint != want.Fingerprint {
			t.Errorf("the token holds %+v, want %+v", got, want)
		}
	}
}

// A token that is malformed, changed after signing, or signed with another key does not verify.
func TestParseTokenRefuses(t *testing.T) {
	ksp, pub := testKSP(t, 1)
	otherKSP, _ := testKSP(t, 2)
	tok, err := SignToken(ksp, sampleToken())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := SignToken(otherKSP, sampleToken())
	if err != nil {
		t.Fatal(err)
	}
	payload, sig, _ := strings.Cut(strings.TrimPrefix(tok, "tok/"), ".")
	b, _ := base64.RawURLEncoding.DecodeString(payload)
	more := strings.Replace(string(b), `"nodes":50`, `"nodes":5000`, 1)
	tampered := "tok/" + base64.RawURLEncoding.EncodeToString([]byte(more)) + "." + sig
	for _, c := range []struct{ name, token, want string }{
		{"empty", "", "not of the form"},
		{"no prefix", strings.TrimPrefix(tok, "tok/"), "not of the form"},
		{"no signature", "tok/" + payload, "not of the form"},
		{"bad base64", "tok/!!." + sig, "not base64url"},
		{"short signature", "tok/" + payload + ".AAAA", "not the base64url of an Ed25519 signature"},
		{"tampered", tampered, "not signed with a Ranz vendor key"},
		{"foreign vendor", foreign, "not signed with a Ranz vendor key"},
	} {
		_, err := ParseToken(c.token, []ed25519.PublicKey{pub})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrInvalid that says %q", c.name, err, c.want)
		}
	}
	if _, err := ParseToken(tok, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("with no vendor key built in, a token verified: %v", err)
	}
}

// The signer cannot sign a token the install would refuse.
func TestSignTokenRefusesInvalid(t *testing.T) {
	ksp, _ := testKSP(t, 1)
	for _, c := range []struct {
		name string
		edit func(*Token)
		want string
	}{
		{"tier", func(t *Token) { t.Tier = "Gold" }, `the tier must be Personal, Business or Enterprise, not "Gold"`},
		{"nodes", func(t *Token) { t.Nodes = 0 }, "the node count must be at least 1, not 0"},
		{"fingerprint", func(t *Token) { t.Fingerprint = "  " }, "the token is not locked to a machine fingerprint"},
		{"expiry", func(t *Token) { t.Expires = time.Time{} }, "the token has no expiry"},
		{"order", func(t *Token) { t.Expires = t.Issued.Add(-time.Hour) }, "the token expires before it was issued"},
	} {
		tok := sampleToken()
		c.edit(&tok)
		_, err := SignToken(ksp, tok)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrInvalid that says %q", c.name, err, c.want)
		}
	}
}

// Resolve: a valid token gives its tier; no vendor key, a foreign, mismatched or expired token
// gives the Personal tier. Criterion: with no vendor signing key linked, every install resolves to
// Personal (ADR-0036 amendment of 2026-10-22).
func TestResolve(t *testing.T) {
	ksp, pub := testKSP(t, 1)
	_, foreignPub := testKSP(t, 2)
	ent := sampleToken()
	ent.Tier, ent.Features = licence.Enterprise, licence.Enterprise.Features()
	entTok, err := SignToken(ksp, ent)
	if err != nil {
		t.Fatal(err)
	}
	now := tokenIssued.Add(time.Minute)

	// A valid Enterprise token on a machine that matches: the Enterprise tier is in force.
	st := Resolve(entTok, "fp-a", []ed25519.PublicKey{pub}, now, "1.0")
	if st.Tier != licence.Enterprise || st.State != licence.StateActive || !st.Allows(licence.FeatureEVPN) || !st.Allows(licence.FeatureHA) {
		t.Errorf("a valid Enterprise token resolved to %+v", st)
	}

	for _, c := range []struct {
		name   string
		token  string
		fp     string
		vendor []ed25519.PublicKey
		now    time.Time
	}{
		{"no vendor key linked (nil)", entTok, "fp-a", nil, now},
		{"no vendor key linked (empty)", entTok, "fp-a", []ed25519.PublicKey{}, now},
		{"foreign vendor key only", entTok, "fp-a", []ed25519.PublicKey{foreignPub}, now},
		{"node mismatch", entTok, "fp-b", []ed25519.PublicKey{pub}, now},
		{"expired token", entTok, "fp-a", []ed25519.PublicKey{pub}, ent.Expires},
		{"garbage token", "tok/nonsense", "fp-a", []ed25519.PublicKey{pub}, now},
	} {
		st := Resolve(c.token, c.fp, c.vendor, c.now, "1.0")
		if st.Tier != licence.Personal || st.Nodes != licence.PersonalNodes || st.State != licence.StateNone {
			t.Errorf("%s: resolved to %+v, want the Personal tier", c.name, st)
		}
		if st.Allows(licence.FeatureEVPN) || st.Allows(licence.FeatureHA) {
			t.Errorf("%s: the Personal tier has Enterprise features: %v", c.name, st.Features)
		}
		if st.Message == "" || st.Version != "1.0" {
			t.Errorf("%s: message %q, version %q", c.name, st.Message, st.Version)
		}
	}
}

// The revocation list signs the same bytes whatever order the ids arrive in, and a changed list
// does not verify.
func TestRevocationSignAndVerify(t *testing.T) {
	ksp, pub := testKSP(t, 1)
	issued := tokenIssued
	a := RevocationList{IDs: []string{"biz-9", "biz-1", "ent-4"}, Issued: issued}
	b := RevocationList{IDs: []string{"ent-4", "biz-1", "biz-9"}, Issued: issued}
	sig, err := SignRevocations(ksp, a)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRevocations(a, sig, []ed25519.PublicKey{pub}) {
		t.Error("the revocation list does not verify against its own signature")
	}
	if !VerifyRevocations(b, sig, []ed25519.PublicKey{pub}) {
		t.Error("the same ids in another order did not verify against the same signature")
	}
	tampered := RevocationList{IDs: []string{"biz-1"}, Issued: issued}
	if VerifyRevocations(tampered, sig, []ed25519.PublicKey{pub}) {
		t.Error("a changed revocation list verified")
	}
	if !a.contains("biz-1") || a.contains("absent") {
		t.Error("contains is wrong")
	}
}

// SoftKSP signs through the crypto.Signer interface and never exposes the private key: the only way
// to a signature is Sign, the same boundary the HSM or the CNG KSP sits behind.
func TestSoftKSPSignsThroughInterface(t *testing.T) {
	ksp, err := GenerateSoftKSP()
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := ksp.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the public key is %T, not an Ed25519 key", ksp.Public())
	}
	msg := []byte("tok/payload")
	sig, err := signEd25519(ksp, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("a signature made through the signer does not verify")
	}
	if _, err := NewSoftKSP([]byte("short")); err == nil {
		t.Error("a short seed was accepted")
	}
}
