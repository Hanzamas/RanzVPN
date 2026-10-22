package activation

import (
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// The fuzz test of the activation package (ADR-0040 item 1, .github/quality/fuzz-targets.txt),
// which the controller workflow runs with go test -fuzz.

// FuzzParseToken reads the input as an activation token (ParseToken), then signs it with the vendor
// key as the JSON of a token and parses that, so that the JSON and the checks behind the signature
// are reached too: a token that parses is in force on its own machine, with its tier and node cap,
// from its issue until its expiry.
func FuzzParseToken(f *testing.F) {
	ksp, err := NewSoftKSP(slices.Repeat([]byte{1}, ed25519.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	tok, err := SignToken(ksp, sampleToken())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok)
	f.Add(`{"licenceId":"biz-1","licensee":"Example Ltd","tier":"Business","nodes":50,"fingerprint":"fp-a","issued":"2026-10-22T12:00:00Z","expires":"2026-10-22T13:00:00Z"}`)
	f.Add(`{"tier":"Enterprise","nodes":1,"fingerprint":"fp-b","expires":"2027-10-22T00:00:00Z"}`)
	vendor := []ed25519.PublicKey{ksp.Public().(ed25519.PublicKey)}

	// The token s, read from the input in, resolved on its machine at its issue
	resolve := func(t *testing.T, in, s string) {
		parsed, err := ParseToken(s, vendor)
		if err != nil {
			return
		}
		st := Resolve(s, parsed.Fingerprint, vendor, parsed.Issued, "1.0")
		if st.State != licence.StateActive || st.Tier != parsed.Tier || st.Nodes != parsed.Nodes {
			t.Fatalf("the token of %q parses as %+v and resolves to %+v", in, parsed, st)
		}
	}

	f.Fuzz(func(t *testing.T, s string) {
		resolve(t, s, s)
		signed := tokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(s))
		sig, err := signEd25519(ksp, []byte(signed))
		if err != nil {
			t.Fatal(err)
		}
		resolve(t, s, signed+"."+base64.RawURLEncoding.EncodeToString(sig))
	})
}
