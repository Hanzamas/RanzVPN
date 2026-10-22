package activation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"strings"
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

// FuzzOpenFeature opens the input as a sealed Enterprise feature blob, under a fixed key and under a
// key taken from the input: a blob that opens yields a plaintext that seals and opens again to the
// same bytes, and every other input fails without a panic.
func FuzzOpenFeature(f *testing.F) {
	key := []byte("feature-key")
	sealed, err := SealFeature(key, []byte("enterprise feature"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(key, sealed)
	f.Add([]byte{}, sealed)
	f.Add(key, []byte{})
	f.Add(key, sealed[:len(sealed)-1])

	f.Fuzz(func(t *testing.T, k, blob []byte) {
		plain, err := OpenFeature(k, blob)
		if err != nil {
			return
		}
		again, err := SealFeature(k, plain)
		if err != nil {
			t.Fatalf("a feature blob of %q opened under %q but its plaintext does not seal: %v", blob, k, err)
		}
		if got, err := OpenFeature(k, again); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("the plaintext of the blob %q does not survive a seal and an open: %v", blob, err)
		}
	})
}

// FuzzOpenOfflineResponse reads the input as the fields of an offline request and of its response.
// The response is signed with the vendor key over the fuzzed fields, so that the nonce and token
// checks behind the signature are reached: a response that opens answers the request's nonce and
// carries a token that is locked to the request's fingerprint.
func FuzzOpenOfflineResponse(f *testing.F) {
	ksp, err := NewSoftKSP(slices.Repeat([]byte{1}, ed25519.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	tok, err := SignToken(ksp, sampleToken())
	if err != nil {
		f.Fatal(err)
	}
	vendor := []ed25519.PublicKey{ksp.Public().(ed25519.PublicKey)}
	fp := sampleToken().Fingerprint
	f.Add(tok, "nonce-1", "nonce-1", fp)
	f.Add(tok, "nonce-1", "nonce-2", fp)
	f.Add(tok, "nonce-1", "nonce-1", "another-machine")
	f.Add("not a token", "n", "n", "fp")

	f.Fuzz(func(t *testing.T, token, respNonce, reqNonce, fingerprint string) {
		req := SignedOfflineRequest{OfflineRequest: OfflineRequest{Fingerprint: fingerprint, Nonce: reqNonce}}
		resp := SignedOfflineResponse{OfflineResponse: OfflineResponse{Token: token, Nonce: respNonce}}
		msg, err := resp.OfflineResponse.message()
		if err != nil {
			t.Skip()
		}
		sig, err := signEd25519(ksp, msg)
		if err != nil {
			t.Fatal(err)
		}
		resp.Signature = base64.StdEncoding.EncodeToString(sig)
		got, err := OpenOfflineResponse(req, resp, vendor)
		if err != nil {
			return
		}
		if respNonce != reqNonce || got != token {
			t.Fatalf("a response with the nonce %q and the token %q opened for a request with the nonce %q", respNonce, token, reqNonce)
		}
		parsed, err := ParseToken(got, vendor)
		if err != nil || parsed.Fingerprint != strings.TrimSpace(fingerprint) {
			t.Fatalf("the opened token %q is not locked to the fingerprint %q: %+v, %v", got, fingerprint, parsed, err)
		}
	})
}
