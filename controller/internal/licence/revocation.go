package licence

// A revocation list is the vendor's signed list of the licence keys the controller must refuse
// (ADR-0036, SEC-5 #283). The vendor cuts it, signs it with the same private key as a licence key,
// and ships it to each install by update. The controller verifies it with the vendor public keys
// built in, applies it, and refuses a licence key whose id is on the list. The core tunnel is
// never gated on it: a refused key only drops the install to the Personal tier.
//
// A signed revocation list has the form of a licence key, with its own prefix so the two can
// never be confused: "revoke/", the base64url (no padding) of the list as JSON, ".", and the
// base64url of the Ed25519 signature of everything before the dot.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// revokePrefix starts every signed revocation list and is part of what the signature covers.
const revokePrefix = "revoke/"

// Revocations is a revocation list: the ids of the licence keys the vendor revoked.
type Revocations struct {
	Issued time.Time `json:"issued"` // when the vendor cut this list
	IDs    []string  `json:"ids"`    // the ids (Licence.ID) of the revoked licence keys
}

// Revokes reports whether the list revokes the licence key l: its id is on the list.
func (r Revocations) Revokes(l Licence) bool {
	return slices.Contains(r.IDs, l.ID)
}

// SignRevocations returns the signed revocation list that holds r, signed with the vendor's
// private key.
func SignRevocations(vendor ed25519.PrivateKey, r Revocations) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	signed := revokePrefix + base64.RawURLEncoding.EncodeToString(b)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(vendor, []byte(signed))), nil
}

// ParseRevocations checks that the signed revocation list s is signed with one of the vendor keys
// and returns what it holds. Space around it, as a list file has, is ignored.
func ParseRevocations(s string, vendor []ed25519.PublicKey) (Revocations, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, revokePrefix)
	payload, sig, dot := strings.Cut(rest, ".")
	if !ok || !dot {
		return Revocations{}, fmt.Errorf("%w: it is not of the form revoke/<list>.<signature>", ErrInvalid)
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Revocations{}, fmt.Errorf("%w: the list is not base64url: %w", ErrInvalid, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Revocations{}, fmt.Errorf("%w: the signature is not the base64url of an Ed25519 signature", ErrInvalid)
	}
	signed := []byte(revokePrefix + payload)
	if !slices.ContainsFunc(vendor, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, signed, signature) }) {
		return Revocations{}, fmt.Errorf("%w: it is not signed with a Ranz vendor key", ErrInvalid)
	}
	var r Revocations
	if err := json.Unmarshal(b, &r); err != nil {
		return Revocations{}, fmt.Errorf("%w: the list is not JSON: %w", ErrInvalid, err)
	}
	return r, nil
}
