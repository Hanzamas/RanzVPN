// Package activation is the Hanzcodes licensing and activation server, new vendor infrastructure
// of the amendment of 2026-10-22 to ADR-0036 (SEC-7, #284). On install the node or the controller
// sends it a Licence key and a machine fingerprint, and it returns a signed, node-locked,
// time-limited activation token. It holds the Enterprise feature key and releases it only against
// an Enterprise token, re-validates the token on a periodic heartbeat, and distributes the
// revocation list. The production service is highly available and its signing key lives in an HSM
// or a CNG KSP, a near-release step; this package is the service and the KSP path, provable in CI,
// where a software KSP stands in for the HSM.
//
// The signing key is reached only through the crypto.Signer interface, the same boundary the
// controller's keys sit behind (internal/keys), so the private key stays inside the provider that
// holds it. An activation token has the form of the Licence key (internal/licence): "tok/", the
// base64url (no padding) of the token as JSON, ".", and the base64url of the Ed25519 signature of
// everything before the dot. The install verifies it with a vendor public key built into the
// release. Until that vendor signing key is linked, no token verifies and every install runs the
// Personal tier.
package activation

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

var (
	// ErrInvalid marks an activation token or a request that is malformed or not signed with a
	// vendor key.
	ErrInvalid = errors.New("invalid activation token")
	// ErrMismatch marks a request whose machine fingerprint is locked to another machine.
	ErrMismatch = errors.New("node mismatch")
	// ErrRevoked marks a Licence whose activation has been revoked.
	ErrRevoked = errors.New("revoked licence")
)

// tokenPrefix starts every activation token and is part of what the signature covers.
const tokenPrefix = "tok/"

// Token is what the activation service issues: a node-locked, time-limited grant of a tier and its
// features for one installation (ADR-0036 amendment of 2026-10-22). Past its expiry a heartbeat
// renews it; without a valid token the install runs the Personal tier.
type Token struct {
	// LicenceID is the vendor id of the Licence key this activates.
	LicenceID string `json:"licenceId"`
	// Licensee is who the Licence was sold to.
	Licensee string `json:"licensee"`
	// Tier is the tier the token grants.
	Tier licence.Tier `json:"tier"`
	// Nodes is the node cap of the Licence.
	Nodes int `json:"nodes"`
	// Features are the features of the tier beyond the core.
	Features []licence.Feature `json:"features"`
	// Fingerprint is the machine fingerprint the token is locked to.
	Fingerprint string `json:"fingerprint"`
	// Issued is when the service signed the token.
	Issued time.Time `json:"issued"`
	// Expires is the end of the token's life, not of the subscription.
	Expires time.Time `json:"expires"`
}

// SoftKSP is a vendor signing key held in memory: a software key storage provider that stands in
// for the HSM or the CNG KSP in CI, where no hardware is available (ADR-0036 amendment of
// 2026-10-22). It carries an Ed25519 key and signs through the crypto.Signer interface, the same
// boundary a hardware provider sits behind, so the licensing server never reads the private key.
type SoftKSP struct {
	priv ed25519.PrivateKey
}

// GenerateSoftKSP returns a new random software signing key.
func GenerateSoftKSP() (*SoftKSP, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	return &SoftKSP{priv: priv}, nil
}

// NewSoftKSP returns the software signing key of the 32-byte Ed25519 seed, so a test needs no
// random source.
func NewSoftKSP(seed []byte) (*SoftKSP, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("activation: the seed is %d bytes, not %d", len(seed), ed25519.SeedSize)
	}
	return &SoftKSP{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Public returns the Ed25519 public key, the half built into the release to verify tokens.
func (k *SoftKSP) Public() crypto.PublicKey {
	return k.priv.Public()
}

// Sign signs message with Ed25519. It follows crypto.Signer: for the pure Ed25519 scheme opts
// must report crypto.Hash(0) and message is the whole message, not a digest.
func (k *SoftKSP) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.priv.Sign(rand.Reader, message, opts)
}

// SignToken returns the activation token that holds t, signed through the signer. The signer is the
// vendor signing key behind the KSP or HSM boundary; its private half never enters this package.
func SignToken(signer crypto.Signer, t Token) (string, error) {
	if err := t.validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	signed := tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	sig, err := signEd25519(signer, []byte(signed))
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ParseToken checks that the activation token s is signed with one of the vendor keys and returns
// what it holds.
func ParseToken(s string, vendor []ed25519.PublicKey) (Token, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, tokenPrefix)
	payload, sig, dot := strings.Cut(rest, ".")
	if !ok || !dot {
		return Token{}, fmt.Errorf("%w: it is not of the form tok/<token>.<signature>", ErrInvalid)
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the token is not base64url: %w", ErrInvalid, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Token{}, fmt.Errorf("%w: the signature is not the base64url of an Ed25519 signature", ErrInvalid)
	}
	signed := []byte(tokenPrefix + payload)
	if !slices.ContainsFunc(vendor, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, signed, signature) }) {
		return Token{}, fmt.Errorf("%w: it is not signed with a Ranz vendor key", ErrInvalid)
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return Token{}, fmt.Errorf("%w: the token is not JSON: %w", ErrInvalid, err)
	}
	if err := t.validate(); err != nil {
		return Token{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return t, nil
}

// Resolve returns the licence in force for the activation token at now on an install of version v,
// given the vendor public keys built into the release. With no vendor signing key linked (an empty
// slice) no token verifies and the Personal tier is in force, so a development build and a release
// whose vendor signing key is not yet linked both run Personal (ADR-0036 amendment of 2026-10-22).
// A token that does not verify, is locked to another machine, or has expired also resolves to
// Personal; a heartbeat renews an expired token.
func Resolve(token, fingerprint string, vendor []ed25519.PublicKey, now time.Time, v string) licence.Status {
	personal := licence.Status{
		Tier: licence.Personal, Nodes: licence.PersonalNodes, Features: licence.Personal.Features(),
		State: licence.StateNone, Version: v,
	}
	if len(vendor) == 0 {
		personal.Message = fmt.Sprintf("no vendor signing key is linked into this build: the %s tier is in force, up to %d nodes",
			licence.Personal, licence.PersonalNodes)
		return personal
	}
	t, err := ParseToken(token, vendor)
	switch {
	case err != nil:
		personal.Message = fmt.Sprintf("no valid activation token: the %s tier is in force, up to %d nodes",
			licence.Personal, licence.PersonalNodes)
		return personal
	case t.Fingerprint != fingerprint:
		personal.Message = fmt.Sprintf("the activation token is locked to another machine: the %s tier is in force, up to %d nodes",
			licence.Personal, licence.PersonalNodes)
		return personal
	case !now.Before(t.Expires):
		personal.Message = fmt.Sprintf("the activation token expired at %s: the %s tier is in force until a heartbeat renews it, up to %d nodes",
			stamp(t.Expires), licence.Personal, licence.PersonalNodes)
		return personal
	}
	key := licence.Licence{ID: t.LicenceID, Licensee: t.Licensee, Tier: t.Tier, Nodes: t.Nodes, Expires: t.Expires}
	return licence.Status{
		Tier: t.Tier, Nodes: t.Nodes, Features: t.Tier.Features(), State: licence.StateActive, Version: v, Key: &key,
		Message: fmt.Sprintf("the %s activation token %s of %s: %d nodes until %s", t.Tier, t.LicenceID, t.Licensee, t.Nodes, stamp(t.Expires)),
	}
}

// validate checks what an activation token holds.
func (t Token) validate() error {
	var problems []error
	switch t.Tier {
	case licence.Personal, licence.Business, licence.Enterprise:
	default:
		problems = append(problems, fmt.Errorf("the tier must be %s, %s or %s, not %q",
			licence.Personal, licence.Business, licence.Enterprise, t.Tier))
	}
	if t.Nodes < 1 {
		problems = append(problems, fmt.Errorf("the node count must be at least 1, not %d", t.Nodes))
	}
	if strings.TrimSpace(t.Fingerprint) == "" {
		problems = append(problems, errors.New("the token is not locked to a machine fingerprint"))
	}
	if t.Expires.IsZero() {
		problems = append(problems, errors.New("the token has no expiry"))
	} else if !t.Expires.After(t.Issued) {
		problems = append(problems, errors.New("the token expires before it was issued"))
	}
	return errors.Join(problems...)
}

// publicEd25519 returns the Ed25519 public half of signer, so the service can verify the tokens it
// issued.
func publicEd25519(signer crypto.Signer) (ed25519.PublicKey, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("activation: the signing key is not an Ed25519 key")
	}
	return pub, nil
}

// signEd25519 signs message through signer and checks the result is an Ed25519 signature.
func signEd25519(signer crypto.Signer, message []byte) ([]byte, error) {
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("activation: signing: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("activation: the signer did not return an Ed25519 signature")
	}
	return sig, nil
}

// stamp formats a time in messages and tokens.
func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
