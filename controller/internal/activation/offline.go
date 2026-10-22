package activation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// The offline activation file (ADR-0036 amendment of 2026-10-22, SEC-6 #285). An air-gapped or
// industrial install that cannot reach the activation service activates by a file exchanged by hand:
// the install writes a signed request, the vendor reads it on a connected machine and writes a
// signed response, and the install reads the response and holds the token it carries. No side
// touches the network, so that segment is never locked out.
//
// The request carries the vendor-signed Licence key (the credential the vendor verifies) and is
// itself signed with an ephemeral key, so tampering in transit is caught. The response is signed
// with the vendor key, so the install verifies it offline with the vendor key built into the
// release, the same key that verifies an online token.

// OfflineRequest is the activation request an air-gapped install writes to a file and carries to the
// vendor by hand.
type OfflineRequest struct {
	// Key is the vendor-signed Licence key, the signed credential the vendor verifies.
	Key string `json:"key"`
	// Fingerprint is this machine's fingerprint, which the token must be locked to.
	Fingerprint string `json:"fingerprint"`
	// Nonce ties the one response back to this request.
	Nonce string `json:"nonce"`
	// Issued is when the install wrote the request.
	Issued time.Time `json:"issued"`
}

// SignedOfflineRequest is an OfflineRequest with the ephemeral signature over it, so the request
// file is tamper-evident in transit. Its identity is the vendor-signed Licence key it carries, not
// the ephemeral key.
type SignedOfflineRequest struct {
	OfflineRequest
	// PublicKey is the base64 of the ephemeral Ed25519 key the request is signed with.
	PublicKey string `json:"publicKey"`
	// Signature is the base64 of the Ed25519 signature over the request by PublicKey.
	Signature string `json:"signature"`
}

// OfflineResponse is the vendor's answer to an offline request: the activation token for the
// request's fingerprint, and the request nonce echoed.
type OfflineResponse struct {
	// Token is the vendor-signed, node-locked, time-limited activation token.
	Token string `json:"token"`
	// Nonce is the request nonce, echoed so the install ties the response to its request.
	Nonce string `json:"nonce"`
}

// SignedOfflineResponse is an OfflineResponse with the vendor signature over it, so the install
// verifies it offline with the vendor key built into the release.
type SignedOfflineResponse struct {
	OfflineResponse
	// Signature is the base64 of the Ed25519 vendor signature over the response.
	Signature string `json:"signature"`
}

// NewOfflineRequest builds the signed offline activation request for a Licence key and this
// machine's fingerprint. The install writes the returned request to a file and keeps it (its nonce
// and fingerprint) to check the response; the ephemeral signing key is used once and discarded.
func NewOfflineRequest(key, fingerprint string, now time.Time) (SignedOfflineRequest, error) {
	fp := strings.TrimSpace(fingerprint)
	if fp == "" {
		return SignedOfflineRequest{}, errors.New("activation: the offline request has no machine fingerprint")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SignedOfflineRequest{}, fmt.Errorf("activation: %w", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return SignedOfflineRequest{}, fmt.Errorf("activation: %w", err)
	}
	req := SignedOfflineRequest{
		OfflineRequest: OfflineRequest{
			Key:         strings.TrimSpace(key),
			Fingerprint: fp,
			Nonce:       base64.RawURLEncoding.EncodeToString(nonce[:]),
			Issued:      now.UTC(),
		},
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	msg, err := req.message()
	if err != nil {
		return SignedOfflineRequest{}, err
	}
	req.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return req, nil
}

// SignOffline validates an offline activation request and returns the signed response that activates
// the install, with no network. It verifies the request's own signature (the tamper check), the
// Licence key against the vendor keys and the subscription, locks the token to the request's
// fingerprint as an online activation does (the same node-lock and revocation checks), signs the
// token through the KSP or HSM boundary, and signs the response so the install verifies it offline.
func (s *Service) SignOffline(req SignedOfflineRequest) (SignedOfflineResponse, error) {
	if err := req.verify(); err != nil {
		return SignedOfflineResponse{}, err
	}
	fp := strings.TrimSpace(req.Fingerprint)
	if fp == "" {
		return SignedOfflineResponse{}, errors.New("activation: the offline request has no machine fingerprint")
	}
	l, err := licence.Parse(req.Key, s.licenceKeys)
	if err != nil {
		return SignedOfflineResponse{}, fmt.Errorf("%w: the Licence key is not valid: %w", ErrInvalid, err)
	}
	now := s.now()
	if st := licence.Evaluate(&l, now, "0.0"); st.State != licence.StateActive {
		return SignedOfflineResponse{}, fmt.Errorf("%w: the subscription is not active", ErrInvalid)
	}

	s.mu.Lock()
	if s.gone[l.ID] {
		s.mu.Unlock()
		return SignedOfflineResponse{}, ErrRevoked
	}
	if bound, ok := s.bound[l.ID]; ok && bound != fp {
		s.mu.Unlock()
		return SignedOfflineResponse{}, ErrMismatch
	}
	s.bound[l.ID] = fp
	s.mu.Unlock()

	tok, err := SignToken(s.signer, Token{
		LicenceID:   l.ID,
		Licensee:    l.Licensee,
		Tier:        l.Tier,
		Nodes:       l.Nodes,
		Features:    l.Tier.Features(),
		Fingerprint: fp,
		Issued:      now,
		Expires:     now.Add(s.ttl),
	})
	if err != nil {
		return SignedOfflineResponse{}, err
	}
	resp := OfflineResponse{Token: tok, Nonce: req.Nonce}
	msg, err := resp.message()
	if err != nil {
		return SignedOfflineResponse{}, err
	}
	sig, err := signEd25519(s.signer, msg)
	if err != nil {
		return SignedOfflineResponse{}, err
	}
	return SignedOfflineResponse{OfflineResponse: resp, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// OpenOfflineResponse verifies the vendor's offline response against the request and the vendor keys
// built into the release, and returns the activation token it carries. It checks the vendor
// signature, that the nonce matches the request, and that the token is locked to the request's
// fingerprint. With no vendor key linked nothing verifies and the install stays Personal.
func OpenOfflineResponse(req SignedOfflineRequest, resp SignedOfflineResponse, vendor []ed25519.PublicKey) (string, error) {
	if len(vendor) == 0 {
		return "", fmt.Errorf("%w: no vendor key is linked into this build", ErrInvalid)
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: the offline response signature is not an Ed25519 signature", ErrInvalid)
	}
	msg, err := resp.OfflineResponse.message()
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(vendor, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, msg, sig) }) {
		return "", fmt.Errorf("%w: the offline response is not signed with a Ranz vendor key", ErrInvalid)
	}
	if resp.Nonce != req.Nonce {
		return "", fmt.Errorf("%w: the offline response does not answer this request", ErrInvalid)
	}
	t, err := ParseToken(resp.Token, vendor)
	if err != nil {
		return "", err
	}
	if t.Fingerprint != strings.TrimSpace(req.Fingerprint) {
		return "", fmt.Errorf("%w: the offline response is locked to another machine", ErrMismatch)
	}
	return resp.Token, nil
}

// verify checks the request's own ephemeral signature, so a request changed after it was signed is
// caught before the Licence key is read.
func (r SignedOfflineRequest) verify() error {
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: the offline request key is not an Ed25519 public key", ErrInvalid)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the offline request signature is not an Ed25519 signature", ErrInvalid)
	}
	msg, err := r.message()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("%w: the offline request was changed after it was signed", ErrInvalid)
	}
	return nil
}

// message is the canonical bytes that the request's own signature covers: the request and its
// ephemeral public key, with the signature field cleared.
func (r SignedOfflineRequest) message() ([]byte, error) {
	r.Signature = ""
	return json.Marshal(r)
}

// message is the canonical bytes that the vendor signature covers.
func (r OfflineResponse) message() ([]byte, error) {
	return json.Marshal(r)
}
