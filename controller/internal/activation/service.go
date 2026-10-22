package activation

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// defaultTokenTTL is the life of an activation token when the config names none: short enough that
// a withdrawn Licence loses its tier soon after the revocation list reaches the install, long
// enough that one missed heartbeat does not degrade a paying customer.
const defaultTokenTTL = 7 * 24 * time.Hour

// maxBody bounds a request body; an activation request is a Licence key and a fingerprint.
const maxBody = 64 << 10

// Config builds a Service.
type Config struct {
	// Signer is the vendor signing key behind the KSP or HSM boundary. The service reaches the key
	// only through it, so the private half never enters the service. Required.
	Signer crypto.Signer
	// LicenceKeys are the vendor public keys that a Licence key presented for activation is signed
	// with (internal/licence). Required to activate a Licence key.
	LicenceKeys []ed25519.PublicKey
	// FeatureKey is the Enterprise feature key, released only against an Enterprise token. It lives
	// in memory only.
	FeatureKey []byte
	// TokenTTL is the life of an issued token; defaultTokenTTL when zero.
	TokenTTL time.Duration
	// Now reads the clock; time.Now when nil.
	Now func() time.Time
}

// Service is the activation service. It issues node-locked, time-limited tokens, releases the
// Enterprise feature key against an Enterprise token, re-validates a token on a heartbeat, and
// serves the revocation list. It is safe for concurrent use.
type Service struct {
	// signer is the vendor signing key behind the KSP or HSM boundary.
	signer crypto.Signer
	// vendor is the signer's own public half, to verify the tokens the service issued.
	vendor []ed25519.PublicKey
	// licenceKeys are the vendor keys that a Licence key presented for activation is signed with.
	licenceKeys []ed25519.PublicKey
	// featureKey is the Enterprise feature key, released only against an Enterprise token.
	featureKey []byte
	// ttl is the life of an issued token.
	ttl time.Duration
	// now reads the clock.
	now func() time.Time

	// mu guards bound and gone.
	mu sync.Mutex
	// bound maps a Licence id to the machine fingerprint its seat is locked to.
	bound map[string]string
	// gone is the set of revoked Licence ids.
	gone map[string]bool
}

// New returns a Service built from cfg.
func New(cfg Config) (*Service, error) {
	if cfg.Signer == nil {
		return nil, errors.New("activation: the config names no signing key")
	}
	pub, err := publicEd25519(cfg.Signer)
	if err != nil {
		return nil, err
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		signer:      cfg.Signer,
		vendor:      []ed25519.PublicKey{pub},
		licenceKeys: slices.Clone(cfg.LicenceKeys),
		featureKey:  slices.Clone(cfg.FeatureKey),
		ttl:         ttl,
		now:         now,
		bound:       map[string]string{},
		gone:        map[string]bool{},
	}, nil
}

// VendorKey returns the public half of the signing key, the half a release links in to verify
// tokens and the revocation list.
func (s *Service) VendorKey() ed25519.PublicKey {
	return slices.Clone(s.vendor[0])
}

// Revoke withdraws the activation of the Licence id. The next heartbeat and feature-key request for
// it are refused, and it appears in the revocation list.
func (s *Service) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gone[id] = true
}

// ActivateRequest activates a Licence key for a machine.
type ActivateRequest struct {
	// Key is the Licence key to activate.
	Key string `json:"key"`
	// Fingerprint is the machine fingerprint to lock the token to.
	Fingerprint string `json:"fingerprint"`
}

// HeartbeatRequest re-validates an activation token.
type HeartbeatRequest struct {
	// Token is the activation token to re-validate.
	Token string `json:"token"`
	// Fingerprint is the machine fingerprint the token is locked to.
	Fingerprint string `json:"fingerprint"`
}

// FeatureKeyRequest asks for the Enterprise feature key.
type FeatureKeyRequest struct {
	// Token is the Enterprise activation token.
	Token string `json:"token"`
	// Fingerprint is the machine fingerprint the token is locked to.
	Fingerprint string `json:"fingerprint"`
}

// TokenResponse carries an issued or renewed token.
type TokenResponse struct {
	Token string `json:"token"`
}

// FeatureKeyResponse carries the Enterprise feature key, base64.
type FeatureKeyResponse struct {
	Key string `json:"key"`
}

// RevocationsResponse carries the signed revocation list.
type RevocationsResponse struct {
	RevocationList
	Signature string `json:"signature"`
}

// problem is an error body.
type problem struct {
	Error string `json:"error"`
}

// Handler returns the HTTP handler of the service.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /activation/v1/activate", s.handleActivate)
	mux.HandleFunc("POST /activation/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /activation/v1/feature-key", s.handleFeatureKey)
	mux.HandleFunc("GET /activation/v1/revocations", s.handleRevocations)
	return mux
}

// handleActivate issues a node-locked, time-limited token for a valid Licence key and fingerprint,
// and refuses an invalid or node-mismatched request.
func (s *Service) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req ActivateRequest
	if !decode(w, r, &req) {
		return
	}
	fp := strings.TrimSpace(req.Fingerprint)
	if fp == "" {
		writeProblem(w, http.StatusBadRequest, "the request names no machine fingerprint")
		return
	}
	l, err := licence.Parse(req.Key, s.licenceKeys)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "the Licence key is not valid: "+err.Error())
		return
	}
	now := s.now()
	st := licence.Evaluate(&l, now, "0.0") // the install version does not gate activation; the subscription does
	if st.State != licence.StateActive {
		writeProblem(w, http.StatusForbidden, "the subscription is not active: activate a current Licence")
		return
	}

	s.mu.Lock()
	if s.gone[l.ID] {
		s.mu.Unlock()
		writeProblem(w, http.StatusForbidden, "the Licence activation has been revoked")
		return
	}
	if bound, ok := s.bound[l.ID]; ok && bound != fp {
		s.mu.Unlock()
		writeProblem(w, http.StatusConflict, ErrMismatch.Error()+": the Licence is already activated on another machine")
		return
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
		writeProblem(w, http.StatusInternalServerError, "signing the token: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{Token: tok})
}

// handleHeartbeat re-validates a token and renews it, or refuses a revoked or node-mismatched one.
func (s *Service) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if !decode(w, r, &req) {
		return
	}
	t, ok := s.checkToken(w, req.Token, req.Fingerprint)
	if !ok {
		return
	}
	now := s.now()
	t.Issued, t.Expires = now, now.Add(s.ttl)
	tok, err := SignToken(s.signer, t)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "signing the token: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{Token: tok})
}

// handleFeatureKey releases the Enterprise feature key, and only against an Enterprise token.
func (s *Service) handleFeatureKey(w http.ResponseWriter, r *http.Request) {
	var req FeatureKeyRequest
	if !decode(w, r, &req) {
		return
	}
	t, ok := s.checkToken(w, req.Token, req.Fingerprint)
	if !ok {
		return
	}
	if !s.now().Before(t.Expires) {
		writeProblem(w, http.StatusForbidden, "the activation token has expired; renew it on a heartbeat")
		return
	}
	if t.Tier != licence.Enterprise {
		writeProblem(w, http.StatusForbidden, "the feature key is released only against an Enterprise token")
		return
	}
	writeJSON(w, http.StatusOK, FeatureKeyResponse{Key: base64.StdEncoding.EncodeToString(s.featureKey)})
}

// handleRevocations serves the signed revocation list.
func (s *Service) handleRevocations(w http.ResponseWriter, _ *http.Request) {
	list := s.revocations()
	sig, err := SignRevocations(s.signer, list)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "signing the revocation list: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, RevocationsResponse{RevocationList: list, Signature: base64.StdEncoding.EncodeToString(sig)})
}

// revocations returns the current revocation list.
func (s *Service) revocations() RevocationList {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.gone))
	for id := range s.gone {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return RevocationList{IDs: ids, Issued: s.now()}
}

// checkToken parses a token, confirms it is locked to fingerprint and not revoked, and writes the
// refusal itself when it is not usable.
func (s *Service) checkToken(w http.ResponseWriter, token, fingerprint string) (Token, bool) {
	t, err := ParseToken(token, s.vendor)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "the activation token is not valid: "+err.Error())
		return Token{}, false
	}
	if t.Fingerprint != strings.TrimSpace(fingerprint) {
		writeProblem(w, http.StatusConflict, ErrMismatch.Error()+": the token is locked to another machine")
		return Token{}, false
	}
	s.mu.Lock()
	revoked := s.gone[t.LicenceID]
	s.mu.Unlock()
	if revoked {
		writeProblem(w, http.StatusForbidden, ErrRevoked.Error()+": the Licence activation has been withdrawn")
		return Token{}, false
	}
	return t, true
}

// decode reads a JSON body, rejecting an unknown field, and writes the error itself on failure.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "the body is not valid: "+err.Error())
		return false
	}
	return true
}

// writeJSON writes v as JSON with the status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem writes an error body with the status code.
func writeProblem(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, problem{Error: msg})
}
