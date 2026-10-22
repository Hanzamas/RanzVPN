package activation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// clock is a test clock the tests advance by hand.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// countingSigner wraps the signer and records every call, so a test can assert the service reached
// the signing key only through the crypto.Signer interface, the boundary the HSM or the CNG KSP
// sits behind (ADR-0036 amendment of 2026-10-22).
type countingSigner struct {
	inner crypto.Signer
	mu    sync.Mutex
	calls int
}

func (c *countingSigner) Public() crypto.PublicKey { return c.inner.Public() }

func (c *countingSigner) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.Sign(r, msg, opts)
}

func (c *countingSigner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// fixture builds a running service with a software KSP standing in for the HSM, a separate vendor
// key for Licence keys, and a fixed clock.
type fixture struct {
	// svc is the service under test.
	svc *Service
	// signer counts the calls through the KSP interface.
	signer *countingSigner
	// client drives the service over HTTP.
	client *Client
	// clk is the test clock.
	clk *clock
	// ttl is the token lifetime the service issues.
	ttl time.Duration
	// featureKey is the Enterprise feature key the service holds.
	featureKey []byte
	// licencePrv is the vendor private key, to sign test Licence keys.
	licencePrv ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ksp, err := NewSoftKSP(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	signer := &countingSigner{inner: ksp}
	licencePrv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	licencePub := licencePrv.Public().(ed25519.PublicKey)
	clk := &clock{at: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	featureKey := []byte("the Enterprise feature blob key")
	ttl := time.Hour
	svc, err := New(Config{
		Signer:      signer,
		LicenceKeys: []ed25519.PublicKey{licencePub},
		FeatureKey:  featureKey,
		TokenTTL:    ttl,
		Now:         clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)
	return &fixture{
		svc:        svc,
		signer:     signer,
		client:     &Client{BaseURL: srv.URL, HTTP: srv.Client()},
		clk:        clk,
		ttl:        ttl,
		featureKey: featureKey,
		licencePrv: licencePrv,
	}
}

// signLicence signs a Licence key of the tier for the fixture's vendor key.
func (f *fixture) signLicence(t *testing.T, id string, tier licence.Tier) string {
	t.Helper()
	key, err := licence.Sign(f.licencePrv, licence.Licence{
		ID: id, Licensee: "Example Ltd", Tier: tier, Nodes: 50,
		Expires: f.clk.now().Add(365 * 24 * time.Hour), FallbackVersion: "0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Criterion 1: the service issues a signed, node-locked, time-limited token for a valid Licence key
// and machine fingerprint, and refuses an invalid or node-mismatched request (ADR-0036 amendment of
// 2026-10-22, SEC-7 #284).
func TestActivateIssuesAndRefuses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := f.signLicence(t, "biz-1", licence.Business)

	tok, err := f.client.Activate(ctx, key, "fp-a")
	if err != nil {
		t.Fatalf("activating a valid Licence: %v", err)
	}
	parsed, err := ParseToken(tok, []ed25519.PublicKey{f.svc.VendorKey()})
	if err != nil {
		t.Fatalf("the issued token does not verify against the vendor key: %v", err)
	}
	if parsed.Fingerprint != "fp-a" {
		t.Errorf("the token is locked to %q, not the fingerprint sent", parsed.Fingerprint)
	}
	if parsed.Tier != licence.Business || parsed.Nodes != 50 {
		t.Errorf("the token holds tier %s, %d nodes", parsed.Tier, parsed.Nodes)
	}
	if !parsed.Expires.Equal(f.clk.now().Add(f.ttl)) || !parsed.Expires.After(parsed.Issued) {
		t.Errorf("the token is not time-limited: issued %v, expires %v, ttl %v", parsed.Issued, parsed.Expires, f.ttl)
	}
	// The install resolves the token to the Business tier on the matching machine.
	if st := Resolve(tok, "fp-a", []ed25519.PublicKey{f.svc.VendorKey()}, f.clk.now(), "1.0"); st.Tier != licence.Business || st.State != licence.StateActive {
		t.Errorf("the install resolved the token to %+v", st)
	}

	if _, err := f.client.Activate(ctx, "key/not-a-real-key.AAAA", "fp-a"); err == nil {
		t.Error("an invalid Licence key was activated")
	}
	if _, err := f.client.Activate(ctx, key, "   "); err == nil {
		t.Error("a request with no machine fingerprint was activated")
	}
	// Re-activating on the same machine is fine; a second machine is a node mismatch.
	if _, err := f.client.Activate(ctx, key, "fp-a"); err != nil {
		t.Errorf("re-activating on the same machine: %v", err)
	}
	if _, err := f.client.Activate(ctx, key, "fp-b"); err == nil {
		t.Error("the Licence was activated on a second machine")
	}
}

// Criterion 2: the Enterprise feature key is released only against an Enterprise token.
func TestFeatureKeyEnterpriseOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	entKey := f.signLicence(t, "ent-1", licence.Enterprise)
	bizKey := f.signLicence(t, "biz-1", licence.Business)

	entTok, err := f.client.Activate(ctx, entKey, "fp-ent")
	if err != nil {
		t.Fatal(err)
	}
	bizTok, err := f.client.Activate(ctx, bizKey, "fp-biz")
	if err != nil {
		t.Fatal(err)
	}

	got, err := f.client.FeatureKey(ctx, entTok, "fp-ent")
	if err != nil {
		t.Fatalf("the Enterprise token did not release the feature key: %v", err)
	}
	if !bytes.Equal(got, f.featureKey) {
		t.Errorf("the feature key released is %q, want %q", got, f.featureKey)
	}
	if _, err := f.client.FeatureKey(ctx, bizTok, "fp-biz"); err == nil {
		t.Error("the feature key was released against a Business token")
	}
	if _, err := f.client.FeatureKey(ctx, entTok, "fp-other"); err == nil {
		t.Error("the feature key was released against a token locked to another machine")
	}
}

// Criterion 3: the heartbeat re-validates and renews a token, the revocation list is delivered and
// verifies, a revoked Licence loses its token, and the signing key is reached only through the KSP
// or HSM interface (a software KSP stands in for the HSM in CI).
func TestHeartbeatAndRevocations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	vendor := []ed25519.PublicKey{f.svc.VendorKey()}
	entKey := f.signLicence(t, "ent-1", licence.Enterprise)

	tok1, err := f.client.Activate(ctx, entKey, "fp-ent")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ParseToken(tok1, vendor)
	if err != nil {
		t.Fatal(err)
	}

	// A heartbeat later renews the token to a later expiry.
	f.clk.advance(30 * time.Minute)
	tok2, err := f.client.Heartbeat(ctx, tok1, "fp-ent")
	if err != nil {
		t.Fatalf("the heartbeat refused a valid token: %v", err)
	}
	renewed, err := ParseToken(tok2, vendor)
	if err != nil {
		t.Fatalf("the renewed token does not verify: %v", err)
	}
	if !renewed.Expires.After(first.Expires) {
		t.Errorf("the heartbeat did not extend the expiry: was %v, now %v", first.Expires, renewed.Expires)
	}
	if _, err := f.client.Heartbeat(ctx, tok2, "fp-other"); err == nil {
		t.Error("the heartbeat renewed a token for another machine")
	}

	// The revocation list is empty, signed, and verifies against the vendor key.
	list, sig, err := f.client.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.IDs) != 0 || !VerifyRevocations(list, sig, vendor) {
		t.Errorf("the empty revocation list is %v, verify %v", list.IDs, VerifyRevocations(list, sig, vendor))
	}

	// After a revocation the Licence is in the list and its token no longer heartbeats.
	f.svc.Revoke("ent-1")
	list, sig, err = f.client.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !list.contains("ent-1") || !VerifyRevocations(list, sig, vendor) {
		t.Errorf("after revoking ent-1 the list is %v, verify %v", list.IDs, VerifyRevocations(list, sig, vendor))
	}
	if _, err := f.client.Heartbeat(ctx, tok2, "fp-ent"); err == nil {
		t.Error("a revoked Licence still heartbeats")
	}
	if _, err := f.client.FeatureKey(ctx, tok2, "fp-ent"); err == nil {
		t.Error("a revoked Licence still gets the feature key")
	}

	// Every signature came through the crypto.Signer interface: the activate, the heartbeat and two
	// revocation lists each signed once, and all of them verify against the signer's public half.
	if got := f.signer.count(); got < 4 {
		t.Errorf("the signer was called %d times; the service did not sign only through the interface", got)
	}
}
