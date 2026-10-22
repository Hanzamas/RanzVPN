package activation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// Criterion 1: the install (the controller) activates against the activation service and gets a
// signed, node-locked token, and the Enterprise feature blob unlocks only with the server key, held
// in memory (ADR-0036 amendment of 2026-10-22, SEC-6 #285).
func TestInstallActivatesAndUnlocksFeatureBlob(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	vendor := []ed25519.PublicKey{f.svc.VendorKey()}
	key := f.signLicence(t, "ent-1", licence.Enterprise)

	inst, err := NewInstall(InstallConfig{Vendor: vendor, Fingerprint: "fp-ctl", Version: "1.0", Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}

	st, err := inst.Activate(ctx, f.client, key)
	if err != nil {
		t.Fatalf("install activation: %v", err)
	}
	if st.Tier != licence.Enterprise || st.State != licence.StateActive {
		t.Fatalf("the install resolved to %+v after activation", st)
	}
	// The held token is node-locked to this machine and verifies against the vendor key.
	parsed, err := ParseToken(inst.Token(), vendor)
	if err != nil {
		t.Fatalf("the held token does not verify against the vendor key: %v", err)
	}
	if parsed.Fingerprint != "fp-ctl" {
		t.Errorf("the token is locked to %q, not this machine", parsed.Fingerprint)
	}
	if !parsed.Expires.After(parsed.Issued) {
		t.Errorf("the token is not time-limited: issued %v, expires %v", parsed.Issued, parsed.Expires)
	}

	// The Enterprise feature blob is sealed with the server-held feature key.
	blob, err := SealFeature(f.featureKey, []byte("the Enterprise feature"))
	if err != nil {
		t.Fatal(err)
	}
	// Before the install fetches the key it holds none and cannot open the blob.
	if _, err := inst.OpenFeature(blob); !errors.Is(err, ErrInvalid) {
		t.Errorf("the install opened the feature blob with no server key: %v", err)
	}
	// The install fetches the key against its Enterprise token; it lives in memory only.
	if err := inst.FetchFeatureKey(ctx, f.client); err != nil {
		t.Fatalf("fetching the feature key: %v", err)
	}
	got, err := inst.OpenFeature(blob)
	if err != nil {
		t.Fatalf("the install could not open the blob with the server key: %v", err)
	}
	if string(got) != "the Enterprise feature" {
		t.Errorf("the blob opened to %q", got)
	}
	// A second install that never fetched the key cannot open the blob: the key is not global.
	other, err := NewInstall(InstallConfig{Vendor: vendor, Fingerprint: "fp-other", Version: "1.0", Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenFeature(blob); !errors.Is(err, ErrInvalid) {
		t.Errorf("a second install opened the blob without the server key: %v", err)
	}
	// The wrong key never opens the blob.
	if _, err := OpenFeature([]byte("the wrong feature key"), blob); !errors.Is(err, ErrInvalid) {
		t.Errorf("the feature blob opened with the wrong key: %v", err)
	}
	// A Business install is refused the feature key by the service, so it never holds it.
	bizKey := f.signLicence(t, "biz-9", licence.Business)
	biz, err := NewInstall(InstallConfig{Vendor: vendor, Fingerprint: "fp-biz", Version: "1.0", Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := biz.Activate(ctx, f.client, bizKey); err != nil {
		t.Fatal(err)
	}
	if err := biz.FetchFeatureKey(ctx, f.client); err == nil {
		t.Error("a Business install fetched the Enterprise feature key")
	}
}

// Criterion 2: a heartbeat re-validates within the grace period, and past the grace period the
// install degrades to the Licence in force or Personal while the core tunnel keeps forwarding
// (ADR-0036 amendment of 2026-10-22, SEC-6 #285).
func TestHeartbeatGraceAndDegrade(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	vendor := []ed25519.PublicKey{f.svc.VendorKey()}
	key := f.signLicence(t, "biz-1", licence.Business)

	grace := 48 * time.Hour
	inst, err := NewInstall(InstallConfig{Vendor: vendor, Fingerprint: "fp-ctl", Version: "1.0", Grace: grace, Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Activate(ctx, f.client, key); err != nil {
		t.Fatal(err)
	}
	if st := inst.Status(); st.Tier != licence.Business || st.State != licence.StateActive {
		t.Fatalf("after activation the install is %+v", st)
	}

	// A heartbeat before expiry renews the token, so the tier stays in force past the first expiry.
	f.clk.advance(f.ttl - time.Minute)
	if _, err := inst.Heartbeat(ctx, f.client); err != nil {
		t.Fatalf("the heartbeat refused a valid token: %v", err)
	}
	f.clk.advance(f.ttl - time.Minute) // past the first token's expiry; the renewed token still runs
	if st := inst.Status(); st.Tier != licence.Business || st.State != licence.StateActive {
		t.Errorf("a heartbeat should have renewed the token, but the install is %+v", st)
	}

	// Heartbeats stop. Within the grace period past the renewed token's expiry the tier still holds.
	f.clk.advance(2 * time.Minute) // just past the renewed token's expiry, well within the grace period
	if st := inst.Status(); st.Tier != licence.Business || st.State != licence.StateActive {
		t.Errorf("within the grace period the tier should hold, but the install is %+v", st)
	}

	// Past the grace period the install degrades to Personal (no installed Licence key). The degrade
	// is a tier change, not a stop: the install still answers a Status, so the data plane reads the
	// tier for feature-gating only and the core tunnel keeps forwarding (zero DRM on the tunnel).
	f.clk.advance(grace)
	if st := inst.Status(); st.Tier != licence.Personal || st.State != licence.StateNone {
		t.Errorf("past the grace period the install should degrade to Personal, but it is %+v", st)
	}
}

// ResolveGrace resolves the tier while a token runs and within the grace period past its expiry, and
// degrades to the Licence in force past it: Personal without an installed Licence key, or the tier
// the installed key proves.
func TestResolveGraceDegradeTargets(t *testing.T) {
	ksp, pub := testKSP(t, 1)
	vendor := []ed25519.PublicKey{pub}
	now := tokenIssued
	tok, err := SignToken(ksp, Token{
		LicenceID: "ent-1", Licensee: "Example Ltd", Tier: licence.Enterprise, Nodes: 50,
		Features: licence.Enterprise.Features(), Fingerprint: "fp-a", Issued: now, Expires: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	grace := time.Hour
	business := &licence.Licence{ID: "biz-1", Licensee: "Example Ltd", Tier: licence.Business, Nodes: 20, Expires: now.Add(365 * 24 * time.Hour)}

	for _, c := range []struct {
		name      string
		fp        string
		vendor    []ed25519.PublicKey
		now       time.Time
		installed *licence.Licence
		wantTier  licence.Tier
		wantState licence.State
	}{
		{"active", "fp-a", vendor, now.Add(time.Minute), nil, licence.Enterprise, licence.StateActive},
		{"within grace", "fp-a", vendor, now.Add(time.Hour + 30*time.Minute), nil, licence.Enterprise, licence.StateActive},
		{"past grace, no key", "fp-a", vendor, now.Add(3 * time.Hour), nil, licence.Personal, licence.StateNone},
		{"past grace, installed Business", "fp-a", vendor, now.Add(3 * time.Hour), business, licence.Business, licence.StateActive},
		{"no vendor key linked", "fp-a", nil, now.Add(time.Minute), nil, licence.Personal, licence.StateNone},
		{"node mismatch", "fp-b", vendor, now.Add(time.Minute), nil, licence.Personal, licence.StateNone},
	} {
		st := ResolveGrace(tok, c.fp, c.vendor, c.now, "1.0", grace, c.installed)
		if st.Tier != c.wantTier || st.State != c.wantState {
			t.Errorf("%s: resolved to tier %s, state %s; want %s, %s", c.name, st.Tier, st.State, c.wantTier, c.wantState)
		}
	}
}

// Criterion 3: the offline activation file round-trips with no network access: a signed request
// produces a signed response that activates the install (ADR-0036 amendment of 2026-10-22, SEC-6
// #285). This test stands up no server and makes no HTTP call; the exchange is files only.
func TestOfflineActivationRoundTrip(t *testing.T) {
	f := newFixture(t)
	vendor := []ed25519.PublicKey{f.svc.VendorKey()}
	key := f.signLicence(t, "ent-1", licence.Enterprise)

	// The air-gapped install writes a signed request to a file.
	req, err := NewOfflineRequest(key, "fp-air", f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	reqFile, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	// The vendor reads the request file on a connected machine and writes a signed response.
	var fromFile SignedOfflineRequest
	if err := json.Unmarshal(reqFile, &fromFile); err != nil {
		t.Fatal(err)
	}
	resp, err := f.svc.SignOffline(fromFile)
	if err != nil {
		t.Fatalf("the vendor refused a valid offline request: %v", err)
	}
	respFile, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	// The install reads the response file, verifies it offline with the vendor key, and activates.
	var respFromFile SignedOfflineResponse
	if err := json.Unmarshal(respFile, &respFromFile); err != nil {
		t.Fatal(err)
	}
	tok, err := OpenOfflineResponse(req, respFromFile, vendor)
	if err != nil {
		t.Fatalf("the install could not open the offline response: %v", err)
	}
	inst, err := NewInstall(InstallConfig{Vendor: vendor, Fingerprint: "fp-air", Version: "1.0", Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	inst.SetToken(tok)
	if st := inst.Status(); st.Tier != licence.Enterprise || st.State != licence.StateActive {
		t.Errorf("the offline-activated install resolved to %+v", st)
	}

	// A request changed after it was signed is refused by its own signature.
	tampered := req
	tampered.Fingerprint = "fp-evil"
	if _, err := f.svc.SignOffline(tampered); err == nil {
		t.Error("a tampered offline request was signed")
	}

	// A second request and its matching response open; a response does not open against the wrong
	// request (the nonce ties them), nor under a foreign vendor key, nor with no vendor key linked.
	req2, err := NewOfflineRequest(f.signLicence(t, "ent-2", licence.Enterprise), "fp-air-2", f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := f.svc.SignOffline(req2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOfflineResponse(req2, resp2, vendor); err != nil {
		t.Errorf("the matching offline pair did not open: %v", err)
	}
	if _, err := OpenOfflineResponse(req, resp2, vendor); err == nil {
		t.Error("an offline response opened against the wrong request")
	}
	_, foreign := testKSP(t, 7)
	if _, err := OpenOfflineResponse(req, respFromFile, []ed25519.PublicKey{foreign}); err == nil {
		t.Error("the offline response opened under a foreign vendor key")
	}
	if _, err := OpenOfflineResponse(req, respFromFile, nil); err == nil {
		t.Error("the offline response opened with no vendor key linked")
	}
}
