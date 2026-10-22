package activation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// defaultGrace is how long past a token's expiry a missed heartbeat is tolerated before the install
// degrades (ADR-0036 amendment of 2026-10-22, SEC-6 #285): long enough that an outage or a few
// missed heartbeats do not degrade a paying customer, short enough that a withdrawn Licence loses
// its tier in reasonable time once heartbeats stop.
const defaultGrace = 14 * 24 * time.Hour

// Install is the install-side activation state of a node or controller (ADR-0036 amendment of
// 2026-10-22, SEC-6 #285). On install it activates a Licence key against the activation service,
// holds the issued token and, for Enterprise, the feature key in memory, re-validates on a heartbeat
// with a grace period, and resolves the licence in force (Status). The core tunnel never depends on
// it: activation only gates the licensed tier and the Enterprise features, never forwarding (zero
// DRM on the tunnel, ADR-0036), so a degrade past the grace period changes the tier and leaves the
// tunnel up. It is safe for concurrent use.
type Install struct {
	// vendor are the vendor public keys built into the release; an empty slice runs Personal.
	vendor []ed25519.PublicKey
	// fingerprint is this machine's fingerprint, which a token must be locked to.
	fingerprint string
	// grace is how long past a token's expiry a missed heartbeat is tolerated.
	grace time.Duration
	// version is the running build's version, which a fallback licence must cover.
	version string
	// installed is the install's own Licence key, the degrade target past the grace period; nil
	// without one, so the degrade target is then Personal.
	installed *licence.Licence
	// now reads the clock.
	now func() time.Time

	// mu guards token and featureKey.
	mu sync.Mutex
	// token is the activation token the install holds, empty before activation.
	token string
	// featureKey is the Enterprise feature key, held in memory only, empty until fetched.
	featureKey []byte
}

// InstallConfig builds an Install.
type InstallConfig struct {
	// Vendor are the vendor public keys built into the release that an activation token is signed
	// with. Empty, as in a development build or a release whose vendor signing key is not yet
	// linked, no token verifies and the install runs Personal.
	Vendor []ed25519.PublicKey
	// Fingerprint is this machine's fingerprint. Required.
	Fingerprint string
	// Grace is how long past a token's expiry a missed heartbeat is tolerated; defaultGrace when
	// zero.
	Grace time.Duration
	// Version is the running build's version; "0.0" when empty.
	Version string
	// Licence is the install's own Licence key (internal/licence), the degrade target past the
	// grace period; nil degrades to Personal.
	Licence *licence.Licence
	// Now reads the clock; time.Now when nil.
	Now func() time.Time
}

// NewInstall returns an Install built from cfg.
func NewInstall(cfg InstallConfig) (*Install, error) {
	fp := strings.TrimSpace(cfg.Fingerprint)
	if fp == "" {
		return nil, errors.New("activation: the install has no machine fingerprint")
	}
	grace := cfg.Grace
	if grace <= 0 {
		grace = defaultGrace
	}
	version := cfg.Version
	if version == "" {
		version = "0.0"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Install{
		vendor:      slices.Clone(cfg.Vendor),
		fingerprint: fp,
		grace:       grace,
		version:     version,
		installed:   cfg.Licence,
		now:         now,
	}, nil
}

// Activate activates the Licence key against the service, holds the issued token in memory, and
// returns the licence in force then.
func (i *Install) Activate(ctx context.Context, c *Client, key string) (licence.Status, error) {
	tok, err := c.Activate(ctx, key, i.fingerprint)
	if err != nil {
		return i.Status(), err
	}
	i.setToken(tok)
	return i.Status(), nil
}

// Heartbeat re-validates the held token with the service and holds the renewed one. On a refused
// heartbeat the install keeps its token and degrades by itself once the grace period passes.
func (i *Install) Heartbeat(ctx context.Context, c *Client) (licence.Status, error) {
	i.mu.Lock()
	token := i.token
	i.mu.Unlock()
	renewed, err := c.Heartbeat(ctx, token, i.fingerprint)
	if err != nil {
		return i.Status(), err
	}
	i.setToken(renewed)
	return i.Status(), nil
}

// FetchFeatureKey fetches the Enterprise feature key against the held token and holds it in memory.
// The service releases it only against an Enterprise token, so a non-Enterprise install is refused.
func (i *Install) FetchFeatureKey(ctx context.Context, c *Client) error {
	i.mu.Lock()
	token := i.token
	i.mu.Unlock()
	key, err := c.FeatureKey(ctx, token, i.fingerprint)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.featureKey = key
	i.mu.Unlock()
	return nil
}

// SetToken holds tok as the install's activation token, for a token obtained off the network through
// the offline activation file (OpenOfflineResponse). Status still checks it against the machine and
// the vendor keys, so a wrong token degrades like a missing one.
func (i *Install) SetToken(tok string) {
	i.setToken(tok)
}

// Token returns the activation token the install holds, empty before activation.
func (i *Install) Token() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.token
}

// Status returns the licence in force for the held token at the current time, tolerating a missed
// heartbeat for the grace period and degrading to the Licence in force past it.
func (i *Install) Status() licence.Status {
	i.mu.Lock()
	token := i.token
	i.mu.Unlock()
	return ResolveGrace(token, i.fingerprint, i.vendor, i.now(), i.version, i.grace, i.installed)
}

// OpenFeature opens the sealed Enterprise feature blob with the feature key the install holds in
// memory. Without a fetched key it refuses, so the Enterprise feature stays sealed until the install
// activates Enterprise and fetches the key against its token.
func (i *Install) OpenFeature(blob []byte) ([]byte, error) {
	i.mu.Lock()
	key := slices.Clone(i.featureKey)
	i.mu.Unlock()
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: the install holds no Enterprise feature key; fetch it against an Enterprise token", ErrInvalid)
	}
	return OpenFeature(key, blob)
}

// setToken holds tok.
func (i *Install) setToken(tok string) {
	i.mu.Lock()
	i.token = strings.TrimSpace(tok)
	i.mu.Unlock()
}

// ResolveGrace returns the licence in force for an activation token at now, tolerating a missed
// heartbeat for the grace period past the token's expiry (ADR-0036 amendment of 2026-10-22, SEC-6
// #285). While the token runs, and for the grace period past its expiry, it grants its tier, so one
// missed heartbeat does not degrade a paying customer. Past the grace period the install degrades to
// the Licence in force that its own Licence key proves (licence.Evaluate), or to Personal without
// one, while the core tunnel keeps forwarding (zero DRM on the tunnel). A token that does not verify,
// is locked to another machine, or has no vendor key to verify it against also resolves to the
// Licence in force. installed is the install's own Licence key, nil without one.
func ResolveGrace(token, fingerprint string, vendor []ed25519.PublicKey, now time.Time, v string, grace time.Duration, installed *licence.Licence) licence.Status {
	inForce := licence.Evaluate(installed, now, v)
	if len(vendor) == 0 {
		return inForce
	}
	t, err := ParseToken(token, vendor)
	if err != nil || t.Fingerprint != strings.TrimSpace(fingerprint) {
		return inForce
	}
	switch {
	case now.Before(t.Expires):
		return tierStatus(t, v, false)
	case now.Before(t.Expires.Add(grace)):
		return tierStatus(t, v, true)
	default:
		return inForce
	}
}

// tierStatus is the licence in force of a valid activation token: its tier and features. inGrace
// marks a token past its expiry that the grace period still honours, so the message says a heartbeat
// must renew it.
func tierStatus(t Token, v string, inGrace bool) licence.Status {
	key := licence.Licence{ID: t.LicenceID, Licensee: t.Licensee, Tier: t.Tier, Nodes: t.Nodes, Expires: t.Expires}
	st := licence.Status{
		Tier: t.Tier, Nodes: t.Nodes, Features: t.Tier.Features(), State: licence.StateActive, Version: v, Key: &key,
	}
	if inGrace {
		st.Message = fmt.Sprintf("the %s activation token %s of %s expired at %s and holds within the grace period until a heartbeat renews it: %d nodes",
			t.Tier, t.LicenceID, t.Licensee, stamp(t.Expires), t.Nodes)
	} else {
		st.Message = fmt.Sprintf("the %s activation token %s of %s: %d nodes until %s", t.Tier, t.LicenceID, t.Licensee, t.Nodes, stamp(t.Expires))
	}
	return st
}
