// Package licence checks the licence key of a Ranz installation (ADR-0036, SDN-30 #206): its
// tier (Personal, Business or Enterprise), its node count, its expiry and the version of its
// perpetual fallback licence. The controller is the one place that enforces it; a node never
// decides a tier itself.
//
// A licence key has the form of Keygen's signed licence keys (the ED25519_SIGN scheme): "key/",
// the base64url (no padding) of the licence as JSON, ".", and the base64url of the Ed25519
// signature of everything before the dot. The vendor signs it with the private half of a key
// whose public half is built into the controller (VendorKeys).
//
// The perpetual fallback licence follows JetBrains' rule: a subscription paid for 12 months
// holds a fallback version (major.minor), and once the subscription expires, that version, its
// bugfix releases and every older version stay licensed with the tier and node count of the
// subscription. An expired subscription without a fallback licence for the running version
// leaves the Personal tier.
package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Tier is what a licence sells (ADR-0036).
type Tier string

// The tiers.
const (
	// Personal is free for non-commercial use, with all core features and a small node cap.
	Personal Tier = "Personal"
	// Business is paid per node per year.
	Business Tier = "Business"
	// Enterprise adds EVPN and BGP, controller high availability and priority support.
	Enterprise Tier = "Enterprise"
)

// Feature is a feature beyond the core that only the Enterprise tier has.
type Feature string

// The Enterprise features that the controller gates.
const (
	// FeatureEVPN is EVPN and BGP at the edge (ADR-0032).
	FeatureEVPN Feature = "evpn-bgp"
	// FeatureHA is controller high availability: a store of 3 or 5 members (ADR-0026).
	FeatureHA Feature = "controller-ha"
)

// PersonalNodes is the node cap of the Personal tier when no licence key is installed, or when a
// subscription expired without a fallback licence for the running version.
const PersonalNodes = 10

// State tells where the licence in force comes from.
type State string

// The states.
const (
	StateNone     State = "none"     // no licence key: the Personal tier
	StateActive   State = "active"   // the licence key, until it expires
	StateFallback State = "fallback" // the expired subscription's fallback licence covers this version
	StateExpired  State = "expired"  // the subscription expired without a fallback licence for this version: the Personal tier
)

var (
	// ErrInvalid marks a licence key that is malformed or not signed with a vendor key.
	ErrInvalid = errors.New("invalid licence key")
	// ErrRefused marks what the licence in force does not allow.
	ErrRefused = errors.New("refused by the licence")
)

// keyPrefix starts every licence key and is part of what the signature covers.
const keyPrefix = "key/"

// Licence is what a licence key holds.
type Licence struct {
	ID       string    `json:"id"`       // the vendor's id of the licence
	Licensee string    `json:"licensee"` // who it was sold to
	Tier     Tier      `json:"tier"`
	Nodes    int       `json:"nodes"`   // the node count
	Expires  time.Time `json:"expires"` // the end of the subscription
	// FallbackVersion is the version (major.minor) of the perpetual fallback licence; empty
	// before the subscription was paid for 12 months.
	FallbackVersion string `json:"fallbackVersion,omitempty"`
}

// Status is the licence in force.
type Status struct {
	Tier     Tier      `json:"tier"`
	Nodes    int       `json:"nodes"`    // the node cap
	Features []Feature `json:"features"` // the features of the tier beyond the core
	State    State     `json:"state"`
	Version  string    `json:"version"`       // of the controller, which a fallback licence must cover
	Key      *Licence  `json:"key,omitempty"` // what the installed licence key holds, nil without one
	Message  string    `json:"message"`       // the licence in force in one sentence
}

// Allows reports whether the licence in force has feature f.
func (s Status) Allows(f Feature) bool {
	return slices.Contains(s.Features, f)
}

// Features returns the features of tier t beyond the core.
func (t Tier) Features() []Feature {
	if t == Enterprise {
		return []Feature{FeatureEVPN, FeatureHA}
	}
	return []Feature{}
}

// Name returns the name of f in a sentence.
func (f Feature) Name() string {
	switch f {
	case FeatureEVPN:
		return "EVPN and BGP"
	case FeatureHA:
		return "controller high availability"
	}
	return string(f)
}

// vendorKeys is the base64 of the Ed25519 public keys that licence keys are signed with,
// separated by commas, so a new vendor key can start before the old one retires. The release
// build sets it:
//
//	go build -ldflags "-X github.com/Hanzamas/RanzVPN/controller/internal/licence.vendorKeys=<base64>"
//
// Empty, as in a development build, no licence key verifies and the Personal tier is in force.
var vendorKeys string

// VendorKeys returns the public keys built into the controller that a licence key must be
// signed with.
func VendorKeys() ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, s := range strings.Split(vendorKeys, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("licence: the vendor key %q built into the controller is not the base64 of an Ed25519 public key", s)
		}
		out = append(out, ed25519.PublicKey(k))
	}
	return out, nil
}

// Sign returns the licence key that holds l, signed with the vendor's private key.
func Sign(vendor ed25519.PrivateKey, l Licence) (string, error) {
	if err := l.validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	b, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	signed := keyPrefix + base64.RawURLEncoding.EncodeToString(b)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(vendor, []byte(signed))), nil
}

// Parse checks that the licence key s is signed with one of the vendor keys and returns what it
// holds. Space around the key, as a key file has, is ignored.
func Parse(s string, vendor []ed25519.PublicKey) (Licence, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, keyPrefix)
	payload, sig, dot := strings.Cut(rest, ".")
	if !ok || !dot {
		return Licence{}, fmt.Errorf("%w: it is not of the form key/<licence>.<signature>", ErrInvalid)
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Licence{}, fmt.Errorf("%w: the licence is not base64url: %w", ErrInvalid, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Licence{}, fmt.Errorf("%w: the signature is not the base64url of an Ed25519 signature", ErrInvalid)
	}
	signed := []byte(keyPrefix + payload)
	if !slices.ContainsFunc(vendor, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, signed, signature) }) {
		return Licence{}, fmt.Errorf("%w: it is not signed with a Ranz vendor key", ErrInvalid)
	}
	var l Licence
	if err := json.Unmarshal(b, &l); err != nil {
		return Licence{}, fmt.Errorf("%w: the licence is not JSON: %w", ErrInvalid, err)
	}
	if err := l.validate(); err != nil {
		return Licence{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return l, nil
}

// Evaluate returns the licence in force at now on a controller of version v: what l holds, while
// its subscription runs or when its fallback licence covers v, and otherwise the Personal tier.
// l is nil when no licence key is installed.
func Evaluate(l *Licence, now time.Time, v string) Status {
	if l == nil {
		return Status{Tier: Personal, Nodes: PersonalNodes, Features: Personal.Features(), State: StateNone, Version: v,
			Message: fmt.Sprintf("no licence key: the %s tier, free for non-commercial use, up to %d nodes", Personal, PersonalNodes)}
	}
	key := *l
	in := Status{Tier: l.Tier, Nodes: l.Nodes, Features: l.Tier.Features(), Version: v, Key: &key}
	switch {
	case now.Before(l.Expires):
		in.State = StateActive
		in.Message = fmt.Sprintf("the %s licence %s of %s: %d nodes until %s", l.Tier, l.ID, l.Licensee, l.Nodes, stamp(l.Expires))
	case l.FallbackVersion != "" && covers(l.FallbackVersion, v):
		in.State = StateFallback
		in.Message = fmt.Sprintf("the %s subscription %s of %s expired at %s, and its perpetual fallback licence for version %s covers this controller (%s): %d nodes",
			l.Tier, l.ID, l.Licensee, stamp(l.Expires), l.FallbackVersion, v, l.Nodes)
	default:
		why := "without a fallback licence"
		if l.FallbackVersion != "" {
			why = fmt.Sprintf("and its fallback licence for version %s does not cover this controller (%s)", l.FallbackVersion, v)
		}
		in.Tier, in.Nodes, in.Features, in.State = Personal, PersonalNodes, Personal.Features(), StateExpired
		in.Message = fmt.Sprintf("the %s subscription %s of %s expired at %s %s: the %s tier is in force, up to %d nodes",
			l.Tier, l.ID, l.Licensee, stamp(l.Expires), why, Personal, PersonalNodes)
	}
	return in
}

// validate checks what a licence key holds.
func (l Licence) validate() error {
	var problems []error
	switch l.Tier {
	case Personal, Business, Enterprise:
	default:
		problems = append(problems, fmt.Errorf("the tier must be %s, %s or %s, not %q", Personal, Business, Enterprise, l.Tier))
	}
	if l.Nodes < 1 {
		problems = append(problems, fmt.Errorf("the node count must be at least 1, not %d", l.Nodes))
	}
	if l.Expires.IsZero() {
		problems = append(problems, errors.New("the licence has no expiry"))
	}
	if l.FallbackVersion != "" {
		if _, err := parseVersion(l.FallbackVersion); err != nil {
			problems = append(problems, fmt.Errorf("fallbackVersion: %w", err))
		}
	}
	return errors.Join(problems...)
}

// covers reports whether a fallback licence for version fallback covers version v: the same
// major.minor (any bugfix release of it) or an older one.
func covers(fallback, v string) bool {
	f, err := parseVersion(fallback)
	if err != nil {
		return false
	}
	r, err := parseVersion(v)
	if err != nil {
		return false
	}
	return r[0] < f[0] || (r[0] == f[0] && r[1] <= f[1])
}

// parseVersion returns the major and minor numbers of v: "major.minor", or "major.minor.patch"
// for a bugfix release.
func parseVersion(v string) ([2]int, error) {
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [2]int{}, fmt.Errorf("version %q is not major.minor or major.minor.patch", v)
	}
	var mm [2]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || p == "" || strings.Trim(p, "0123456789") != "" {
			return [2]int{}, fmt.Errorf("version %q is not major.minor or major.minor.patch", v)
		}
		if i < 2 {
			mm[i] = n
		}
	}
	return mm, nil
}

// stamp formats an expiry in messages.
func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
