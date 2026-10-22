package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// testVendor returns the vendor key pair of seed: fixed, so the tests need no random source.
func testVendor(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(slices.Repeat([]byte{seed}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

var expiry = time.Date(2027, 10, 22, 0, 0, 0, 0, time.UTC)

func business() Licence {
	return Licence{ID: "biz-1", Licensee: "Example Ltd", Tier: Business, Nodes: 50, Expires: expiry, FallbackVersion: "0.2"}
}

// A signed key verifies and holds what was signed, also with the space of a key file around it.
func TestSignAndParse(t *testing.T) {
	pub, priv := testVendor(1)
	key, err := Sign(priv, business())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "key/") || strings.Count(key, ".") != 1 {
		t.Errorf("the key %q is not of the form key/<licence>.<signature>", key)
	}
	other, _ := testVendor(2)
	for _, s := range []string{key, "  " + key + "\r\n"} {
		l, err := Parse(s, []ed25519.PublicKey{other, pub})
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		want := business()
		if !l.Expires.Equal(want.Expires) {
			t.Errorf("the key expires at %v, want %v", l.Expires, want.Expires)
		}
		want.Watermark = WatermarkFor(want.Licensee) // Sign embedded it
		l.Expires, want.Expires = time.Time{}, time.Time{}
		if l != want {
			t.Errorf("the key holds %+v, want %+v", l, want)
		}
	}
}

// A key that is malformed, changed after signing or signed with another key does not verify.
func TestParseRefuses(t *testing.T) {
	pub, priv := testVendor(1)
	_, otherPriv := testVendor(2)
	key, err := Sign(priv, business())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := Sign(otherPriv, business())
	if err != nil {
		t.Fatal(err)
	}
	payload, sig, _ := strings.Cut(strings.TrimPrefix(key, "key/"), ".")
	b, _ := base64.RawURLEncoding.DecodeString(payload)
	more := strings.Replace(string(b), `"nodes":50`, `"nodes":5000`, 1)
	tampered := "key/" + base64.RawURLEncoding.EncodeToString([]byte(more)) + "." + sig
	for _, c := range []struct{ name, key, want string }{
		{"empty", "", "not of the form"},
		{"no prefix", strings.TrimPrefix(key, "key/"), "not of the form"},
		{"no signature", "key/" + payload, "not of the form"},
		{"bad base64", "key/!!." + sig, "not base64url"},
		{"short signature", "key/" + payload + ".AAAA", "not the base64url of an Ed25519 signature"},
		{"tampered", tampered, "not signed with a Ranz vendor key"},
		{"foreign vendor", foreign, "not signed with a Ranz vendor key"},
	} {
		_, err := Parse(c.key, []ed25519.PublicKey{pub})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrInvalid that says %q", c.name, err, c.want)
		}
	}
	if _, err := Parse(key, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("with no vendor key built in, a key verified: %v", err)
	}
}

// The vendor cannot sign a licence that the controller would refuse.
func TestSignRefusesInvalidLicence(t *testing.T) {
	_, priv := testVendor(1)
	for _, c := range []struct {
		name string
		edit func(*Licence)
		want string
	}{
		{"tier", func(l *Licence) { l.Tier = "Gold" }, `the tier must be Personal, Business or Enterprise, not "Gold"`},
		{"nodes", func(l *Licence) { l.Nodes = 0 }, "the node count must be at least 1, not 0"},
		{"expiry", func(l *Licence) { l.Expires = time.Time{} }, "the licence has no expiry"},
		{"fallback", func(l *Licence) { l.FallbackVersion = "1" }, `version "1" is not major.minor`},
		{"fallback sign", func(l *Licence) { l.FallbackVersion = "+1.2" }, `version "+1.2" is not major.minor`},
	} {
		l := business()
		c.edit(&l)
		_, err := Sign(priv, l)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrInvalid that says %q", c.name, err, c.want)
		}
	}
}

// The licence in force: the key while it runs, its fallback licence after it expired when that
// covers the version (the same major.minor, a bugfix release of it, or an older version), and
// the Personal tier otherwise or without a key.
func TestEvaluate(t *testing.T) {
	before, after := expiry.Add(-time.Second), expiry
	enterprise := business()
	enterprise.Tier = Enterprise
	noFallback := business()
	noFallback.FallbackVersion = ""
	for _, c := range []struct {
		name    string
		l       *Licence
		now     time.Time
		version string
		state   State
		tier    Tier
		nodes   int
	}{
		{"no key", nil, before, "0.2", StateNone, Personal, PersonalNodes},
		{"active", &noFallback, before, "9.9", StateActive, Business, 50},
		{"fallback, same version", ptr(business()), after, "0.2", StateFallback, Business, 50},
		{"fallback, bugfix release", ptr(business()), after, "0.2.7", StateFallback, Business, 50},
		{"fallback, older version", ptr(business()), after, "0.1", StateFallback, Business, 50},
		{"fallback, Enterprise", &enterprise, after, "0.2", StateFallback, Enterprise, 50},
		{"newer minor", ptr(business()), after, "0.3", StateExpired, Personal, PersonalNodes},
		{"newer major", ptr(business()), after, "1.0", StateExpired, Personal, PersonalNodes},
		{"no fallback", &noFallback, after, "0.2", StateExpired, Personal, PersonalNodes},
	} {
		st := Evaluate(c.l, c.now, c.version)
		if st.State != c.state || st.Tier != c.tier || st.Nodes != c.nodes || st.Version != c.version {
			t.Errorf("%s: %+v, want state %s, tier %s, %d nodes, version %s", c.name, st, c.state, c.tier, c.nodes, c.version)
		}
		if (st.Key != nil) != (c.l != nil) || st.Message == "" {
			t.Errorf("%s: key %v, message %q", c.name, st.Key, st.Message)
		}
		if want := c.tier == Enterprise; st.Allows(FeatureEVPN) != want || st.Allows(FeatureHA) != want {
			t.Errorf("%s: the features are %v", c.name, st.Features)
		}
	}
	st := Evaluate(ptr(business()), after, "0.3")
	if want := "and its fallback licence for version 0.2 does not cover this controller (0.3): the Personal tier is in force, up to 10 nodes"; !strings.Contains(st.Message, want) {
		t.Errorf("the message %q does not say %q", st.Message, want)
	}
}

func TestVendorKeys(t *testing.T) {
	defer func(v string) { vendorKeys = v }(vendorKeys)
	a, _ := testVendor(1)
	b, _ := testVendor(2)
	for _, c := range []struct {
		built string
		want  []ed25519.PublicKey
	}{
		{"", nil},
		{base64.StdEncoding.EncodeToString(a), []ed25519.PublicKey{a}},
		{base64.StdEncoding.EncodeToString(a) + ", " + base64.StdEncoding.EncodeToString(b), []ed25519.PublicKey{a, b}},
	} {
		vendorKeys = c.built
		got, err := VendorKeys()
		if err != nil || !slices.EqualFunc(got, c.want, func(x, y ed25519.PublicKey) bool { return x.Equal(y) }) {
			t.Errorf("%q: %v, %v", c.built, got, err)
		}
	}
	vendorKeys = "AAAA"
	if _, err := VendorKeys(); err == nil {
		t.Error("a malformed vendor key was accepted")
	}
}

// Every generated licence key embeds the per-customer watermark, which round-trips through
// verification (SEC-5 #283, first criterion). It is the same for every key of one customer, and an
// explicit watermark is kept as given.
func TestWatermarkRoundTrips(t *testing.T) {
	pub, priv := testVendor(1)
	key, err := Sign(priv, business())
	if err != nil {
		t.Fatal(err)
	}
	l, err := Parse(key, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	want := WatermarkFor(business().Licensee)
	if want == "" {
		t.Fatal("the watermark of a licensee is empty")
	}
	if l.Watermark != want {
		t.Errorf("the key embeds the watermark %q, want %q", l.Watermark, want)
	}

	// A second key of the same customer carries the same watermark; another customer's differs.
	same := business()
	same.ID = "biz-2"
	k2, _ := Sign(priv, same)
	l2, _ := Parse(k2, []ed25519.PublicKey{pub})
	if l2.Watermark != want {
		t.Errorf("a second key of the same customer has the watermark %q, want %q", l2.Watermark, want)
	}
	other := business()
	other.Licensee = "Other Ltd"
	k3, _ := Sign(priv, other)
	l3, _ := Parse(k3, []ed25519.PublicKey{pub})
	if l3.Watermark == want {
		t.Errorf("a key of another customer has the same watermark %q", l3.Watermark)
	}

	// An explicit watermark is signed and parsed back as given, not overwritten.
	fixed := business()
	fixed.Watermark = "deadbeefcafef00d"
	k4, _ := Sign(priv, fixed)
	l4, _ := Parse(k4, []ed25519.PublicKey{pub})
	if l4.Watermark != fixed.Watermark {
		t.Errorf("the explicit watermark became %q, want %q", l4.Watermark, fixed.Watermark)
	}
}

// A signed revocation list verifies and holds what was signed, also with the space of a list file
// around it, and names the keys it revokes.
func TestSignAndParseRevocations(t *testing.T) {
	pub, priv := testVendor(1)
	r := Revocations{Issued: expiry, IDs: []string{"biz-1", "ent-7"}}
	signed, err := SignRevocations(priv, r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(signed, "revoke/") || strings.Count(signed, ".") != 1 {
		t.Errorf("the list %q is not of the form revoke/<list>.<signature>", signed)
	}
	other, _ := testVendor(2)
	for _, s := range []string{signed, "  " + signed + "\r\n"} {
		got, err := ParseRevocations(s, []ed25519.PublicKey{other, pub})
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if !got.Issued.Equal(r.Issued) || !slices.Equal(got.IDs, r.IDs) {
			t.Errorf("the list holds %+v, want %+v", got, r)
		}
		if !got.Revokes(Licence{ID: "biz-1"}) || got.Revokes(Licence{ID: "biz-9"}) {
			t.Errorf("the list revokes the wrong ids: %+v", got.IDs)
		}
	}
}

// A revocation list that is malformed, changed after signing or signed with another key does not
// verify.
func TestParseRevocationsRefuses(t *testing.T) {
	pub, priv := testVendor(1)
	_, otherPriv := testVendor(2)
	signed, err := SignRevocations(priv, Revocations{Issued: expiry, IDs: []string{"biz-1"}})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := SignRevocations(otherPriv, Revocations{Issued: expiry, IDs: []string{"biz-1"}})
	if err != nil {
		t.Fatal(err)
	}
	payload, sig, _ := strings.Cut(strings.TrimPrefix(signed, "revoke/"), ".")
	b, _ := base64.RawURLEncoding.DecodeString(payload)
	more := strings.Replace(string(b), `"biz-1"`, `"biz-2"`, 1)
	tampered := "revoke/" + base64.RawURLEncoding.EncodeToString([]byte(more)) + "." + sig
	for _, c := range []struct{ name, list, want string }{
		{"empty", "", "not of the form"},
		{"no prefix", strings.TrimPrefix(signed, "revoke/"), "not of the form"},
		{"no signature", "revoke/" + payload, "not of the form"},
		{"bad base64", "revoke/!!." + sig, "not base64url"},
		{"short signature", "revoke/" + payload + ".AAAA", "not the base64url of an Ed25519 signature"},
		{"tampered", tampered, "not signed with a Ranz vendor key"},
		{"foreign vendor", foreign, "not signed with a Ranz vendor key"},
	} {
		_, err := ParseRevocations(c.list, []ed25519.PublicKey{pub})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrInvalid that says %q", c.name, err, c.want)
		}
	}
}

func ptr(l Licence) *Licence {
	return &l
}
