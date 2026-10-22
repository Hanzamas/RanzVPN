package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// The fuzz test of the licence package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the controller workflow runs with go test -fuzz.

// FuzzParse reads the input as a licence key (Parse), then signs it with the vendor key as the
// licence of a key and parses that, so that the JSON and the checks behind the signature are
// reached too: a licence that parses has passed them.
func FuzzParse(f *testing.F) {
	pub, priv := testVendor(1)
	key, err := Sign(priv, business())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(key)
	f.Add(`{"id":"biz-1","licensee":"Example Ltd","tier":"Business","nodes":50,"expires":"2027-10-22T00:00:00Z","fallbackVersion":"0.2"}`)
	f.Add(`{"tier":"Enterprise","nodes":1,"expires":"2027-10-22T00:00:00Z","fallbackVersion":"1.2.3"}`)
	vendor := []ed25519.PublicKey{pub}

	f.Fuzz(func(t *testing.T, s string) {
		if l, err := Parse(s, vendor); err == nil && l.validate() != nil {
			t.Fatalf("Parse(%q) holds a licence that does not validate: %+v", s, l)
		}
		signed := keyPrefix + base64.RawURLEncoding.EncodeToString([]byte(s))
		l, err := Parse(signed+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signed))), vendor)
		if err != nil {
			return
		}
		if l.Nodes < 1 || l.Expires.IsZero() {
			t.Fatalf("the signed licence %q parses with %d nodes and the expiry %v", s, l.Nodes, l.Expires)
		}
		if l.FallbackVersion != "" {
			if _, err := parseVersion(l.FallbackVersion); err != nil {
				t.Fatalf("the signed licence %q parses with the fallback version %q: %v", s, l.FallbackVersion, err)
			}
		}
	})
}
