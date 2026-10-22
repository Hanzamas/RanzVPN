package intent

import (
	"bytes"
	"testing"
)

// The fuzz tests of the intent package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the controller workflow runs with go test -fuzz.

// FuzzParseDocument reads the input as an intent document, in JSON or YAML as `ranz apply -f`,
// `ranz import -f` and the API take one (ParseDocument), and applies a document that parses to an
// empty intent (Apply) and as the whole intent of one (Replace, the import), which complete and
// check every resource. The ULAs they draw come from a reader of zeros, so a failing input fails
// again.
func FuzzParseDocument(f *testing.F) {
	f.Add([]byte(docJSON))
	f.Add([]byte(docYAML))
	f.Add([]byte(`{"resources": [{"kind": "Controller", "name": "c1", "spec": {}}]}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		doc, err := ParseDocument(b)
		if err != nil {
			return
		}
		in, err := Apply(New(), doc, bytes.NewReader(make([]byte, 4096)))
		if err == nil {
			if _, err := FromResources(in.Resources()); err != nil {
				t.Fatalf("an applied intent does not load from its own resources: %v", err)
			}
		}
		// The import of the same document over what Apply made
		_, _ = Replace(in, doc, bytes.NewReader(make([]byte, 4096)))
	})
}

// FuzzParseValues reads the input as each value of a resource that has a parser of its own: the
// ULA of a VRF (ParseULA), the pools of a Network (ParsePool), the public key of a Node (ParseKey)
// and its relay address (ParseRelay), and as a source prefix of a Network or of the admin source
// allowlist (ParseSources) and as the remote address of a connection that those prefixes are
// matched against (SourceAddr).
func FuzzParseValues(f *testing.F) {
	for _, s := range []string{"fd12:3456:789a::/48", "10.0.0.0/24", "2001:db8::/64", key1, "192.0.2.1:4000", "[2001:db8::1]:4000", "[::ffff:192.0.2.1]:1"} {
		f.Add(s)
	}
	for _, s := range []string{"192.0.2.7", "::ffff:192.0.2.7", "fe80::1%eth0", "0.0.0.0/0"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if p, err := ParseULA(s); err == nil && (p.Bits() != 48 || !p.Addr().Is6()) {
			t.Errorf("ParseULA(%q) = %s, not an IPv6 /48", s, p)
		}
		for _, family := range []int{4, 6} {
			if p, err := ParsePool(s, family); err == nil && p != p.Masked() {
				t.Errorf("ParsePool(%q, %d) = %s, with host bits", s, family, p)
			}
		}
		if k, err := ParseKey(s); err == nil && len(k) != KeySize {
			t.Errorf("ParseKey(%q) is %d bytes, not %d", s, len(k), KeySize)
		}
		if ap, err := ParseRelay(s); err == nil && (ap.Port() == 0 || ap.Addr().Is4In6()) {
			t.Errorf("ParseRelay(%q) = %s", s, ap)
		}
		if ps, err := ParseSources([]string{s}); err == nil {
			for _, p := range ps {
				if p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
					t.Errorf("ParseSources(%q) = %s, with host bits, an IPv4-mapped address or a zone", s, p)
				}
			}
		}
		if a, ok := SourceAddr(s); ok && (a.Is4In6() || a.Zone() != "") {
			t.Errorf("SourceAddr(%q) = %s, an IPv4-mapped address or with a zone", s, a)
		}
	})
}
