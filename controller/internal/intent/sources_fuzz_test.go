package intent

import "testing"

// FuzzParseSources reads the input as a source prefix of a Network or of the admin source
// allowlist (ParseSources), and as the remote address of a connection that such prefixes are
// matched against (SourceAddr), which the controller workflow runs with go test -fuzz
// (ADR-0040 item 1, .github/quality/fuzz-targets.txt).
func FuzzParseSources(f *testing.F) {
	for _, s := range []string{"203.0.113.0/24", "2001:db8::/32", "192.0.2.7", "::ffff:192.0.2.7", "fe80::1%eth0", "0.0.0.0/0", "::/0"} {
		f.Add(s)
	}
	for _, s := range []string{"192.0.2.1:4000", "[2001:db8::1]:4000", "[::ffff:192.0.2.1]:1", "[fe80::1%eth0]:1", "10.0.0.5/8"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
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
