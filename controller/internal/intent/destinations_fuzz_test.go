package intent

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// FuzzParseDestinations reads the input, one entry on each line, as the entries of the three admin
// destination lists (ParseTargetHosts, ParseUNCServers and ParseSensorPrefixes, which Normalize runs
// for the body of PUT /api/v1/admin-destinations), and as the path of a file of a node that a Listener
// names (UNCServer, AllowsServer), which the controller workflow runs with go test -fuzz (ADR-0040
// item 1, .github/quality/fuzz-targets.txt).
func FuzzParseDestinations(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1\n10.0.0.0/8\nsiem.corp.example\nlocalhost.",
		"fe80::/10\n::1\n::ffff:192.0.2.7\nFS01\n_dmarc.example",
		"10.0.0.1/8\nfe80::1%eth0\n127.1\na..b\n\n-x.example",
		`\\server\share\pfx.txt`,
		`\\?\UNC\server\share\x`,
		`\\?\GLOBALROOT\Device\Mup\server\share`,
		`\\files@SSL@443\DavWWWRoot\x.pfx`,
		`\\2001-db8--1s4.ipv6-literal.net\share`,
		`C:\ProgramData\Ranz\node.pfx`,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		entries := strings.Split(s, "\n")
		if got, err := (Destinations{Targets: entries, Sensors: entries, UNCServers: entries}).Normalize(); err == nil {
			again, err := got.Normalize()
			if err != nil || !slices.Equal(again.Targets, got.Targets) || !slices.Equal(again.Sensors, got.Sensors) || !slices.Equal(again.UNCServers, got.UNCServers) {
				t.Errorf("Normalize(%q) = %+v, which normalizes again to %+v (%v)", s, got, again, err)
			}
		}
		checkPrefixes := func(what string, ps []netip.Prefix) {
			for _, p := range ps {
				if p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
					t.Errorf("%s(%q) kept the prefix %s, with host bits, an IPv4-mapped address or a zone", what, s, p)
				}
			}
		}
		if l, err := ParseTargetHosts(entries); err == nil {
			for _, n := range l.Names {
				if n != strings.ToLower(n) || strings.HasSuffix(n, ".") || !hostNameOK(n) {
					t.Errorf("ParseTargetHosts(%q) kept the name %q", s, n)
				}
			}
			checkPrefixes("ParseTargetHosts", l.Prefixes)
			if len(l.Strings()) != len(l.Names)+len(l.Prefixes) {
				t.Errorf("ParseTargetHosts(%q) holds %d entries, and Strings gives %d", s, len(l.Names)+len(l.Prefixes), len(l.Strings()))
			}
		}
		if ps, err := ParseSensorPrefixes(entries); err == nil {
			checkPrefixes("ParseSensorPrefixes", ps)
		}
		if l, err := ParseUNCServers(entries); err == nil {
			checkPrefixes("ParseUNCServers", l.Prefixes)
		}

		server, unc := UNCServer(s)
		if !unc && server != "" {
			t.Errorf("UNCServer(%q) = %q for a path that is not on a network", s, server)
		}
		listed, err := ParseUNCServers([]string{"fs01", "192.0.2.0/24", "2001:db8::/32"})
		if err != nil {
			t.Fatal(err)
		}
		if server == "" && listed.AllowsServer(server) {
			t.Errorf("a list allows the empty server of %q", s)
		}
		_ = listed.AllowsServer(s)
	})
}
