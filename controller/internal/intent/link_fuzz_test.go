package intent

import "testing"

// FuzzParseVTEP reads the input as the address of a tunnel endpoint of a Node (SDN-76, ParseVTEPAddress).
// An address that parses is an IP address of one Node, without a zone and not IPv4-mapped, in the form
// that it parses back to.
func FuzzParseVTEP(f *testing.F) {
	for _, s := range []string{"10.1.0.1", "2001:db8::2", "::ffff:10.1.0.1", "fe80::1%eth0", "0.0.0.0", "::", "224.0.0.5", "ff02::1", "10.1.0.1:4789", "dc-gw.example.com", ""} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseVTEPAddress(s)
		if err != nil {
			return
		}
		if !a.IsValid() || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			t.Errorf("ParseVTEPAddress(%q) = %s", s, a)
		}
		if again, err := ParseVTEPAddress(a.String()); err != nil || again != a {
			t.Errorf("ParseVTEPAddress(%q) = %s, which parses back as %s, %v", s, a, again, err)
		}
	})
}
