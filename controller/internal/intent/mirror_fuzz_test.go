package intent

import (
	"strconv"
	"testing"
)

// FuzzParseMirror reads the input as each value of a Mirror that has a parser of its own (SDN-23):
// its sensor (ParseSensor) and its protocol (ParseProtocol). A sensor that parses is a unicast
// address with a port, in the form that it parses back to; a protocol that parses is the number of
// one of its names or the number that it spells.
func FuzzParseMirror(f *testing.F) {
	for _, s := range []string{"192.0.2.50", "192.0.2.50:4790", "[2001:db8::5]:6081", "2001:db8::5", "::ffff:192.0.2.1", "fe80::1%eth0", "0.0.0.0",
		"tcp", "udp", "icmp", "47", "0", "256", "06", ""} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if ap, err := ParseSensor(s); err == nil {
			if ap.Port() == 0 || !ap.Addr().IsValid() || ap.Addr().Is4In6() || ap.Addr().Zone() != "" || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
				t.Errorf("ParseSensor(%q) = %s", s, ap)
			}
			if again, err := ParseSensor(ap.String()); err != nil || again != ap {
				t.Errorf("ParseSensor(%q) = %s, which parses back as %s, %v", s, ap, again, err)
			}
		}
		if p, err := ParseProtocol(s); err == nil {
			if name, ok := mirrorProtocols[s]; ok {
				if p != name {
					t.Errorf("ParseProtocol(%q) = %d, want %d", s, p, name)
				}
			} else if (s == "") != (p == 0) || (s != "" && strconv.Itoa(int(p)) != s) {
				t.Errorf("ParseProtocol(%q) = %d", s, p)
			}
		}
	})
}
