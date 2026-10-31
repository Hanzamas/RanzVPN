package intent

import (
	"slices"
	"testing"
)

// FuzzParseStretch reads the input as the ESI of a Stretch (ParseESI). An ESI that parses is ESISize octets that are not all zero,
// and it writes back in the one form that parses back to the same octets.
func FuzzParseStretch(f *testing.F) {
	for _, s := range []string{"00:11:22:33:44:55:66:77:88:99", "AA:BB:CC:DD:EE:FF:00:11:22:33", "00:00:00:00:00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
		"00:11:22:33:44:55:66:77:88", "00:11:22:33:44:55:66:77:88:99:aa", "0:1:2:3:4:5:6:7:8:9", "001122334455667788 99", "+1:11:22:33:44:55:66:77:88:99",
		"00:11:22:33:44:55:66:77:88:9g", ""} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		esi, err := ParseESI(s)
		if err != nil {
			return
		}
		if len(esi) != ESISize || !slices.ContainsFunc(esi, func(b byte) bool { return b != 0 }) {
			t.Fatalf("ParseESI(%q) = %x", s, esi)
		}
		again, err := ParseESI(formatESI(esi))
		if err != nil || !slices.Equal(again, esi) {
			t.Fatalf("ParseESI(%q) = %x, which writes as %s and parses back as %x, %v", s, esi, formatESI(esi), again, err)
		}
	})
}
