package password

import "testing"

// FuzzParse reads the input as a stored hash (Parse): the text of a store that a damaged backup or
// another program wrote. A value that parses is the text that String writes for it, within the
// bounds of the package, so a hash that Verify derives from never costs more than MaxIterations.
func FuzzParse(f *testing.F) {
	stored, err := hashWith("a long enough secret", []byte("0123456789abcdef"), 2)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(stored)
	f.Add("")
	f.Add("$pbkdf2-sha256$i=600000$$")
	f.Add("$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g")
	// The input that the first run of the fuzz test found: a line end inside the hash, which the base64 decoder skips
	f.Add("$pbkdf2-sha256$i=1$00000000000$000000000000\r0000000000000000000000000000000")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			return
		}
		if p.String() != s {
			t.Fatalf("Parse(%q) writes back as %q", s, p.String())
		}
		if p.Iterations < 1 || p.Iterations > MaxIterations || len(p.Salt) < minSalt || len(p.Salt) > maxSalt || len(p.Key) != KeySize {
			t.Fatalf("Parse(%q) = %d iterations, a salt of %d bytes and a hash of %d bytes", s, p.Iterations, len(p.Salt), len(p.Key))
		}
	})
}
