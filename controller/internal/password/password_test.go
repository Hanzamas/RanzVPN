package password

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The derivation gives the vectors that every implementation of PBKDF2-HMAC-SHA256 gives for
// "password" and "salt" (the same function that RFC 7914 section 11 uses for scrypt), on each
// system: CNG on Windows, the standard library elsewhere. The last two are a salt and a password
// longer than a block of SHA-256 and a key of more than one block.
func TestDeriveVectors(t *testing.T) {
	for _, c := range []struct {
		secret     string
		salt       string
		iterations int
		size       int
		want       string
	}{
		{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
			"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
	} {
		got, err := derive(c.secret, []byte(c.salt), c.iterations, c.size)
		if err != nil {
			t.Fatalf("derive(%q, %q, %d, %d): %v", c.secret, c.salt, c.iterations, c.size, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("derive(%q, %q, %d, %d) = %x, want %s", c.secret, c.salt, c.iterations, c.size, got, c.want)
		}
	}
}

// A hash has the form that the stored text promises, with the iteration count of the node, and its
// text holds neither the password nor the same salt twice. Verify takes the right password and
// refuses every other one.
func TestHashAndVerify(t *testing.T) {
	const secret = "correct horse battery staple"
	stored, err := Hash(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "$pbkdf2-sha256$i=600000$") || strings.Contains(stored, "correct") || strings.Contains(stored, "horse") {
		t.Errorf("the stored hash is %q", stored)
	}
	p, err := Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	if p.Iterations != Iterations || len(p.Salt) != SaltSize || len(p.Key) != KeySize {
		t.Errorf("the stored hash has %d iterations, a salt of %d bytes and a hash of %d bytes", p.Iterations, len(p.Salt), len(p.Key))
	}
	if ok, err := Verify(secret, stored); err != nil || !ok {
		t.Errorf("Verify of the right password: %v, %v", ok, err)
	}
	for _, wrong := range []string{"correct horse battery stapl", "Correct horse battery staple", "", strings.Repeat("x", MaxLength+1)} {
		if ok, err := Verify(wrong, stored); err != nil || ok {
			t.Errorf("Verify(%q): %v, %v, want a mismatch", wrong, ok, err)
		}
	}
	other, err := Hash(secret)
	if err != nil {
		t.Fatal(err)
	}
	if other == stored {
		t.Error("two hashes of one password are the same text: the salt is not random")
	}
}

// The hash of a password with the salt and the count of its stored form is that stored form again,
// and Verify checks against the count that the hash holds, not the one of a new hash.
func TestVerifyUsesTheStoredCount(t *testing.T) {
	stored, err := hashWith("a long enough secret", []byte("0123456789abcdef"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := hashWith("a long enough secret", []byte("0123456789abcdef"), 3); err != nil || again != stored {
		t.Errorf("the same password, salt and count gave %q and %q (%v)", stored, again, err)
	}
	if ok, err := Verify("a long enough secret", stored); err != nil || !ok {
		t.Errorf("Verify against a hash of 3 iterations: %v, %v", ok, err)
	}
	if ok, err := Verify("a long enough secreT", stored); err != nil || ok {
		t.Errorf("Verify of a wrong password against a hash of 3 iterations: %v, %v", ok, err)
	}
}

// A stored value that is not a hash of this package is an error and never a match.
func TestVerifyRefusesAMalformedHash(t *testing.T) {
	for _, stored := range []string{"", "plain", "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$aGFzaA", "$pbkdf2-sha256$i=3$$"} {
		if ok, err := Verify("a long enough secret", stored); ok || !errors.Is(err, ErrFormat) {
			t.Errorf("Verify against %q: %v, %v, want ErrFormat", stored, ok, err)
		}
	}
}

// Parse takes what String writes and nothing else.
func TestParse(t *testing.T) {
	good, err := hashWith("a long enough secret", []byte("0123456789abcdef"), 2)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.Iterations != 2 || string(p.Salt) != "0123456789abcdef" || len(p.Key) != KeySize || p.String() != good {
		t.Errorf("Parse(%q) = %+v, which writes %q", good, p, p.String())
	}

	parts := strings.Split(good, "$")
	// parts is "", the scheme, the count, the salt and the hash
	salt, key := parts[3], parts[4]
	for _, bad := range []string{
		"",
		"pbkdf2-sha256$i=2$" + salt + "$" + key,
		"$pbkdf2-sha1$i=2$" + salt + "$" + key,
		"$pbkdf2-sha256$i=2$" + salt,
		"$pbkdf2-sha256$i=2$" + salt + "$" + key + "$extra",
		"$pbkdf2-sha256$2$" + salt + "$" + key,
		"$pbkdf2-sha256$i=0$" + salt + "$" + key,
		"$pbkdf2-sha256$i=-1$" + salt + "$" + key,
		"$pbkdf2-sha256$i=+2$" + salt + "$" + key,
		"$pbkdf2-sha256$i=02$" + salt + "$" + key,
		"$pbkdf2-sha256$i=10000001$" + salt + "$" + key,
		"$pbkdf2-sha256$i=two$" + salt + "$" + key,
		"$pbkdf2-sha256$i=2$" + salt[:6] + "$" + key,
		"$pbkdf2-sha256$i=2$" + salt + "=$" + key,
		"$pbkdf2-sha256$i=2$" + salt + "$" + key[:40],
		"$pbkdf2-sha256$i=2$" + salt + "$" + key + "AA",
		"$pbkdf2-sha256$i=2$" + strings.Repeat("A", 90) + "$" + key,
	} {
		if p, err := Parse(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("Parse(%q) = %+v, %v, want ErrFormat", bad, p, err)
		}
	}
}

// A password has 8 characters at least, counted as characters, and 256 bytes at most.
func TestCheck(t *testing.T) {
	for _, c := range []struct {
		secret string
		ok     bool
	}{
		{"", false},
		{"1234567", false},
		{"12345678", true},
		{"kata sandi", true},
		{"пароль12", true},
		{"пароль1", false},
		{strings.Repeat("x", MaxLength), true},
		{strings.Repeat("x", MaxLength+1), false},
	} {
		err := Check(c.secret)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
			t.Errorf("Check(%q) = %v, want ok %v", c.secret, err, c.ok)
		}
	}
	if _, err := Hash("short"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Hash of a short password: %v, want ErrInvalid", err)
	}
}

// Decoy takes any input, the ones Verify refuses at once among them, and gives nothing back.
func TestDecoy(t *testing.T) {
	for _, secret := range []string{"", "x", "a password of a user that does not exist", strings.Repeat("x", MaxLength+1)} {
		Decoy(secret)
	}
}
