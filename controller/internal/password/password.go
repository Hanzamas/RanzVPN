// Package password keeps the passwords of the users of the controller (SDN-31, #225). A password
// is stored as a PBKDF2-HMAC-SHA256 hash with a random salt of its own and the iteration count next
// to the hash, so the count can be raised later: the scheme of the passwords in the Configuration
// store of a Node (ConfigStore.c, ADR-0022 amendment of 2026-10-19), written as a PHC string:
//
//	$pbkdf2-sha256$i=600000$SALT$HASH
//
// where SALT and HASH are the unpadded base64 of RFC 4648. The derivation is the one of the
// operating system where there is one: CNG (BCryptDeriveKeyPBKDF2) on Windows, in
// pbkdf2_windows.go, and the Go standard library everywhere else, in pbkdf2_other.go. Both give the
// same bytes, so a store that was backed up on one system verifies its passwords on the other.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// Iterations is the iteration count of a new hash: 600000, which OWASP recommends for
	// PBKDF2-HMAC-SHA256 (2023) and which the Configuration store of a Node uses too.
	Iterations = 600000
	// SaltSize is the size in bytes of the salt of a new hash.
	SaltSize = 16
	// KeySize is the size in bytes of a hash: the output of SHA-256.
	KeySize = 32
	// MinLength is the fewest characters that a password has.
	MinLength = 8
	// MaxLength is the most bytes that a password has. A longer one is no password of this
	// controller, so a login with one is refused without a derivation, and no caller can make the
	// controller derive from more.
	MaxLength = 256
	// MaxIterations is the largest iteration count that Parse takes from a stored hash, so that a
	// damaged value cannot make a login run for hours.
	MaxIterations = 10_000_000

	// scheme names the algorithm in the stored form.
	scheme = "pbkdf2-sha256"
	// minSalt is the shortest salt that Parse takes: 64 bits, the least RFC 8018 recommends.
	minSalt = 8
	// maxSalt is the longest salt that Parse takes.
	maxSalt = 64
)

var (
	// ErrInvalid marks a password that the rules of the controller do not take: too short or too
	// long.
	ErrInvalid = errors.New("invalid password")
	// ErrFormat marks a stored value that is not a hash of this package.
	ErrFormat = errors.New("not a stored password hash")
)

// b64 is the base64 of the stored form: unpadded, and strict, so that each value has one text.
var b64 = base64.RawStdEncoding.Strict()

// decoySalt is the salt that Decoy derives with.
var decoySalt = []byte("ranz-decoy-salt!")

// Params are the parts of a stored hash.
type Params struct {
	// Iterations is the iteration count of PBKDF2.
	Iterations int
	// Salt is the salt of the hash.
	Salt []byte
	// Key is the derived key, KeySize bytes.
	Key []byte
}

// String returns the stored form of p.
func (p Params) String() string {
	return "$" + scheme + "$i=" + strconv.Itoa(p.Iterations) + "$" + b64.EncodeToString(p.Salt) + "$" + b64.EncodeToString(p.Key)
}

// Parse reads the stored form of a hash. It takes only the text that String writes: the algorithm
// pbkdf2-sha256, an iteration count from 1 to MaxIterations in its plain digits, a salt of 8 to 64
// bytes and a hash of KeySize bytes, in unpadded base64, and no line end, which the base64 decoder
// of Go would skip.
func Parse(encoded string) (Params, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != scheme || strings.ContainsAny(encoded, "\r\n") {
		return Params{}, fmt.Errorf("%w: it is not a $%s$ hash", ErrFormat, scheme)
	}
	count, ok := strings.CutPrefix(parts[2], "i=")
	n, err := strconv.Atoi(count)
	if !ok || err != nil || strconv.Itoa(n) != count || n < 1 || n > MaxIterations {
		return Params{}, fmt.Errorf("%w: the iteration count is not a number from 1 to %d", ErrFormat, MaxIterations)
	}
	salt, err := b64.DecodeString(parts[3])
	if err != nil || len(salt) < minSalt || len(salt) > maxSalt {
		return Params{}, fmt.Errorf("%w: the salt is not %d to %d bytes in base64", ErrFormat, minSalt, maxSalt)
	}
	key, err := b64.DecodeString(parts[4])
	if err != nil || len(key) != KeySize {
		return Params{}, fmt.Errorf("%w: the hash is not %d bytes in base64", ErrFormat, KeySize)
	}
	return Params{Iterations: n, Salt: salt, Key: key}, nil
}

// Check applies the rules of the controller to a password: MinLength characters at least and
// MaxLength bytes at most. An error wraps ErrInvalid.
func Check(secret string) error {
	if len(secret) > MaxLength {
		return fmt.Errorf("%w: a password has at most %d bytes", ErrInvalid, MaxLength)
	}
	if utf8.RuneCountInString(secret) < MinLength {
		return fmt.Errorf("%w: a password has at least %d characters", ErrInvalid, MinLength)
	}
	return nil
}

// Hash returns the stored form of a new hash of secret: a random salt and Iterations iterations.
// A password that Check refuses is refused here too.
func Hash(secret string) (string, error) {
	if err := Check(secret); err != nil {
		return "", err
	}
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: drawing a salt: %w", err)
	}
	return hashWith(secret, salt, Iterations)
}

// hashWith returns the stored form of the hash of secret with the salt salt and iterations
// iterations.
func hashWith(secret string, salt []byte, iterations int) (string, error) {
	key, err := derive(secret, salt, iterations, KeySize)
	if err != nil {
		return "", err
	}
	return Params{Iterations: iterations, Salt: salt, Key: key}.String(), nil
}

// Verify reports whether secret is the password that the stored hash encoded holds, comparing in
// constant time. A stored value that Parse refuses is an error, not a mismatch. A secret that no
// password of this controller can be (none, or more than MaxLength bytes) is a mismatch at once.
func Verify(secret, encoded string) (bool, error) {
	p, err := Parse(encoded)
	if err != nil {
		return false, err
	}
	if secret == "" || len(secret) > MaxLength {
		return false, nil
	}
	key, err := derive(secret, p.Salt, p.Iterations, len(p.Key))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, p.Key) == 1, nil
}

// Decoy does the work of Verify against no hash, so that a login of a name that no user has, or of
// a user that has no password, takes as long as one of a user that has: the time of a login does not
// tell which names exist. It returns nothing, and a failed derivation changes nothing.
func Decoy(secret string) {
	if secret == "" || len(secret) > MaxLength {
		return
	}
	_, _ = derive(secret, decoySalt, Iterations, KeySize)
}
