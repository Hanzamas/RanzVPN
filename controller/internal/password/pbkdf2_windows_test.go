//go:build windows && (amd64 || arm64)

package password

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"strings"
	"testing"
)

// CNG derives what the Go standard library derives, for the iteration counts, the sizes and the
// passwords of each length that the package takes, so a store that moves from a Windows controller to
// a Linux one keeps its passwords. A derivation that CNG refuses is an error.
func TestCNGMatchesTheStandardLibrary(t *testing.T) {
	salt := []byte("0123456789abcdef")
	for _, secret := range []string{"x", "password", strings.Repeat("p", 64), strings.Repeat("q", 65), strings.Repeat("r", MaxLength), "пароль и 密码"} {
		for _, iterations := range []int{1, 2, 1000} {
			for _, size := range []int{20, 32, 33, 64} {
				got, err := derive(secret, salt, iterations, size)
				if err != nil {
					t.Fatalf("derive(%q, salt, %d, %d): %v", secret, iterations, size, err)
				}
				want, err := pbkdf2.Key(sha256.New, secret, salt, iterations, size)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("derive(%q, salt, %d, %d) = %x, the standard library gives %x", secret, iterations, size, got, want)
				}
			}
		}
	}
	for _, c := range []struct {
		secret     string
		salt       []byte
		iterations int
		size       int
	}{
		{"", salt, 1, 32},
		{"password", nil, 1, 32},
		{"password", salt, 0, 32},
		{"password", salt, 1, 0},
	} {
		if got, err := derive(c.secret, c.salt, c.iterations, c.size); err == nil {
			t.Errorf("derive(%q, %q, %d, %d) = %x, want an error", c.secret, c.salt, c.iterations, c.size, got)
		}
	}
}
