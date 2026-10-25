//go:build !(windows && (amd64 || arm64))

package password

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

// derive returns size bytes of PBKDF2-HMAC-SHA256 of secret and salt with iterations iterations,
// made by the Go standard library: the system that runs this build has no CNG.
func derive(secret string, salt []byte, iterations, size int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, secret, salt, iterations, size)
}
