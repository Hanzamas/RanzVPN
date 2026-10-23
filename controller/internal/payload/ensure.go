package payload

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Ensure puts the file of p in dir unless it is there already, and returns its path (ONE-4, #313:
// ranz controller writes its rqlite member under its data directory at every start that finds it
// missing). A file with the name of p whose SHA-256 is the one recorded for p stays as it is: it is
// the file that an earlier Ensure or Install wrote after its checks, byte for byte. A file that is
// missing, or that differs in a single byte, is written from p by Install, which checks p's hash
// and its Authenticode signature before anything reaches dir. So deleting the file between two
// starts does not break the next one, and a file that someone changed is replaced by the one that
// the executable carries. dir is created if it does not exist.
func Ensure(dir string, p Payload) (string, error) {
	if len(p.Data) == 0 {
		return "", fmt.Errorf("payload: %s carries no data (a build without the real payload embedded)", p.Name)
	}
	dest := filepath.Join(dir, p.Name)
	if hasSum(dest, p.SHA256) {
		return dest, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("payload: %s: %w", p.Name, err)
	}
	if err := Install(dir, p); err != nil {
		return "", err
	}
	return dest, nil
}

// hasSum reports whether the file at path exists and has the SHA-256 sum.
func hasSum(path string, sum [32]byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return [32]byte(h.Sum(nil)) == sum
}
