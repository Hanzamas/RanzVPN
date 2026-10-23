//go:build !windows

package certgen

import "os"

// protectFile makes the file path readable by its owner only. WriteFile created the file with that
// mode, but a file that existed keeps the mode it had.
func protectFile(path string) error {
	return os.Chmod(path, 0o600)
}
