//go:build !windows

package certgen

import "os"

// protectFile makes the file path readable by its owner only. WriteFile created the file with that
// mode, but a file that existed keeps the mode it had.
func protectFile(path string) error {
	return os.Chmod(path, 0o600)
}

// CreateKeyFile makes the file path for a secret, such as the keys of a WireGuard Device, readable by
// its owner only, and opens it for writing. A file that exists is refused with an error that wraps
// fs.ErrExist, and so is a link that is there, which it does not follow (O_EXCL). The mode is set to
// 0600 on the open file, whatever the umask took from it, and the volume keeps it, so it reports true.
func CreateKeyFile(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, false, err
	}
	return f, true, nil
}
