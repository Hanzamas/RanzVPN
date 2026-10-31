//go:build !windows

package certgen

import "os"

// protectFile makes the file path readable by its owner only. WriteFile created the file with that
// mode, but a file that existed keeps the mode it had.
func protectFile(path string) error {
	return os.Chmod(path, 0o600)
}

// CheckKeyFileName accepts every name: a colon is an ordinary character of a name here, so no name makes a
// stream of a file, and the mode that CreateKeyFile sets is the one that the file has. It is there for the
// callers that also run on Windows, where it refuses some names (SDN-82-R2).
func CheckKeyFileName(string) error {
	return nil
}

// chmodKeyFile sets the mode of the file that CreateKeyFile made: the call that a test replaces with one
// that fails, since no file that the test makes refuses its mode.
var chmodKeyFile = (*os.File).Chmod

// CreateKeyFile makes the file path for a secret, such as the keys of a WireGuard Device, readable by
// its owner only, and opens it for writing. A file that exists is refused with an error that wraps
// fs.ErrExist, and so is a link that is there, which it does not follow (O_EXCL). The mode is set to
// 0600 on the open file, whatever the umask took from it, and the volume keeps it, so it reports true.
// A file whose mode cannot be set is removed, so that no file of a key is left with a mode that nobody
// checked.
func CreateKeyFile(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := chmodKeyFile(f, 0o600); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, false, err
	}
	return f, true, nil
}
