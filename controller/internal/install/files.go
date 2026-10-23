package install

import (
	"os"
	"path/filepath"
	"strings"
)

// fileExists reports whether something is at path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// sameFile reports whether a and b name the same file, whatever the spelling of their paths: the
// running ranz.exe and the copy of it in the Ranz folder can be one file.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// removeExcept removes the folder dir and what it holds, except the file named keep in it, which
// a running process holds open and which Windows does not let go. With no keep it removes all of
// dir, the folder too. With one it empties the folder and leaves the folder and that file.
func removeExcept(dir, keep string) error {
	if keep == "" {
		return os.RemoveAll(dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), keep) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
