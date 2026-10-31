package certgen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// CreateKeyFile makes a new file for a secret, which only its owner reads (and on Windows SYSTEM and the
// Administrators, which ranz device create checks), and never opens a file that exists, nor a link (SDN-82-R1).
func TestCreateKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phone.conf")
	f, acls, err := CreateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("PrivateKey = one"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !acls {
		t.Error("CreateKeyFile says that the volume of a temporary folder keeps no access lists")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "PrivateKey = one" {
		t.Errorf("the file holds %q (%v)", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("the file has the mode %v, want 0600", fi.Mode())
		}
	}

	// A file that exists is refused, and keeps what it holds
	if f, _, err := CreateKeyFile(path); !errors.Is(err, fs.ErrExist) {
		if f != nil {
			f.Close()
		}
		t.Errorf("CreateKeyFile of a file that exists: %v, want that it exists", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "PrivateKey = one" {
		t.Errorf("the file holds %q (%v) after the refusal", b, err)
	}

	// A link is refused, and the file that it names is not made
	if runtime.GOOS != "windows" {
		target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link.conf")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if f, _, err := CreateKeyFile(link); !errors.Is(err, fs.ErrExist) {
			if f != nil {
				f.Close()
			}
			t.Errorf("CreateKeyFile of a link: %v, want that it exists", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("CreateKeyFile made the file that a link names: %v", err)
		}
	}

	if _, _, err := CreateKeyFile(filepath.Join(dir, "missing", "phone.conf")); err == nil {
		t.Error("a file in a folder that does not exist was made")
	}
}
