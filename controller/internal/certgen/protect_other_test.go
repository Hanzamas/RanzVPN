//go:build !windows

package certgen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A file whose mode cannot be set to 0600 is no file of a key: CreateKeyFile removes the file that it made and says
// why, so that no key is written to a file whose mode nobody checked (SDN-82-R1).
func TestCreateKeyFileRemovesAFileWhoseModeCannotBeSet(t *testing.T) {
	refused := errors.New("this volume keeps no modes")
	was := chmodKeyFile
	chmodKeyFile = func(*os.File, os.FileMode) error { return refused }
	t.Cleanup(func() { chmodKeyFile = was })

	path := filepath.Join(t.TempDir(), "phone.conf")
	f, acls, err := CreateKeyFile(path)
	if f != nil {
		f.Close()
		t.Error("CreateKeyFile gave a file whose mode it could not set")
	}
	if !errors.Is(err, refused) || acls {
		t.Errorf("CreateKeyFile gave %v and %v, want the error of the mode and no access lists", err, acls)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the file that CreateKeyFile made is still there: %v", err)
	}
}

// A colon is an ordinary character of a name off Windows, so CheckKeyFileName takes the names that make a stream of a file
// on Windows, and CreateKeyFile makes the file, readable by its owner only (SDN-82-R2).
func TestCreateKeyFileTakesAColonOffWindows(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"phone:1.conf", "notes.txt:phone.conf", "notes.txt::$DATA"} {
		path := filepath.Join(dir, name)
		if err := CheckKeyFileName(path); err != nil {
			t.Errorf("CheckKeyFileName(%q) = %v, want that the name is taken", path, err)
		}
		f, acls, err := CreateKeyFile(path)
		if err != nil || !acls {
			t.Fatalf("CreateKeyFile(%q) = %v, %v, want a file", path, acls, err)
		}
		f.Close()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("the file %q has the mode %v, want 0600", path, fi.Mode())
		}
	}
}
