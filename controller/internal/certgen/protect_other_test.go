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
