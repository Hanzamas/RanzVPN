//go:build !windows

package keys

import (
	"os"
	"path/filepath"
	"testing"
)

// Off Windows the sealing key is the file store.key of the data directory, which only its owner reads.
func TestLoadSealerFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadSealer(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "store.key"))
	if err != nil {
		t.Fatalf("the sealing key is not in the data directory: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("store.key has the mode %v, want 0600", fi.Mode().Perm())
	}
}
