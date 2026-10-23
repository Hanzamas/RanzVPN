package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "thing.bin")
	if fileExists(path) {
		t.Fatal("fileExists is true for a file that is not there")
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	if !fileExists(path) || !fileExists(dir) {
		t.Fatal("fileExists is false for a file and a folder that are there")
	}
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte("same bytes"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	// Join cleans a path, so the second spelling is made by hand
	spelled := dir + string(os.PathSeparator) + "." + string(os.PathSeparator) + "a.bin"
	if !sameFile(a, a) || !sameFile(a, spelled) {
		t.Error("sameFile is false for one file under two spellings")
	}
	if sameFile(a, b) {
		t.Error("sameFile is true for two files with the same bytes")
	}
	if sameFile(a, filepath.Join(dir, "missing.bin")) || sameFile(filepath.Join(dir, "missing.bin"), a) {
		t.Error("sameFile is true for a file that is not there")
	}
}

func TestRemoveExceptRemovesAllWithNoFileToKeep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Ranz VPN")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("making the folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "thing.bin"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing a file: %v", err)
	}
	if err := removeExcept(dir, ""); err != nil {
		t.Fatalf("removeExcept: %v", err)
	}
	if fileExists(dir) {
		t.Fatal("removeExcept with no file to keep left the folder")
	}
	// A folder that is not there is no error
	if err := removeExcept(dir, ""); err != nil {
		t.Fatalf("removeExcept of a folder that is not there: %v", err)
	}
}

func TestRemoveExceptLeavesTheFileToKeep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Ranz VPN")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("making the folder: %v", err)
	}
	for _, name := range []string{"Ranz.EXE", "ranz-node.exe", filepath.Join("sub", "thing.bin")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if err := removeExcept(dir, "ranz.exe"); err != nil {
		t.Fatalf("removeExcept: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the folder: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "Ranz.EXE" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("removeExcept left %v, want only Ranz.EXE (the name of the file to keep is matched without case)", names)
	}
}

func TestRemoveExceptReportsAFolderItCannotRead(t *testing.T) {
	if err := removeExcept(filepath.Join(t.TempDir(), "missing"), "ranz.exe"); err == nil {
		t.Fatal("removeExcept of a folder that is not there did not fail while keeping a file")
	}
}
