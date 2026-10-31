//go:build windows

package certgen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// On Windows a colon in the last element of a name makes a stream of a file, which CheckKeyFileName refuses (SDN-82-R2).
// The colon of a drive is no such colon, and the other forms of a path are taken.
func TestCheckKeyFileName(t *testing.T) {
	for _, path := range []string{
		`phone.conf`, `C:phone.conf`, `C:\temp\phone.conf`, `C:/temp/phone.conf`, `\\server\share\phone.conf`, `\\?\C:\temp\phone.conf`,
	} {
		if err := CheckKeyFileName(path); err != nil {
			t.Errorf("CheckKeyFileName(%q) = %v, want that the name is taken", path, err)
		}
	}
	for _, path := range []string{
		`notes.txt:phone.conf`, `C:notes.txt:phone.conf`, `C:\temp\notes.txt:phone.conf`, `C:/temp/notes.txt:phone.conf`,
		`C:\temp\notes.txt::$DATA`, `C:\temp\notes.txt:`, `\\server\share\notes.txt:phone.conf`, `\\?\C:\temp\notes.txt:phone.conf`,
	} {
		err := CheckKeyFileName(path)
		var pe *fs.PathError
		if !errors.Is(err, ErrStream) || !errors.As(err, &pe) || pe.Path != path {
			t.Errorf("CheckKeyFileName(%q) = %v, want an error that wraps ErrStream and names the path", path, err)
		}
	}
}

// The third finding of the review of SDN-82-R1: a name that makes a stream of a file that exists is refused by CreateKeyFile,
// and the keys reach no stream. The ACL that the call gives is for a new file, so a stream that it made would have the ACL
// of notes.txt, which other accounts may read; the test makes the stream by hand first, so that the volume is one that keeps
// streams and it is the refusal that stops it. The file keeps what it holds, and no stream is made, whether the file exists
// or not (SDN-82-R2).
func TestCreateKeyFileMakesNoStream(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes+":probe", []byte("probe"), 0o600); err != nil {
		t.Fatalf("a name with a colon makes no stream on the volume of the test, which the test needs: %v", err)
	}
	if b, err := os.ReadFile(notes + ":probe"); err != nil || string(b) != "probe" {
		t.Fatalf("the stream that the test made holds %q (%v), want probe", b, err)
	}

	missing := filepath.Join(dir, "missing.txt")
	for _, path := range []string{notes + ":phone.conf", notes + "::$DATA", missing + ":phone.conf"} {
		f, _, err := CreateKeyFile(path)
		if f != nil {
			f.Close()
		}
		if !errors.Is(err, ErrStream) {
			t.Errorf("CreateKeyFile(%q) = %v, want a refusal that wraps ErrStream", path, err)
		}
	}
	if _, err := os.Stat(notes + ":phone.conf"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("CreateKeyFile made the stream phone.conf of notes.txt: %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("CreateKeyFile made the file missing.txt for a stream of it: %v", err)
	}
	if b, err := os.ReadFile(notes); err != nil || string(b) != "notes" {
		t.Errorf("notes.txt holds %q (%v) after the refusals, want what it held", b, err)
	}
}
