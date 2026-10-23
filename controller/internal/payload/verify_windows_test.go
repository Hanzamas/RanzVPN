//go:build windows

package payload

import (
	"os"
	"path/filepath"
	"testing"
)

// notepadPath returns a real, Microsoft-signed executable that every Windows runner and
// workstation has, so TestVerifyAuthenticode* need no certificate of their own.
func notepadPath(t *testing.T) string {
	t.Helper()
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe is not at %s: %v", path, err)
	}
	return path
}

func TestVerifyAuthenticodeAcceptsASignedFile(t *testing.T) {
	if err := verifyAuthenticode(notepadPath(t)); err != nil {
		t.Fatalf("verifyAuthenticode(notepad.exe) = %v, want nil", err)
	}
}

func TestVerifyAuthenticodeRejectsAChangedFile(t *testing.T) {
	src := notepadPath(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	if len(data) < 4096 {
		t.Skipf("%s is only %d bytes, too small to flip a byte safely away from its header", src, len(data))
	}
	// A byte well inside the file, away from the MS-DOS and PE headers at the front: changing it
	// changes the Authenticode digest without making the file an invalid PE to read back.
	mid := len(data) / 2
	data[mid] ^= 0xFF
	changed := filepath.Join(t.TempDir(), "notepad-changed.exe")
	if err := os.WriteFile(changed, data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", changed, err)
	}
	if err := verifyAuthenticode(changed); err == nil {
		t.Fatal("verifyAuthenticode did not reject a file with one byte changed")
	}
}

func TestVerifyAuthenticodeRejectsAnUnsignedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(path, []byte("not a signed executable"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	if err := verifyAuthenticode(path); err == nil {
		t.Fatal("verifyAuthenticode did not reject an unsigned file")
	}
}
