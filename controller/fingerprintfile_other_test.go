//go:build !windows

package controllercmd

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// Outside Windows ReadFingerprint takes the file of the data directory as servercert.ReadFingerprint reads it: the
// check of who may have written it is the one of Windows, where C:\ProgramData lets every user make a folder
// (AUD1-DT-14, #496). A folder or a file that is not there, or a file that holds no fingerprint, is an error and no
// fingerprint, so ranz asks for -tls-fingerprint.
func TestReadFingerprintOutsideWindows(t *testing.T) {
	dir := t.TempDir()
	if got, err := ReadFingerprint(dir); err == nil || got != "" || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a folder with no file gave %q, %v, want an error that says it is not there", got, err)
	}
	if got, err := ReadFingerprint(filepath.Join(dir, "none")); err == nil || got != "" || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a folder that is not there gave %q, %v, want an error that says it is not there", got, err)
	}
	fp := strings.Repeat("ab", 32)
	if err := servercert.WriteFingerprint(dir, strings.ToUpper(fp)); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFingerprint(dir); err != nil || got != fp {
		t.Errorf("the file of the Controller gave %q, %v, want %q", got, err, fp)
	}
	var untrusted *UntrustedError
	if _, err := ReadFingerprint(filepath.Join(dir, "none")); errors.As(err, &untrusted) {
		t.Errorf("a folder that is not there is refused as untrusted: %v", err)
	}
}
