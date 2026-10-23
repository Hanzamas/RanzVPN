//go:build windows

package payload

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signedCandidates are the executables of a Windows runner or workstation that carry an embedded
// Authenticode signature of Microsoft, the signature that WinVerifyTrust reads from the file
// itself: the pwsh.exe that the steps of CI run in, and Microsoft Edge with its updater. Most files
// of System32, notepad.exe among them, are signed by catalog instead and carry none, so they are no
// fixture for a check of the signature of a file.
func signedCandidates() []string {
	var found []string
	if path, err := exec.LookPath("pwsh.exe"); err == nil {
		found = append(found, path)
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		found = append(found,
			filepath.Join(base, "PowerShell", "7", "pwsh.exe"),
			filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(base, "Microsoft", "EdgeUpdate", "MicrosoftEdgeUpdate.exe"),
		)
	}
	var existing []string
	for _, path := range found {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	return existing
}

// signedFile returns an executable that verifyAuthenticode accepts, or fails the test with the
// verdict on each candidate.
func signedFile(t *testing.T) string {
	t.Helper()
	candidates := signedCandidates()
	var verdicts []string
	for _, path := range candidates {
		err := verifyAuthenticode(path)
		if err == nil {
			return path
		}
		verdicts = append(verdicts, path+": "+err.Error())
	}
	t.Fatalf("none of the %d signed executables of this machine verifies: %s", len(candidates), strings.Join(verdicts, "; "))
	return ""
}

func TestVerifyAuthenticodeAcceptsASignedFile(t *testing.T) {
	path := signedFile(t)
	t.Logf("verifyAuthenticode accepts %s", path)
}

func TestVerifyAuthenticodeRejectsAChangedFile(t *testing.T) {
	src := signedFile(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	// A byte well inside the file, away from the MS-DOS and PE headers at the front and the
	// signature at the end: changing it changes the Authenticode digest without making the file an
	// invalid PE to read back.
	mid := len(data) / 2
	data[mid] ^= 0xFF
	changed := filepath.Join(t.TempDir(), "changed.exe")
	if err := os.WriteFile(changed, data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", changed, err)
	}
	err = verifyAuthenticode(changed)
	if err == nil {
		t.Fatal("verifyAuthenticode did not reject a file with one byte changed")
	}
	// The file keeps its signature, so the refusal must be about the digest and not about a
	// signature that is missing
	if strings.Contains(err.Error(), "no Authenticode signature") {
		t.Fatalf("verifyAuthenticode refused the changed file for a missing signature: %v", err)
	}
	t.Logf("verifyAuthenticode refuses a file with one byte changed: %v", err)
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

func TestTrustErrorNamesTheCause(t *testing.T) {
	if err := trustError(trustOK); err != nil {
		t.Errorf("trustError(trustOK) = %v, want nil", err)
	}
	for code, want := range map[uint32]string{
		trustNoSignature:  "no Authenticode signature",
		trustBadDigest:    "not the one that was signed",
		certUntrustedRoot: "trusted root",
		0x80004005:        "WinVerifyTrust 0x80004005",
	} {
		err := trustError(code)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("trustError(%#x) = %v, want a message with %q", code, err, want)
		}
	}
}
