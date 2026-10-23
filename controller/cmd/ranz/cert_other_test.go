//go:build !windows

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Off Windows there is no key storage provider: -ksp and -signksp say so, and nothing is written.
func TestCertKSPOffWindows(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "a.pem")
	var errOut bytes.Buffer
	if code := runCert([]string{"-cn", "localhost", "-ksp", "ranz-test", "-savecert", certPath}, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "Windows only") {
		t.Errorf("ranz cert -ksp: exit code %d, stderr %q, want 1 and that the provider is of Windows only", code, errOut.String())
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Errorf("ranz cert -ksp wrote the certificate file (%v)", err)
	}

	caPath, caKey := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if code := runCert([]string{"-ca", "-cn", "CA", "-savecert", caPath, "-savekey", caKey}, io.Discard, &errOut); code != 0 {
		t.Fatalf("ranz cert -ca: exit code %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	args := []string{"-cn", "a", "-signcert", caPath, "-signksp", "ranz-test", "-savecert", filepath.Join(dir, "b.pem"), "-savekey", filepath.Join(dir, "b.key")}
	if code := runCert(args, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "-signksp") || !strings.Contains(errOut.String(), "Windows only") {
		t.Errorf("ranz cert -signksp: exit code %d, stderr %q, want 1 and that the provider is of Windows only", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "b.pem")); !os.IsNotExist(err) {
		t.Errorf("ranz cert -signksp wrote the certificate file (%v)", err)
	}
}
