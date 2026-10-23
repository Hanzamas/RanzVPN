//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// kspName returns a name for a key of the provider that no other test or run uses.
func kspName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Ranz cert test " + hex.EncodeToString(b)
}

// thumbprintOf returns the thumbprint that ranz cert printed.
func thumbprintOf(t *testing.T, out string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^Thumbprint   ([0-9A-F]{40})$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the output has no thumbprint:\n%s", out)
	}
	return m[1]
}

// ranz cert -ksp keeps the key in the Microsoft Software Key Storage Provider and puts the
// certificate into the My store of the user, linked to the key, where the node looks for the
// certificate of its listener by its thumbprint; -signksp signs with a CA key of the provider.
// The CA and a certificate that it signs are made that way, and the certificate verifies against
// the CA, as does a certificate with its key in a file that the same CA key signs.
func TestCertInTheKeyStorageProvider(t *testing.T) {
	dir := t.TempDir()
	caName, leafName := kspName(t), kspName(t)
	caPath, leafPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "leaf.pem")
	t.Cleanup(func() {
		keys.DeleteKSP(caName, false)
		keys.DeleteKSP(leafName, false)
	})

	var out, errOut bytes.Buffer
	if code := runCert([]string{"-ca", "-cn", "Ranz KSP test CA", "-ksp", caName, "-savecert", caPath}, &out, &errOut); code != 0 {
		t.Fatalf("ranz cert -ca -ksp: exit code %d, stderr %q", code, errOut.String())
	}
	caThumbprint := thumbprintOf(t, out.String())
	t.Cleanup(func() { certgen.RemoveFromStore(caThumbprint, false) })
	for _, want := range []string{`Store        CurrentUser\My, linked to its key`, `in the Microsoft Software Key Storage Provider as "` + caName + `"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
	if err := certgen.CheckStoredKey(caThumbprint, false); err != nil {
		t.Errorf("the CA certificate in the store does not find its key: %v", err)
	}

	out.Reset()
	args := []string{"-cn", "localhost", "-signcert", caPath, "-signksp", caName, "-ksp", leafName, "-savecert", leafPath}
	if code := runCert(args, &out, &errOut); code != 0 {
		t.Fatalf("ranz cert -signksp -ksp: exit code %d, stderr %q", code, errOut.String())
	}
	leafThumbprint := thumbprintOf(t, out.String())
	t.Cleanup(func() { certgen.RemoveFromStore(leafThumbprint, false) })
	ca, leaf := certFile(t, caPath), certFile(t, leafPath)
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Errorf("the certificate does not verify against its CA: %v", err)
	}
	if err := certgen.CheckStoredKey(leafThumbprint, false); err != nil {
		t.Errorf("the certificate in the store does not find its key: %v", err)
	}

	// The key of the CA in the provider signs a certificate whose key is in a file, which a
	// listener serves with and a client that trusts the CA accepts
	filePath, fileKey := filepath.Join(dir, "file.pem"), filepath.Join(dir, "file.key")
	args = []string{"-cn", "localhost", "-signcert", caPath, "-signksp", caName, "-savecert", filePath, "-savekey", fileKey}
	if code := runCert(args, io.Discard, &errOut); code != 0 {
		t.Fatalf("ranz cert -signksp: exit code %d, stderr %q", code, errOut.String())
	}
	if err := handshake(t, filePath, fileKey, caPath, "localhost"); err != nil {
		t.Errorf("a client that trusts the CA refused the certificate that its key in the provider signed: %v", err)
	}

	// A name of a key that the provider holds is refused, and no file is written
	again := filepath.Join(dir, "again.pem")
	errOut.Reset()
	if code := runCert([]string{"-cn", "again", "-ksp", leafName, "-savecert", again}, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "already") {
		t.Errorf("ranz cert -ksp with a name that is taken: exit code %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(again); !os.IsNotExist(err) {
		t.Errorf("a failed ranz cert wrote the certificate file (%v)", err)
	}
	// A CA key that the provider does not hold
	errOut.Reset()
	args = []string{"-cn", "a", "-signcert", caPath, "-signksp", kspName(t), "-savecert", again, "-savekey", filepath.Join(dir, "again.key")}
	if code := runCert(args, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "-signksp") {
		t.Errorf("ranz cert -signksp with a key that is not there: exit code %d, stderr %q", code, errOut.String())
	}
}
