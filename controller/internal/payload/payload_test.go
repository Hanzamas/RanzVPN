package payload

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withVerify substitutes verify for the life of the test, so Install's hash check and its write
// can be tested without a real Authenticode signature.
func withVerify(t *testing.T, f func(string) error) {
	t.Helper()
	old := verify
	verify = f
	t.Cleanup(func() { verify = old })
}

// withHashFile substitutes hashFile for the life of the test, so Install can be given a file that
// was written wrong.
func withHashFile(t *testing.T, f func(string) ([32]byte, error)) {
	t.Helper()
	old := hashFile
	hashFile = f
	t.Cleanup(func() { hashFile = old })
}

func TestInstallWritesTheExactBytes(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { return nil })

	data := []byte("the payload bytes")
	if err := Install(dir, New("thing.bin", data)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "thing.bin"))
	if err != nil {
		t.Fatalf("reading the installed file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("the installed file is %q, not %q", got, data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("Install left %d files in %s, not 1 (a temporary file was not cleaned up)", len(entries), dir)
	}
}

func TestInstallReplacesAFileThatIsThere(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { return nil })
	dest := filepath.Join(dir, "thing.bin")
	if err := os.WriteFile(dest, []byte("the old bytes"), 0o600); err != nil {
		t.Fatalf("writing the old file: %v", err)
	}

	if err := Install(dir, New("thing.bin", []byte("the new bytes"))); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "the new bytes" {
		t.Fatalf("the installed file is %q, not the new bytes", got)
	}
}

func TestInstallRefusesEmptyData(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { return nil })

	if err := Install(dir, Payload{Name: "thing.bin"}); err == nil {
		t.Fatal("Install of a payload with no data did not fail")
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesANameThatIsNoPlainFileName(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { t.Fatal("verify ran for a name that is no file name"); return nil })

	for _, name := range []string{"", ".", "..", "sub/thing.bin", "../thing.bin"} {
		if err := Install(dir, New(name, []byte("bytes"))); err == nil {
			t.Errorf("Install of a payload named %q did not fail", name)
		}
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesAMismatchedHash(t *testing.T) {
	dir := t.TempDir()
	// The verify function must never run: the hash check refuses first.
	withVerify(t, func(string) error { t.Fatal("verify ran although the hash does not match"); return nil })

	p := Payload{Name: "thing.bin", Data: []byte("real bytes"), SHA256: [32]byte{1, 2, 3}}
	if err := Install(dir, p); err == nil {
		t.Fatal("Install of a payload whose data does not match its recorded hash did not fail")
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesAFileThatWasWrittenWrong(t *testing.T) {
	dir := t.TempDir()
	// The signature check must never run on a file whose hash is wrong
	withVerify(t, func(string) error { t.Fatal("verify ran although the file does not match the hash"); return nil })
	withHashFile(t, func(string) ([32]byte, error) { return sha256.Sum256([]byte("other bytes")), nil })

	err := Install(dir, New("thing.bin", []byte("real bytes")))
	if err == nil || !strings.Contains(err.Error(), "does not match the hash") {
		t.Fatalf("Install of a file that was written wrong = %v, want a refusal for its hash", err)
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesAFileThatCannotBeHashed(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("disk gone")
	withVerify(t, func(string) error { t.Fatal("verify ran although the file cannot be hashed"); return nil })
	withHashFile(t, func(string) ([32]byte, error) { return [32]byte{}, wantErr })

	if err := Install(dir, New("thing.bin", []byte("real bytes"))); !errors.Is(err, wantErr) {
		t.Fatalf("Install of a file that cannot be hashed = %v, want it to wrap %v", err, wantErr)
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesAFailedSignature(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("bad signature")
	withVerify(t, func(string) error { return wantErr })

	if err := Install(dir, New("thing.bin", []byte("real bytes"))); err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("Install with a failed signature check = %v, want it to wrap %v", err, wantErr)
	}
	assertEmpty(t, dir)
}

func TestInstallLeavesTheFileThatIsThereWhenACheckFails(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { return errors.New("bad signature") })
	dest := filepath.Join(dir, "thing.bin")
	if err := os.WriteFile(dest, []byte("the old bytes"), 0o600); err != nil {
		t.Fatalf("writing the old file: %v", err)
	}

	if err := Install(dir, New("thing.bin", []byte("the new bytes"))); err == nil {
		t.Fatal("Install with a failed signature check did not fail")
	}
	if got, _ := os.ReadFile(dest); string(got) != "the old bytes" {
		t.Fatalf("a refused Install changed the file that was there: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a refused Install left %d files in %s, not 1", len(entries), dir)
	}
}

func TestNewRecordsTheHashOfItsData(t *testing.T) {
	p := New("thing.bin", []byte("x"))
	if p.SHA256 != sha256.Sum256([]byte("x")) {
		t.Fatalf("New recorded the hash %x, not the SHA-256 of its data", p.SHA256)
	}
	dir := t.TempDir()
	calledWith := ""
	withVerify(t, func(path string) error { calledWith = path; return nil })
	if err := Install(dir, p); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if calledWith == "" || filepath.Dir(calledWith) != dir {
		t.Fatalf("verify was called with %q, not a file inside %s", calledWith, dir)
	}
}

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "thing.bin")
	data := []byte("some bytes to hash")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	got, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("fileSHA256: %v", err)
	}
	if got != sha256.Sum256(data) {
		t.Fatalf("fileSHA256 = %x, not the SHA-256 of the file", got)
	}
	if _, err := fileSHA256(filepath.Join(filepath.Dir(path), "missing.bin")); err == nil {
		t.Fatal("fileSHA256 of a file that is not there did not fail")
	}
}

// assertEmpty fails the test unless dir holds no files: a refused Install must leave no temporary
// file behind and never create the destination path.
func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("a refused Install left %d file(s) in %s: %v", len(entries), dir, names)
	}
}
