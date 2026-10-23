package payload

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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

func TestInstallRefusesEmptyData(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { return nil })

	if err := Install(dir, Payload{Name: "thing.bin"}); err == nil {
		t.Fatal("Install of a payload with no data did not fail")
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

func TestInstallRefusesAFailedSignature(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("bad signature")
	withVerify(t, func(string) error { return wantErr })

	if err := Install(dir, New("thing.bin", []byte("real bytes"))); err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("Install with a failed signature check = %v, want it to wrap %v", err, wantErr)
	}
	assertEmpty(t, dir)
}

func TestNewRecordsTheHashOfItsData(t *testing.T) {
	p := New("thing.bin", []byte("x"))
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
