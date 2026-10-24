package payload

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ensureVerify substitutes verify for the life of the test with a check that counts its calls and
// returns err, so that Ensure's writes can be tested without a real Authenticode signature.
func ensureVerify(t *testing.T, err error) *int {
	t.Helper()
	old := verify
	calls := new(int)
	verify = func(string) error {
		*calls++
		return err
	}
	t.Cleanup(func() { verify = old })
	return calls
}

// ensureContent returns the content of the file name in dir, and fails the test when it cannot.
func ensureContent(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return b
}

// A file that is not there is written, in a directory that Ensure makes, after one signature check.
func TestEnsureWritesAFileThatIsMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "payload")
	calls := ensureVerify(t, nil)
	p := New("member.bin", []byte("the member"))

	got, err := Ensure(dir, p)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if want := filepath.Join(dir, "member.bin"); got != want {
		t.Errorf("Ensure returned %s, want %s", got, want)
	}
	if b := ensureContent(t, dir, "member.bin"); !bytes.Equal(b, p.Data) {
		t.Errorf("the file holds %q, want %q", b, p.Data)
	}
	if *calls != 1 {
		t.Errorf("the signature was checked %d times, want once", *calls)
	}
}

// A file that has the recorded hash stays as it is and is not checked again: the start of a
// controller whose member is in place costs a hash and nothing else.
func TestEnsureKeepsAFileThatMatches(t *testing.T) {
	dir := t.TempDir()
	calls := ensureVerify(t, nil)
	p := New("member.bin", []byte("the member"))
	if _, err := Ensure(dir, p); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(dir, p); err != nil {
		t.Fatalf("the second Ensure: %v", err)
	}
	if *calls != 1 {
		t.Errorf("the signature was checked %d times for two calls, want once", *calls)
	}
}

// A file that was deleted while the program was stopped is written again after the checks, so the
// next start is not broken (the fourth criterion of ONE-4).
func TestEnsureWritesAgainAFileThatWasDeleted(t *testing.T) {
	dir := t.TempDir()
	calls := ensureVerify(t, nil)
	p := New("member.bin", []byte("the member"))
	if _, err := Ensure(dir, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "member.bin")); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(dir, p); err != nil {
		t.Fatalf("Ensure after the file was deleted: %v", err)
	}
	if b := ensureContent(t, dir, "member.bin"); !bytes.Equal(b, p.Data) {
		t.Errorf("the file holds %q after it was written again, want %q", b, p.Data)
	}
	if *calls != 2 {
		t.Errorf("the signature was checked %d times, want once for each write", *calls)
	}
}

// A file that differs in one byte is replaced by the one that the executable carries.
func TestEnsureReplacesAFileThatWasChanged(t *testing.T) {
	dir := t.TempDir()
	calls := ensureVerify(t, nil)
	p := New("member.bin", []byte("the member"))
	if err := os.WriteFile(filepath.Join(dir, "member.bin"), []byte("the membeR"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(dir, p); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if b := ensureContent(t, dir, "member.bin"); !bytes.Equal(b, p.Data) {
		t.Errorf("the changed file holds %q after Ensure, want %q", b, p.Data)
	}
	if *calls != 1 {
		t.Errorf("the signature was checked %d times, want once", *calls)
	}
}

// A payload whose signature does not verify is never written, and Ensure returns the reason.
func TestEnsureRefusesAFailedSignature(t *testing.T) {
	dir := t.TempDir()
	bad := errors.New("bad signature")
	ensureVerify(t, bad)

	_, err := Ensure(dir, New("member.bin", []byte("the member")))
	if !errors.Is(err, bad) {
		t.Fatalf("Ensure with a failed signature check = %v, want it to wrap %v", err, bad)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("a refused Ensure left %d file(s) in %s (%v)", len(entries), dir, err)
	}
}

// A payload with no data, as a build without the real member embeds, is refused before Ensure
// touches the disk.
func TestEnsureRefusesAPayloadWithNoData(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "payload")
	ensureVerify(t, nil)

	_, err := Ensure(dir, Payload{Name: "member.bin"})
	if err == nil || !strings.Contains(err.Error(), "carries no data") {
		t.Fatalf("Ensure of a payload with no data = %v, want an error that says so", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused Ensure made %s (%v)", dir, err)
	}
}
