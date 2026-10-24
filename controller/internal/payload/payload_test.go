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

// Windows reads a catalog by its extension, so the file that is checked ends in the name it will
// have: a catalog checked under another extension never verifies (ONE-3, #312).
func TestInstallChecksTheFileUnderTheExtensionItWillHave(t *testing.T) {
	dir := t.TempDir()
	calledWith := ""
	withVerify(t, func(path string) error { calledWith = path; return nil })

	if err := Install(dir, New("package.cat", []byte("a catalog"))); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.HasSuffix(calledWith, "package.cat") {
		t.Fatalf("verify was called with %q, which does not end in the name package.cat", calledWith)
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

// An Unsigned payload, a file that cannot carry a signature, is written after its hash check and
// never reaches the Authenticode check (ONE-3, #312).
func TestInstallDoesNotRunTheSignatureCheckForAnUnsignedPayload(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { t.Fatal("verify ran for an unsigned payload"); return nil })

	data := []byte("the INF of a driver package")
	if err := Install(dir, NewUnsigned("driver.inf", data)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "driver.inf"))
	if err != nil {
		t.Fatalf("reading the installed file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("the installed file is %q, not %q", got, data)
	}
}

// The hash check of an Unsigned payload stands: a file that was written wrong is refused.
func TestInstallChecksTheHashOfAnUnsignedPayload(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { t.Fatal("verify ran for an unsigned payload"); return nil })
	withHashFile(t, func(string) ([32]byte, error) { return sha256.Sum256([]byte("other bytes")), nil })

	err := Install(dir, NewUnsigned("driver.inf", []byte("real bytes")))
	if err == nil || !strings.Contains(err.Error(), "does not match the hash") {
		t.Fatalf("Install of an unsigned file that was written wrong = %v, want a refusal for its hash", err)
	}
	assertEmpty(t, dir)
}

// withVerifyCatalog substitutes verifyCatalog for the life of the test, so Install's handling of a
// Catalog Member can be tested without a real catalog.
func withVerifyCatalog(t *testing.T, f func(catalog, path string) error) {
	t.Helper()
	old := verifyCatalog
	verifyCatalog = f
	t.Cleanup(func() { verifyCatalog = old })
}

// A Catalog Member is written after its hash check and checked as a member of the catalog that was
// written to the same directory before it, never by a signature of its own (ONE-3, #312).
func TestInstallChecksACatalogMemberAgainstItsCatalog(t *testing.T) {
	dir := t.TempDir()
	withVerify(t, func(string) error { t.Fatal("verify ran for a catalog member"); return nil })
	var gotCatalog, gotFile string
	withVerifyCatalog(t, func(catalog, path string) error {
		gotCatalog, gotFile = catalog, path
		return nil
	})

	data := []byte("a library that the catalog lists")
	if err := Install(dir, NewCatalogMember("lib.dll", data, "package.cat")); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if want := filepath.Join(dir, "package.cat"); gotCatalog != want {
		t.Errorf("the catalog check was given the catalog %q, want %q", gotCatalog, want)
	}
	if gotFile == "" || filepath.Dir(gotFile) != dir {
		t.Errorf("the catalog check was given %q, not a file inside %s", gotFile, dir)
	}
	got, err := os.ReadFile(filepath.Join(dir, "lib.dll"))
	if err != nil {
		t.Fatalf("reading the installed file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("the installed file is %q, not %q", got, data)
	}
}

// A catalog that does not list the file refuses it: nothing is written.
func TestInstallRefusesACatalogMemberThatTheCatalogRejects(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("not in the catalog")
	withVerifyCatalog(t, func(string, string) error { return wantErr })

	err := Install(dir, NewCatalogMember("lib.dll", []byte("real bytes"), "package.cat"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Install of a file that its catalog rejects = %v, want it to wrap %v", err, wantErr)
	}
	assertEmpty(t, dir)
}

// The hash check of a Catalog Member stands, and runs first.
func TestInstallChecksTheHashOfACatalogMember(t *testing.T) {
	dir := t.TempDir()
	withVerifyCatalog(t, func(string, string) error { t.Fatal("the catalog check ran although the file does not match the hash"); return nil })
	withHashFile(t, func(string) ([32]byte, error) { return sha256.Sum256([]byte("other bytes")), nil })

	err := Install(dir, NewCatalogMember("lib.dll", []byte("real bytes"), "package.cat"))
	if err == nil || !strings.Contains(err.Error(), "does not match the hash") {
		t.Fatalf("Install of a catalog member that was written wrong = %v, want a refusal for its hash", err)
	}
	assertEmpty(t, dir)
}

func TestInstallRefusesACatalogNameThatIsNoPlainFileName(t *testing.T) {
	dir := t.TempDir()
	withVerifyCatalog(t, func(string, string) error { t.Fatal("the catalog check ran for a catalog that is no file name"); return nil })

	for _, catalog := range []string{".", "..", "sub/package.cat", "../package.cat"} {
		if err := Install(dir, NewCatalogMember("lib.dll", []byte("bytes"), catalog)); err == nil {
			t.Errorf("Install of a payload whose catalog is named %q did not fail", catalog)
		}
	}
	assertEmpty(t, dir)
}

func TestNewCatalogMemberRecordsTheHashAndTheCatalog(t *testing.T) {
	p := NewCatalogMember("lib.dll", []byte("x"), "package.cat")
	if p.Catalog != "package.cat" {
		t.Errorf("NewCatalogMember recorded the catalog %q, not package.cat", p.Catalog)
	}
	if p.SHA256 != sha256.Sum256([]byte("x")) {
		t.Errorf("NewCatalogMember recorded the hash %x, not the SHA-256 of its data", p.SHA256)
	}
	if p.Unsigned {
		t.Error("NewCatalogMember marked the payload unsigned: its catalog check must run")
	}
	if New("lib.dll", []byte("x")).Catalog != "" {
		t.Error("New named a catalog: its own signature must be checked")
	}
}

func TestNewUnsignedRecordsTheHashAndTheFlag(t *testing.T) {
	p := NewUnsigned("driver.inf", []byte("x"))
	if !p.Unsigned {
		t.Error("NewUnsigned did not mark the payload unsigned")
	}
	if p.SHA256 != sha256.Sum256([]byte("x")) {
		t.Errorf("NewUnsigned recorded the hash %x, not the SHA-256 of its data", p.SHA256)
	}
	if New("driver.sys", []byte("x")).Unsigned {
		t.Error("New marked a payload unsigned: its signature must be checked")
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
