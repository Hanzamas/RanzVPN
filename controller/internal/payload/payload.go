// Package payload is the mechanism that writes a file embedded in ranz.exe out to disk (ADR-0011
// amendment of 2026-10-22, ONE-2 #311; the Payload entry of CONTEXT.md): ranz-node.exe, the rqlite
// member of a Controller (ONE-4 #313, which Ensure writes again when it is missing), and the
// Wintun driver, the SeLow package and the XDP runtime of ONE-3 #312 (wintun.go, selow.go,
// xdp.go). A Payload carries its own data and the SHA-256 recorded for it. Install writes the data
// to a temporary file beside the destination and checks that file, its hash and its Authenticode
// signature, before it takes the place of the destination by a rename: a payload that fails either
// check is never written to its destination and never started. The signature check is Windows
// only (verify_windows.go); on another OS it always refuses (verify_other.go), so Install never
// produces a file that nothing has verified.
//
// A file that cannot carry an Authenticode signature is an Unsigned Payload, which Install checks
// by its hash alone: the INF and the performance counter manifest of a driver package, and the
// NOTICE. Windows itself checks an INF against the signed catalog of its package when the package
// is published (SetupCopyOEMInf), and ranz.exe, which holds every Payload, is signed as a whole.
//
// A file whose own signature no machine trusts, but which the signed catalog of its package lists,
// is a Catalog Member, which Install checks as a member of that catalog, written to the same
// directory before it (the xdpapi.dll of the XDP runtime: its signature chains to a root that
// Windows does not trust for code, so the catalog of the package is how Windows trusts it).
//
// The directory that Install writes to must be one that only SYSTEM and the Administrators can
// write to. Otherwise another account could replace the temporary file between the check and the
// rename. Ensure, which writes a file for the program that runs it, has its own rule (ensure.go).
package payload

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Payload is one embedded file: its installed name, its bytes and the SHA-256 that New recorded
// for them.
type Payload struct {
	Name   string
	Data   []byte
	SHA256 [32]byte
	// Unsigned marks a file that carries no Authenticode signature of its own (NewUnsigned):
	// Install checks its hash and does not run the signature check.
	Unsigned bool
	// Catalog is the name of the Payload, written to the same directory before this one, whose
	// signed catalog lists this file (NewCatalogMember): Install checks the file as a member of
	// that catalog, after its hash, and does not run the signature check. "" for a file that is
	// not a member.
	Catalog string
}

// New returns the Payload name of the embedded bytes data, with its SHA-256 recorded. Install
// checks the Authenticode signature of the file it writes.
func New(name string, data []byte) Payload {
	return Payload{Name: name, Data: data, SHA256: sha256.Sum256(data)}
}

// NewUnsigned returns the Payload name of the embedded bytes data, a file that cannot carry an
// Authenticode signature, with its SHA-256 recorded. Install checks its hash only.
func NewUnsigned(name string, data []byte) Payload {
	p := New(name, data)
	p.Unsigned = true
	return p
}

// NewCatalogMember returns the Payload name of the embedded bytes data, a file that the signed
// catalog named catalog lists, with its SHA-256 recorded. Install checks it as a member of that
// catalog, which must be written to the same directory first.
func NewCatalogMember(name string, data []byte, catalog string) Payload {
	p := New(name, data)
	p.Catalog = catalog
	return p
}

// verify is the Authenticode check that Install runs on the file it is about to install:
// verifyAuthenticode of this OS. A test of this package substitutes it to exercise Install's
// other steps without a real signed file.
var verify = verifyAuthenticode

// verifyCatalog is the check that Install runs on a Catalog Member: verifyCatalogMember of this
// OS, which takes the path of the catalog and the path of the file. A test substitutes it, as it
// does verify.
var verifyCatalog = verifyCatalogMember

// hashFile is the SHA-256 of the file at path, which Install compares with the hash recorded for
// the payload. A test substitutes it to make a file that was written wrong.
var hashFile = fileSHA256

// Install writes p as dir/p.Name, after its hash and its Authenticode signature check (a Catalog
// Member's catalog check). Both checks run on a temporary file in dir: the hash of the file as it
// was written, and its signature. A payload whose data does not match its recorded hash, or whose
// file does not pass a check, is refused, the temporary file is removed, and the destination path
// is never touched. On success the temporary file becomes the destination path by a rename.
func Install(dir string, p Payload) error {
	if p.Name == "" || p.Name == "." || p.Name == ".." || filepath.Base(p.Name) != p.Name {
		return fmt.Errorf("payload: %q is not a plain file name", p.Name)
	}
	if p.Catalog != "" && (p.Catalog == "." || p.Catalog == ".." || filepath.Base(p.Catalog) != p.Catalog) {
		return fmt.Errorf("payload: %s: its catalog %q is not a plain file name", p.Name, p.Catalog)
	}
	if len(p.Data) == 0 {
		return fmt.Errorf("payload: %s carries no data (a build without the real payload embedded)", p.Name)
	}
	if sha256.Sum256(p.Data) != p.SHA256 {
		return fmt.Errorf("payload: %s: its data does not match the hash recorded for it", p.Name)
	}

	// The name of the file stays at the end of the temporary name: Windows reads a catalog by its
	// extension, so a .cat file that is checked under another extension never verifies
	tmp, err := os.CreateTemp(dir, ".tmp-*-"+p.Name)
	if err != nil {
		return fmt.Errorf("payload: %s: %w", p.Name, err)
	}
	tmpPath := tmp.Name()
	_, writeErr := tmp.Write(p.Data)
	if writeErr == nil {
		writeErr = tmp.Sync()
	}
	if closeErr := tmp.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("payload: %s: writing it: %w", p.Name, writeErr)
	}

	if err := check(dir, tmpPath, p); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("payload: %s: %w", p.Name, err)
	}

	dest := filepath.Join(dir, p.Name)
	if err := rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("payload: %s: %w", p.Name, err)
	}
	return nil
}

// check runs the two checks on the file at path, which Install wrote to dir: it must hold the
// bytes whose hash p records, as they came off the disk, and its Authenticode signature must
// verify. An Unsigned payload has the first check only, and a Catalog Member has, instead of the
// second, the check that the catalog written to dir lists it.
func check(dir, path string, p Payload) error {
	sum, err := hashFile(path)
	if err != nil {
		return fmt.Errorf("hashing the file it wrote: %w", err)
	}
	if sum != p.SHA256 {
		return errors.New("the file it wrote does not match the hash recorded for it")
	}
	if p.Unsigned {
		return nil
	}
	if p.Catalog != "" {
		return verifyCatalog(filepath.Join(dir, p.Catalog), path)
	}
	return verify(path)
}

// fileSHA256 returns the SHA-256 of the file at path.
func fileSHA256(path string) ([32]byte, error) {
	var sum [32]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// rename moves from to to, which replaces a file that is there. A scanner that holds the file it
// has just seen written makes the rename fail for a moment, so it tries for a few seconds.
func rename(from, to string) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}
