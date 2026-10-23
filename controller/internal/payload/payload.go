// Package payload is the mechanism that writes a file embedded in ranz.exe out to disk (ADR-0011
// amendment of 2026-10-22, ONE-2 #311; the Payload entry of CONTEXT.md): ranz-node.exe today, and
// the Wintun driver, the SeLow package, the XDP runtime and the rqlite member of a Controller of
// ONE-3 and ONE-4 later. A Payload carries its own data and the SHA-256 recorded for it; Install
// checks that hash and the file's Authenticode signature before it ever reaches its destination
// path, so a payload that fails either check is never written and never started. The signature
// check is Windows only (verify_windows.go); on another OS it always refuses (verify_other.go), so
// Install never produces a file that nothing has verified.
package payload

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// Payload is one embedded file: its installed name, its bytes and the SHA-256 that New recorded
// for them.
type Payload struct {
	Name   string
	Data   []byte
	SHA256 [32]byte
}

// New returns the Payload name of the embedded bytes data, with its SHA-256 recorded.
func New(name string, data []byte) Payload {
	return Payload{Name: name, Data: data, SHA256: sha256.Sum256(data)}
}

// verify is the Authenticode check that Install runs on the file it is about to install:
// verifyAuthenticode of this OS. A test of this package substitutes it to exercise Install's hash
// check and its write without a real signed file.
var verify = verifyAuthenticode

// Install checks p's hash and its Authenticode signature, then writes it as dir/p.Name. Both
// checks run on a temporary file in dir before anything is written at the destination path: a
// payload whose data does not match its recorded hash, or whose signature does not verify, is
// refused, the temporary file is removed, and the destination path is never touched. On success
// the temporary file becomes the destination path by an atomic rename.
func Install(dir string, p Payload) error {
	if len(p.Data) == 0 {
		return fmt.Errorf("payload: %s carries no data (a build without the real payload embedded)", p.Name)
	}
	if sha256.Sum256(p.Data) != p.SHA256 {
		return fmt.Errorf("payload: %s: its data does not match the hash recorded for it", p.Name)
	}

	tmp, err := os.CreateTemp(dir, "."+p.Name+".tmp-*")
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

	if err := verify(tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("payload: %s: %w", p.Name, err)
	}

	dest := filepath.Join(dir, p.Name)
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("payload: %s: %w", p.Name, err)
	}
	return nil
}
