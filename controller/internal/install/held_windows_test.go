//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A file that another handle holds is waited for until that handle closes, and no longer.
func TestWaitUnheldWaitsForTheHandleToClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranz.exe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	const hold = 500 * time.Millisecond
	go func() {
		time.Sleep(hold)
		f.Close()
	}()

	var out strings.Builder
	start := time.Now()
	waitUnheld(&out, path, 10*time.Second)
	if took := time.Since(start); took < hold || took > 5*time.Second {
		t.Errorf("waitUnheld returned after %s, want after the handle closed at %s", took, hold)
	}
	if out.Len() != 0 {
		t.Errorf("waitUnheld reported %q for a file that was released", out.String())
	}
}

// A file that stays held is reported once the time is up, and a file that is not there is free.
func TestWaitUnheldGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranz.exe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	var out strings.Builder
	waitUnheld(&out, path, 300*time.Millisecond)
	if !strings.Contains(out.String(), "still held by another process") {
		t.Errorf("waitUnheld reported %q for a file that stayed held", out.String())
	}

	out.Reset()
	start := time.Now()
	waitUnheld(&out, filepath.Join(t.TempDir(), "missing.exe"), 10*time.Second)
	if took := time.Since(start); took > time.Second || out.Len() != 0 {
		t.Errorf("waitUnheld of a missing file took %s and reported %q", took, out.String())
	}
}

// The image of a program that runs holds no handle to its file: ranz uninstall -keep-ranz, run from the
// ranz.exe of the Ranz folder, does not wait for itself. The running program here is the test binary,
// which go test has just written: another process of the runner, a scanner of new programs for one, may
// still hold it for a moment, and waitUnheld waits for that as it should. So a first wait lets such a
// handle go, and a program that held its own image would make it run out of time and report; the second
// wait, while the program still runs from the file, must not wait at all.
func TestWaitUnheldDoesNotWaitForTheRunningProgram(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	var out strings.Builder
	waitUnheld(&out, self, 10*time.Second)
	if out.Len() != 0 {
		t.Fatalf("waitUnheld of the running program reported %q", out.String())
	}
	start := time.Now()
	waitUnheld(&out, self, 10*time.Second)
	if took := time.Since(start); took > time.Second || out.Len() != 0 {
		t.Errorf("waitUnheld of the running program took %s and reported %q", took, out.String())
	}
}
