//go:build linux

package certgen

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// A write that fails is an error of WriteFile, which closes the file: /dev/full is a file that takes no byte. The file
// is no private one, so that WriteFile leaves the mode of the device alone.
func TestWriteFileReportsAFailedWrite(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("this host has no /dev/full")
	}
	if err := WriteFile("/dev/full", []byte("x"), false, true); !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("WriteFile to a file that takes no byte: %v, want that the device is full", err)
	}
}
