//go:build !windows

package install

import (
	"errors"
	"io"
	"testing"
)

func TestInstallIsRefusedOffWindows(t *testing.T) {
	if err := Install(io.Discard, false); !errors.Is(err, errNotWindows) {
		t.Fatalf("Install(false) = %v, want %v", err, errNotWindows)
	}
	if err := Install(io.Discard, true); !errors.Is(err, errNotWindows) {
		t.Fatalf("Install(true) = %v, want %v", err, errNotWindows)
	}
}

func TestUninstallIsRefusedOffWindows(t *testing.T) {
	if err := Uninstall(io.Discard); !errors.Is(err, errNotWindows) {
		t.Fatalf("Uninstall() = %v, want %v", err, errNotWindows)
	}
}
