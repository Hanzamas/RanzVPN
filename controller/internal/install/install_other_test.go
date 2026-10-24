//go:build !windows

package install

import (
	"errors"
	"io"
	"testing"
)

func TestInstallIsRefusedOffWindows(t *testing.T) {
	for _, opts := range []Options{{}, {Controller: true}, {NoXDP: true}, {Controller: true, NoXDP: true, Notice: "licences"}} {
		if err := Install(io.Discard, opts); !errors.Is(err, errNotWindows) {
			t.Fatalf("Install(%+v) = %v, want %v", opts, err, errNotWindows)
		}
	}
}

func TestUninstallIsRefusedOffWindows(t *testing.T) {
	if err := Uninstall(io.Discard); !errors.Is(err, errNotWindows) {
		t.Fatalf("Uninstall() = %v, want %v", err, errNotWindows)
	}
}
