//go:build !windows

package install

import (
	"bytes"
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

// The traffic test opens no port off Windows, and says nothing of a firewall
func TestAllowTestPortDoesNothingOffWindows(t *testing.T) {
	var out bytes.Buffer
	AllowTestPort(&out, 9821)()
	if out.Len() != 0 {
		t.Errorf("AllowTestPort printed %q", out.String())
	}
}

func TestUninstallIsRefusedOffWindows(t *testing.T) {
	for _, opts := range []UninstallOptions{{}, {KeepRanz: true}} {
		if err := Uninstall(io.Discard, opts); !errors.Is(err, errNotWindows) {
			t.Fatalf("Uninstall(%+v) = %v, want %v", opts, err, errNotWindows)
		}
	}
}
