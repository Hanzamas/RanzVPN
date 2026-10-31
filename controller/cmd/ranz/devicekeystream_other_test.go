//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestDeviceCreateTakesAColonOffWindows: a colon is an ordinary character of a name off Windows, which makes no stream of a
// file, so ranz writes the files of -o and -qr-file under names that have one, and they hold the keys with the mode 0600. The
// refusal of a name with a colon (SDN-82-R2) is the one of Windows.
func TestDeviceCreateTakesAColonOffWindows(t *testing.T) {
	dir := t.TempDir()
	conf, png := filepath.Join(dir, "notes.txt:phone.conf"), filepath.Join(dir, "phone:1.png")
	cli, _ := deviceController(t, madePhone(t), 0)
	args := []string{"-network", "lab-net", "-gateway", "gw", "-o", conf, "-qr-file", png, "phone"}
	if err := createDevice(context.Background(), cli, args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(conf); err != nil || string(b) != deviceConfig {
		t.Errorf("the file %s holds %q (%v), want the configuration", conf, b, err)
	}
	for _, path := range []string{conf, png} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("the file %s has the mode %v, want 0600", path, fi.Mode())
		}
	}
}
