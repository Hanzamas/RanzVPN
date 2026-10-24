//go:build windows && amd64

package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// Temporary (ONE-3, #312), removed with .github/workflows/diag-xdp-sign.yml: puts the SeLow driver and the XDP runtime on
// the runner as ranz install does, in the four situations that install.ps1 reads from outside, and says what each step did.
func diagState(m *mgr.Mgr, name string) string {
	s, err := m.OpenService(name)
	if err != nil {
		return "absent"
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return "unknown: " + err.Error()
	}
	return fmt.Sprintf("state %d", status.State)
}

func TestDiagInstallDrivers(t *testing.T) {
	if os.Getenv("DIAG_INSTALL") == "" {
		t.Skip("DIAG_INSTALL is not set")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	dir := filepath.Join(os.Getenv("ProgramFiles"), "Ranz VPN diag")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	phase := func(name string, f func(w io.Writer)) {
		var out bytes.Buffer
		f(&out)
		published, recorded := recordedDriver("xdp")
		t.Logf("---- %s\n%s---- SeLow %s, xdp %s, xdp recorded %q %v", name, out.String(), diagState(m, "SeLow"), diagState(m, "xdp"), published, recorded)
	}
	gone := func(what string) {
		for _, name := range []string{"SeLow", "xdp"} {
			if diagState(m, name) != "absent" {
				t.Errorf("%s: the service %s is %s", what, name, diagState(m, name))
			}
		}
	}

	phase("install both", func(w io.Writer) {
		if n := installDrivers(w, m, dir, Options{}); n != 2 {
			t.Errorf("installDrivers installed %d drivers, want 2", n)
		}
	})
	phase("install again", func(w io.Writer) {
		if n := installDrivers(w, m, dir, Options{}); n != 0 {
			t.Errorf("the second installDrivers installed %d drivers, want 0", n)
		}
	})
	phase("remove both", func(w io.Writer) {
		if err := removeDrivers(w, m, dir); err != nil {
			t.Errorf("removeDrivers: %v", err)
		}
	})
	gone("after the removal")

	// The XDP driver with one byte changed, as a ranz.exe of the install job carries it: its hash is the one of the file
	phase("a changed xdp.sys", func(w io.Writer) {
		bad := append([]payload.Payload(nil), payload.XdpPackage...)
		for i, p := range bad {
			if p.Name == "xdp.sys" {
				data := append([]byte(nil), p.Data...)
				data[len(data)/2] ^= 0xFF
				bad[i] = payload.New("xdp.sys", data)
			}
		}
		d := xdpDriver
		d.files = bad
		done, err := installDriver(w, m, dir, d)
		if err == nil || done {
			t.Errorf("installDriver with a changed xdp.sys = %v, %v, want an error", done, err)
		}
		fmt.Fprintf(w, "installDriver: %v\n", err)
		if _, statErr := os.Stat(filepath.Join(dir, driversFolder, "xdp")); statErr == nil {
			t.Errorf("a refused XDP runtime left its folder")
		}
	})
	gone("after a changed xdp.sys")

	phase("no XDP", func(w io.Writer) {
		if n := installDrivers(w, m, dir, Options{NoXDP: true}); n != 1 {
			t.Errorf("installDrivers with NoXDP installed %d drivers, want 1", n)
		}
	})
	phase("remove SeLow", func(w io.Writer) {
		if err := removeDrivers(w, m, dir); err != nil {
			t.Errorf("removeDrivers: %v", err)
		}
	})
	gone("after the removal of SeLow")

	// A SeLow that was there before: installed by hand, from the package of the repository
	phase("SeLow by hand, then install", func(w io.Writer) {
		pkg, err := filepath.Abs(filepath.Join("..", "payload", "selow"))
		if err != nil {
			t.Fatal(err)
		}
		out, err := runTool("netcfg.exe", "-v", "-l", filepath.Join(pkg, "SeLow_x64.inf"), "-c", "p", "-i", "SeLow")
		fmt.Fprintf(w, "netcfg by hand: %v\n%s\n", err, out)
		if n := installDrivers(w, m, dir, Options{}); n != 1 {
			t.Errorf("installDrivers beside a SeLow that was there installed %d drivers, want 1", n)
		}
	})
	phase("remove, SeLow stays", func(w io.Writer) {
		if err := removeDrivers(w, m, dir); err != nil {
			t.Errorf("removeDrivers: %v", err)
		}
		if diagState(m, "SeLow") == "absent" {
			t.Errorf("removeDrivers took out the SeLow that was there before")
		}
		if diagState(m, "xdp") != "absent" {
			t.Errorf("removeDrivers left the XDP runtime")
		}
		out, err := runTool("netcfg.exe", "-u", "SeLow")
		fmt.Fprintf(w, "netcfg -u SeLow: %v\n%s\n", err, out)
	})
}
