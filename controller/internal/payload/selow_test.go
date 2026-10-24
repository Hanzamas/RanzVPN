package payload

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hamcoreSeLow is the SeLow driver package of the C build (src/bin/hamcore), seen from this
// directory.
const hamcoreSeLow = "../../../src/bin/hamcore/DriverPackages/SeLow_Win10/x64"

// The SeLow package that ranz carries is the one of hamcore (ONE-3, #312): go:embed reaches files
// below its own package only, so selow/ holds a copy of the three files, and this test fails when
// one side changes without the other.
func TestSeLowCopyIsTheHamcorePackage(t *testing.T) {
	original, err := os.ReadDir(hamcoreSeLow)
	if err != nil {
		t.Fatalf("reading the package in hamcore: %v", err)
	}
	copied, err := os.ReadDir("selow")
	if err != nil {
		t.Fatalf("reading selow/: %v", err)
	}
	if len(original) != len(copied) {
		t.Errorf("hamcore holds %d files of the package and selow/ %d", len(original), len(copied))
	}
	for _, e := range original {
		want, err := os.ReadFile(filepath.Join(hamcoreSeLow, e.Name()))
		if err != nil {
			t.Fatalf("reading %s of hamcore: %v", e.Name(), err)
		}
		got, err := os.ReadFile(filepath.Join("selow", e.Name()))
		if err != nil {
			t.Fatalf("reading %s of selow/: %v", e.Name(), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("selow/%s differs from the file of hamcore (%d bytes, not %d)", e.Name(), len(got), len(want))
		}
	}
}

// The INF names the driver and the catalog that the package holds, so Windows finds them next to it
// when it publishes the package.
func TestSeLowINFNamesTheFilesOfThePackage(t *testing.T) {
	inf, err := os.ReadFile(filepath.Join("selow", "SeLow_x64.inf"))
	if err != nil {
		t.Fatalf("reading the INF: %v", err)
	}
	for _, name := range []string{"SeLow_x64.sys", "SeLow_Win10_x64.cat"} {
		if !strings.Contains(string(inf), name) {
			t.Errorf("the INF of the package does not name %s", name)
		}
		if _, err := os.Stat(filepath.Join("selow", name)); err != nil {
			t.Errorf("the package has no %s: %v", name, err)
		}
	}
}

func TestWintunDllName(t *testing.T) {
	if WintunDll.Name != "wintun.dll" {
		t.Errorf("the Wintun payload is named %q, not wintun.dll", WintunDll.Name)
	}
	if WintunDll.Unsigned {
		t.Error("the Wintun payload is unsigned: WireGuard LLC signs the DLL and Install must check it")
	}
}
