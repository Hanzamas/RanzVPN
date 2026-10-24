//go:build windows && amd64

package payload

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// packageNames checks that pkg holds exactly the files in want, each marked unsigned as want says,
// and returns the payload of each file by name.
func packageNames(t *testing.T, pkg []Payload, want map[string]bool) map[string]Payload {
	t.Helper()
	if len(pkg) != len(want) {
		t.Errorf("the package holds %d files, want %d", len(pkg), len(want))
	}
	byName := make(map[string]Payload, len(pkg))
	for _, p := range pkg {
		unsigned, ok := want[p.Name]
		if !ok {
			t.Errorf("the package holds %s, which it should not", p.Name)
			continue
		}
		if p.Unsigned != unsigned {
			t.Errorf("%s: unsigned is %v, want %v", p.Name, p.Unsigned, unsigned)
		}
		byName[p.Name] = p
	}
	return byName
}

// The SeLow package of ranz for x64: the driver and its catalog are checked by their signature, the
// INF by its hash, and each file is the copy that selow/ holds.
func TestSeLowPackageHoldsTheCopiedFiles(t *testing.T) {
	byName := packageNames(t, SeLowPackage, map[string]bool{
		"SeLow_x64.sys":       false,
		"SeLow_Win10_x64.cat": false,
		"SeLow_x64.inf":       true,
	})
	for name, p := range byName {
		file, err := os.ReadFile(filepath.Join("selow", name))
		if err != nil {
			t.Fatalf("reading selow/%s: %v", name, err)
		}
		if !bytes.Equal(file, p.Data) {
			t.Errorf("%s of the package is not the file of selow/", name)
		}
	}
}

// The XDP runtime of ranz for x64 holds the files of runtime/native that the INF installs and the
// manifest of its performance counters. The committed files are empty placeholders, so only the
// names and the way each is checked are tested here: the driver and its catalog by their
// signature, the INF and the manifest by their hash, and xdpapi.dll as a member of the catalog,
// which therefore comes first.
func TestXdpPackageHoldsTheFilesOfTheRuntime(t *testing.T) {
	byName := packageNames(t, XdpPackage, map[string]bool{
		"xdp.sys":    false,
		"xdpapi.dll": false,
		"xdp.cat":    false,
		"xdp.inf":    true,
		"xdppcw.man": true,
	})
	if got := byName["xdpapi.dll"].Catalog; got != "xdp.cat" {
		t.Errorf("xdpapi.dll is checked as a member of the catalog %q, want xdp.cat", got)
	}
	for name, p := range byName {
		if name != "xdpapi.dll" && p.Catalog != "" {
			t.Errorf("%s is checked as a member of the catalog %q: only xdpapi.dll is", name, p.Catalog)
		}
	}
	catalogAt, memberAt := -1, -1
	for i, p := range XdpPackage {
		switch p.Name {
		case "xdp.cat":
			catalogAt = i
		case "xdpapi.dll":
			memberAt = i
		}
	}
	if catalogAt < 0 || memberAt < 0 || catalogAt > memberAt {
		t.Errorf("xdp.cat must be written before xdpapi.dll: it is file %d of the package and xdpapi.dll is file %d", catalogAt, memberAt)
	}
}
