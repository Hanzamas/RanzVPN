//go:build windows

package payload

import (
	"os"
	"path/filepath"
	"testing"
)

// Temporary (ONE-3, #312), removed with .github/workflows/diag-xdp-sign.yml: the verdict of the catalog check on the
// files of the pinned XDP runtime, and on a copy of each with one byte changed.
func TestDiagVerifyEachFile(t *testing.T) {
	dir := os.Getenv("DIAG_DIR")
	if dir == "" {
		t.Skip("DIAG_DIR names no folder")
	}
	// The SeLow package of the repository, a driver package of the same kind
	selow, err := filepath.Abs("selow")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SeLow_x64.sys", "SeLow_x64.inf", "SeLow_Win10_x64.cat"} {
		for _, alg := range []string{"SHA256", "SHA1"} {
			code, err := catalogVerdict(filepath.Join(selow, "SeLow_Win10_x64.cat"), filepath.Join(selow, name), alg)
			t.Logf("%s: member of SeLow_Win10_x64.cat, hashed with %s: %#08x, %v", name, alg, code, err)
		}
	}
	catalog := filepath.Join(dir, "xdp.cat")
	changedDir := t.TempDir()
	for _, name := range []string{"xdp.sys", "xdpapi.dll", "xdp.cat", "xdp.inf", "xdppcw.man"} {
		path := filepath.Join(dir, name)
		for _, alg := range []string{"SHA256", "SHA1"} {
			code, err := catalogVerdict(catalog, path, alg)
			t.Logf("%s: member of xdp.cat, hashed with %s: %#08x, %v", name, alg, code, err)
		}
		t.Logf("%s: verifyCatalogMember: %v", name, verifyCatalogMember(catalog, path))

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)/2] ^= 0xFF
		changed := filepath.Join(changedDir, name)
		if err := os.WriteFile(changed, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s, one byte changed: verifyCatalogMember: %v", name, verifyCatalogMember(catalog, changed))
	}
}
