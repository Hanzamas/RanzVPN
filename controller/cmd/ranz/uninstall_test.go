package main

import (
	"runtime"
	"testing"
)

// ranz uninstall -keep-ranz is what the thin MSI runs (ONE-5 #314): the flag is spelled with one
// dash or two, and the command takes no positional argument with it either. These refuse before they
// reach install.Uninstall; what the flag does is tested by removeDir of package install and by the
// msi job of windows.yml.
func TestRunUninstallTakesKeepRanzAndNoArguments(t *testing.T) {
	for _, args := range [][]string{{"-keep-ranz", "extra"}, {"--keep-ranz", "extra"}, {"extra", "-keep-ranz"}} {
		if code := runUninstall(args); code != 2 {
			t.Errorf("ranz uninstall %q: exit code %d, want 2", args, code)
		}
	}
}

// Off Windows ranz uninstall reaches install.Uninstall at once, which refuses; so the flag is taken
// when the command exits with 1, the failure of the uninstall, and not with 2, the refusal of its
// arguments. On Windows the same call would remove the product of the machine, so it is not made.
func TestRunUninstallAcceptsKeepRanz(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ranz uninstall on Windows removes the product of the machine")
	}
	for _, args := range [][]string{{"-keep-ranz"}, {"--keep-ranz"}, {}} {
		if code := runUninstall(args); code != 1 {
			t.Errorf("ranz uninstall %q: exit code %d, want 1 (install.Uninstall refuses off Windows)", args, code)
		}
	}
}
