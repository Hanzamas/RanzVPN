package main

import "testing"

// ranz install and ranz uninstall take no positional arguments; ranz install also takes
// -controller. Both run install.Install/install.Uninstall, which refuse with a non-zero exit code
// on every OS this module builds for (on Windows that exercises the real thing; see the install CI
// job of windows.yml, ONE-2 #311, for a run that can actually install the services).
func TestRunInstallTakesNoPositionalArguments(t *testing.T) {
	if code := runInstall([]string{"extra"}); code != 2 {
		t.Errorf("ranz install extra: exit code %d, want 2", code)
	}
}

func TestRunInstallRejectsAnUnknownFlag(t *testing.T) {
	if code := runInstall([]string{"-nope"}); code != 2 {
		t.Errorf("ranz install -nope: exit code %d, want 2", code)
	}
}

func TestRunUninstallTakesNoArguments(t *testing.T) {
	if code := runUninstall([]string{"extra"}); code != 2 {
		t.Errorf("ranz uninstall extra: exit code %d, want 2", code)
	}
}
