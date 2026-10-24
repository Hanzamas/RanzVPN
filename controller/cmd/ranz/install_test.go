package main

import "testing"

// ranz install and ranz uninstall take no positional arguments; ranz install also takes
// -controller and -no-xdp, spelled with one dash or two. Each of these refuses its arguments before
// it reaches install.Install or install.Uninstall; what those do is tested by the install job of
// windows.yml (ONE-2 #311, ONE-3 #312), which runs them on Windows with a signed ranz.exe.
func TestRunInstallTakesNoPositionalArguments(t *testing.T) {
	if code := runInstall([]string{"extra"}); code != 2 {
		t.Errorf("ranz install extra: exit code %d, want 2", code)
	}
	if code := runInstall([]string{"--controller", "extra"}); code != 2 {
		t.Errorf("ranz install --controller extra: exit code %d, want 2", code)
	}
	for _, args := range [][]string{{"--no-xdp", "extra"}, {"-no-xdp", "--controller", "extra"}} {
		if code := runInstall(args); code != 2 {
			t.Errorf("ranz install %q: exit code %d, want 2", args, code)
		}
	}
}

func TestRunInstallRejectsAnUnknownFlag(t *testing.T) {
	if code := runInstall([]string{"-nope"}); code != 2 {
		t.Errorf("ranz install -nope: exit code %d, want 2", code)
	}
}

func TestRunInstallHelpIsNoFailure(t *testing.T) {
	if code := runInstall([]string{"-h"}); code != 0 {
		t.Errorf("ranz install -h: exit code %d, want 0", code)
	}
	if code := runUninstall([]string{"-h"}); code != 0 {
		t.Errorf("ranz uninstall -h: exit code %d, want 0", code)
	}
}

func TestRunUninstallTakesNoArguments(t *testing.T) {
	if code := runUninstall([]string{"extra"}); code != 2 {
		t.Errorf("ranz uninstall extra: exit code %d, want 2", code)
	}
	if code := runUninstall([]string{"-controller"}); code != 2 {
		t.Errorf("ranz uninstall -controller: exit code %d, want 2", code)
	}
}
