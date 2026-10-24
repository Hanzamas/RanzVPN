package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

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

// An uninstall that a network component kept from finishing in time exits 3010, as Windows
// Installer does when a restart finishes the job, also when the error comes wrapped and joined
// with others (#72, risk R2); any other failure exits 1.
func TestUninstallCodeReportsARequiredRestart(t *testing.T) {
	wrapped := fmt.Errorf("uninstall: %w", errors.Join(errors.New("removing the SeLow driver: a note"), fmt.Errorf("removing the XDP runtime: %w", install.ErrRebootRequired)))
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{install.ErrRebootRequired, 3010},
		{wrapped, 3010},
		{errors.New("uninstall: the service control manager"), 1},
	}
	for _, c := range cases {
		if got := uninstallCode(c.err); got != c.want {
			t.Errorf("uninstallCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
