//go:build !windows

package main

import "testing"

// Off Windows ranz install refuses after it parsed its flags, with exit code 1: a flag that the
// command does not know is exit code 2. So this shows that -controller and -no-xdp, with one dash
// or two, are flags of ranz install, without installing anything (on Windows the install job of
// windows.yml runs the real command).
func TestRunInstallParsesItsFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"-controller"}, {"--controller"}, {"-no-xdp"}, {"--no-xdp"}, {"-no-xdp", "--controller"}} {
		if code := runInstall(args); code != 1 {
			t.Errorf("ranz install %q: exit code %d, want 1 (the refusal off Windows after the flags parsed)", args, code)
		}
	}
}
