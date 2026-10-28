package main

import "testing"

// --admin-from is the allowlist of the Controller (AUD1-DT-6, #454): ranz install refuses it
// without --controller, an empty or a wrong list, and any beside a prefix, before it reaches
// install.Install.
func TestRunInstallChecksAdminFrom(t *testing.T) {
	for _, args := range [][]string{
		{"--admin-from", "203.0.113.0/24"},
		{"--controller", "--admin-from", ","},
		{"--controller", "--admin-from", "nowhere"},
		{"--controller", "--admin-from", "10.0.0.1/8"},
		{"--controller", "--admin-from", "any,203.0.113.0/24"},
		{"--controller", "--admin-from", "203.0.113.0/24,203.0.113.0/24"},
	} {
		if code := runInstall(args); code != 2 {
			t.Errorf("ranz install %q: exit code %d, want 2", args, code)
		}
	}
}
