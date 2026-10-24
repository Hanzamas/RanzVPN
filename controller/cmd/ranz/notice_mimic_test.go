package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The NOTICE holds the licence text of each library that `ranz mimic` carries, word for word
// (CORE-P2-1, #85), as it holds that of GoBGP: the BSD licence of the Go authors that uTLS and the
// forked part of REALITY are under, the Mozilla Public License of REALITY, and the licence of
// juju/ratelimit, a dependency of REALITY, which section 4 of its LGPL asks to come with every
// program that uses it. Each text is compared with the file of the module that this build uses, so a
// library whose licence text changed fails here until the NOTICE follows it.
func TestNoticeHasTheLicencesOfTheMimicryLibraries(t *testing.T) {
	for _, c := range []struct{ module, file string }{
		{"github.com/refraction-networking/utls", "LICENSE"},
		{"github.com/xtls/reality", "LICENSE"},
		{"github.com/xtls/reality", "LICENSE-Go"},
		{"github.com/juju/ratelimit", "LICENSE"},
	} {
		t.Run(c.module+" "+c.file, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", c.module).Output()
			if err != nil {
				t.Fatalf("go list -m %s: %v", c.module, err)
			}
			dir := strings.TrimSpace(string(out))
			b, err := os.ReadFile(filepath.Join(dir, c.file))
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Fields(string(b))
			if len(want) == 0 {
				t.Fatalf("the %s of %s in %s holds no words", c.file, c.module, dir)
			}
			have := strings.Fields(notice)
			if !strings.Contains(strings.Join(have, " "), strings.Join(want, " ")) {
				t.Errorf("the NOTICE does not hold the %s of %s word for word: %s", c.file, c.module, firstDifference(have, want))
			}
		})
	}
}

// ranz mimic is a subcommand of ranz, which a Node starts as `ranz.exe mimic -pipe NAME`. The test
// does not run it: Main applies the process mitigations to the process that calls it, and the
// workflow runs the executable for its contract (ranz.yml, The executable).
func TestMimicIsASubcommand(t *testing.T) {
	if subcommands["mimic"] == nil {
		t.Fatal("ranz mimic is not a subcommand")
	}
}
