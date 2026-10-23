package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// Every subcommand of the one executable (ONE-1, #310) is registered under the name that the Node,
// the Windows service and the operator type.
func TestSubcommandsAreRegistered(t *testing.T) {
	for _, name := range []string{"controller", "bgp", "notice", "version", "-version", "--version"} {
		if subcommands[name] == nil {
			t.Errorf("ranz has no subcommand %q", name)
		}
	}
}

// A name that a subcommand holds cannot be registered a second time.
func TestRegisterRefusesATakenName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("register took the name of a subcommand twice")
		}
	}()
	register("version", func([]string) int { return 0 })
}

// `ranz version` prints one line, ranz and its one version: the major.minor of internal/version
// and a build number. No subcommand has a version of its own.
func TestVersionIsOneLine(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runVersion(nil, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("ranz version: exit code %d, stderr %q", code, errOut.String())
	}
	line := out.String()
	if !regexp.MustCompile(`^ranz [0-9]+\.[0-9]+\.[0-9]+\n$`).MatchString(line) {
		t.Errorf("ranz version printed %q, want ranz and major.minor.build on one line", line)
	}
	if prefix := "ranz " + version.Version + "."; !strings.HasPrefix(line, prefix) {
		t.Errorf("ranz version printed %q, which does not start with %q, the version of internal/version", line, prefix)
	}
	if want := versionLine() + "\n"; line != want {
		t.Errorf("ranz version printed %q, want %q", line, want)
	}
}

// `ranz version` takes no arguments: it answers them with a message and the exit code 2.
func TestVersionTakesNoArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runVersion([]string{"extra"}, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
		t.Errorf("ranz version extra: exit code %d, stdout %q, stderr %q, want 2, nothing and a message", code, out.String(), errOut.String())
	}
}
