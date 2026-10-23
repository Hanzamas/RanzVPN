package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// build is the build number, the third part of the version. A plain go build leaves it 0, as the C
// build does without BUILD_NUMBER; CI sets it to the run number of the workflow:
//
//	go build -ldflags "-X main.build=<run number>" ./controller/cmd/ranz
var build = "0"

// versionLine is what `ranz version` prints: ranz and its one version, the major.minor of
// internal/version, which is the one of CMakeLists.txt, and the build number. Every subcommand is
// part of the same file, so none of them has a version of its own.
func versionLine() string {
	return "ranz " + version.Version + "." + build
}

func init() {
	for _, name := range []string{"version", "-version", "--version"} {
		register(name, func(args []string) int { return runVersion(args, os.Stdout, os.Stderr) })
	}
}

// runVersion is `ranz version`: it prints the version to stdout and returns the exit code, 2 for
// arguments, which the command does not take.
func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "ranz version: unexpected arguments: %q\n", args)
		return 2
	}
	fmt.Fprintln(stdout, versionLine())
	return 0
}
