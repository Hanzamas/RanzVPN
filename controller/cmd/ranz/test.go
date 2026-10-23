package main

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
)

// `ranz test` runs a test of the network that the nodes make (SDN-53, #246): `ranz test
// throughput` measures the rate between two nodes, as the traffic test of vpncmd did. Each test is
// a file of its own that registers itself from its init function, as the files of the subcommands
// do (subcommand.go), so a new test is a new file and never an edit of this one.

// tests are the tests of `ranz test` by name. Each one gets the arguments that follow its name
// and returns the exit code of the process.
var tests = map[string]func(args []string) int{}

// registerTest adds the test name. It panics when the name is taken, which only a mistake in the
// code can cause.
func registerTest(name string, run func(args []string) int) {
	if _, taken := tests[name]; taken {
		panic("ranz: the test " + name + " is registered twice")
	}
	tests[name] = run
}

func init() {
	register("test", func(args []string) int { return runTest(args, os.Stderr) })
}

// runTest is `ranz test NAME [arguments]`: it runs the test that NAME names, and returns its exit
// code. A name that no test has, and no name, are answered with the usage and the exit code 2.
func runTest(args []string, stderr io.Writer) int {
	if len(args) > 0 {
		if run, ok := tests[args[0]]; ok {
			return run(args[1:])
		}
	}
	fmt.Fprintf(stderr, "usage: ranz test %s [arguments]\n", strings.Join(slices.Sorted(maps.Keys(tests)), "|"))
	return 2
}
