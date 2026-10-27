// Command ranz-explainplan writes the plans of the explain conformance (ADR-0031 decision 8; SDN-15, #191) that the
// vpntest harness runs: for each scenario of tests/explain it explains every test packet on the desired states that
// the intent of the scenario compiles to, and writes the plan of the scenario (controller/internal/explain,
// Scenario.Plan) into a directory, one file NAME.plan for each. `vpntest explain DIR` then runs the plans through the
// data plane of real Nodes (src/vpntest/explaintest.c). A scenario whose verdicts explain does not give gets no plan,
// and the tool fails. It is a test tool: CI builds it (.github/scripts/explain-conformance.ps1) and never ships it.
//
// Usage: ranz-explainplan -o DIR FILE|DIR...
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run writes the plans of the scenarios that args name and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz-explainplan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("o", "", "the directory that the plans go into")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: ranz-explainplan -o DIR FILE|DIR...")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" || flags.NArg() == 0 {
		flags.Usage()
		return 2
	}
	var files []string
	for _, a := range flags.Args() {
		st, err := os.Stat(a)
		if err != nil {
			fmt.Fprintln(stderr, "ranz-explainplan:", err)
			return 1
		}
		if !st.IsDir() {
			files = append(files, a)
			continue
		}
		found, err := explain.ScenarioFiles(a)
		if err != nil {
			fmt.Fprintln(stderr, "ranz-explainplan:", err)
			return 1
		}
		files = append(files, found...)
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "ranz-explainplan: no scenario file")
		return 1
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, "ranz-explainplan:", err)
		return 1
	}
	code := 0
	for _, f := range files {
		s, err := explain.LoadScenario(f)
		var plan []byte
		if err == nil {
			plan, err = s.Plan()
		}
		path := filepath.Join(*out, s.Name+".plan")
		if err == nil {
			err = os.WriteFile(path, plan, 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "ranz-explainplan: %s: %v\n", f, err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "%s: %d packets, the plan %s\n", s.Name, len(s.Packets), path)
	}
	return code
}
