package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/forkimport"
)

// The subcommand import-config (SDN-27, #203; ADR-0031 decision 11), the one-time importer of the Config file of the fork:
//
//	ranz import-config [flags] FILE   read FILE, the Config file ranz_server.config of the old server (- for standard
//	                                  input), and write the intent document that its Virtual Hubs make: each is a VRF with
//	                                  one Network, its groups and users are Groups and Users whose names are tags of policy,
//	                                  and its access list is the Policies of its VRF (package forkimport)
//
// It reads the file and calls no controller, so it needs no token. The document goes to standard output, YAML unless -o json,
// for ranz apply -f to take, and what the import left out and what it carried in another way goes to standard error, one
// line each. Apply adds the resources to the intent and changes none of the others, where ranz import -f makes a document
// the whole intent and deletes what it leaves out, so the document is for apply. The old server runs on until every Virtual
// Hub has moved, so -hub takes the Virtual Hubs that it names, as often as there are: the names of the resources are the
// same whichever hubs are taken, and a hub named DEFAULT is not VRF default, so imports of one file never make a name
// twice and never replace a first install. -pool gives the Network of a Virtual Hub its IPv4 pool, which a Virtual Hub of
// the fork has none of, and -mode makes L2 Networks. The passwords of the users are not imported (a User has none until
// ranz user password sets one), and the report says what else is not.
func init() {
	register("import-config", func(args []string) int { return runImportConfig(args, os.Stdin, os.Stdout, os.Stderr) })
}

const importConfigUsage = `usage: ranz import-config [-hub NAME]... [-mode L3|L2] [-pool NAME=PREFIX]... [-o yaml|json] FILE
  FILE: the Config file of the old server, ranz_server.config, or - for standard input
  The intent document goes to standard output: apply it with ranz apply -f. What the import left out goes to standard error.
`

// listFlag is a flag that can be given more than once, each value an entry.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// runImportConfig runs ranz import-config with the arguments that follow its name, and returns the exit code: 0 for a
// document, 1 for a file or an option that the import refuses, 2 for arguments that the command does not take.
func runImportConfig(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz import-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var hubs, pools listFlag
	flags.Var(&hubs, "hub", "take the Virtual Hub with this name, without regard to case, as often as there are hubs to take; every Virtual Hub when it is left out")
	mode := flags.String("mode", "L3", "the mode of the Networks, L3 or L2")
	flags.Var(&pools, "pool", "the IPv4 pool of the Network of a Virtual Hub as NAME=PREFIX, such as LAB=10.0.0.0/24, once for each Virtual Hub")
	format := flags.String("o", "yaml", "the form of the intent document: yaml or json")
	flags.Usage = func() {
		fmt.Fprint(stderr, importConfigUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 1 || (*format != "yaml" && *format != "json") {
		flags.Usage()
		return 2
	}
	opts := forkimport.Options{Hubs: hubs, Mode: *mode}
	given := map[string]bool{}
	for _, p := range pools {
		name, prefix, ok := strings.Cut(p, "=")
		if !ok || name == "" || prefix == "" {
			fmt.Fprintf(stderr, "ranz import-config: -pool %q is not NAME=PREFIX\n", p)
			flags.Usage()
			return 2
		}
		if given[strings.ToLower(name)] {
			fmt.Fprintf(stderr, "ranz import-config: -pool gives Virtual Hub %q a pool twice\n", name)
			return 2
		}
		given[strings.ToLower(name)] = true
		if opts.Pools == nil {
			opts.Pools = map[string]string{}
		}
		opts.Pools[name] = prefix
	}

	b, err := readConfigFile(flags.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	root, err := forkimport.Parse(b)
	if err != nil {
		fmt.Fprintf(stderr, "ranz: %s: %v\n", flags.Arg(0), err)
		return 1
	}
	res, err := forkimport.Import(root, opts)
	if err != nil {
		fmt.Fprintf(stderr, "ranz: %s: %v\n", flags.Arg(0), err)
		return 1
	}
	fmt.Fprint(stderr, res.Report())
	if *format == "json" {
		err = show(stdout, res.Document)
	} else {
		var doc []byte
		if doc, err = res.Document.YAML(); err == nil {
			_, err = stdout.Write(doc)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	return 0
}

// readConfigFile reads the Config file name, or standard input for "-".
func readConfigFile(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}
