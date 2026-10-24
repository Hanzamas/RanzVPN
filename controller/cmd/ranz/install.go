package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// ranz install and ranz uninstall are the install and uninstall of the product (package install,
// ONE-2 #311, ONE-3 #312); this file only parses -controller and -no-xdp, passes the NOTICE that
// install writes beside the Wintun DLL and the standard output for the steps they report, and
// reports the result the way every subcommand of ranz does. The flags are spelled -controller or
// --controller, -no-xdp or --no-xdp.
func init() {
	register("install", runInstall)
	register("uninstall", runUninstall)
}

func runInstall(args []string) int {
	flags := flag.NewFlagSet("ranz install", flag.ContinueOnError)
	controller := flags.Bool("controller", false, "also register and start the Controller service")
	noXDP := flags.Bool("no-xdp", false, "leave the XDP runtime out, on a server that does not want it: the Node falls back to SeLow")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ranz install: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	opts := install.Options{Controller: *controller, NoXDP: *noXDP, Notice: notice}
	if err := install.Install(os.Stdout, opts); err != nil {
		fmt.Fprintln(os.Stderr, "ranz install:", err)
		return 1
	}
	fmt.Println("ranz install: done")
	return 0
}

func runUninstall(args []string) int {
	flags := flag.NewFlagSet("ranz uninstall", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ranz uninstall: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if err := install.Uninstall(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ranz uninstall:", err)
		return 1
	}
	fmt.Println("ranz uninstall: done")
	return 0
}
