package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// ranz install and ranz uninstall are the install and uninstall of the product (package install,
// ONE-2 #311); this file only parses -controller and reports the result the way every subcommand
// of ranz does.
func init() {
	register("install", runInstall)
	register("uninstall", runUninstall)
}

func runInstall(args []string) int {
	flags := flag.NewFlagSet("ranz install", flag.ContinueOnError)
	controller := flags.Bool("controller", false, "also register and start the Controller service")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ranz install: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if err := install.Install(*controller); err != nil {
		fmt.Fprintln(os.Stderr, "ranz install:", err)
		return 1
	}
	fmt.Println("ranz install: done")
	return 0
}

func runUninstall(args []string) int {
	flags := flag.NewFlagSet("ranz uninstall", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ranz uninstall: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if err := install.Uninstall(); err != nil {
		fmt.Fprintln(os.Stderr, "ranz uninstall:", err)
		return 1
	}
	fmt.Println("ranz uninstall: done")
	return 0
}
