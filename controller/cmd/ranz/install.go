package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// ranz install and ranz uninstall are the install and uninstall of the product (package install,
// ONE-2 #311, ONE-3 #312); this file only parses -controller, -no-xdp and -keep-ranz, passes the
// NOTICE that install writes beside the Wintun DLL and the standard output for the steps they
// report, and reports the result the way every subcommand of ranz does. The flags are spelled
// -controller or --controller, -no-xdp or --no-xdp, -keep-ranz or --keep-ranz. The thin MSI runs
// ranz install and ranz uninstall -keep-ranz (ONE-5 #314).
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
	keepRanz := flags.Bool("keep-ranz", false, "leave ranz.exe and the Ranz folder for the caller to remove, as the MSI does")
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
	err := install.Uninstall(os.Stdout, install.UninstallOptions{KeepRanz: *keepRanz})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ranz uninstall:", err)
	} else {
		fmt.Println("ranz uninstall: done")
	}
	return uninstallCode(err)
}

// rebootRequired is the exit code of an uninstall that a restart of Windows finishes, as Windows
// Installer reports one (ERROR_SUCCESS_REBOOT_REQUIRED).
const rebootRequired = 3010

// uninstallCode is the exit code of ranz uninstall for the error of install.Uninstall: 0 for none,
// rebootRequired when a network component did not unbind in time (#72, risk R2), 1 otherwise.
func uninstallCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, install.ErrRebootRequired):
		return rebootRequired
	default:
		return 1
	}
}
