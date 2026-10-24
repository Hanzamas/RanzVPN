package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/doctor"
)

// ranz doctor is the system check, the successor of the Check command of vpncmd (SDN-53, #246):
// it runs the six checks that the command ran, the kernel, memory, strings, the file system,
// threads and the network, and prints a line for each and the verdict. It exits with 0 when every
// check passed and with 1 when one failed. With -bundle it also writes the diagnostics bundle of
// the host (doctorbundle.go, SDN-54, #247): the logs, the configuration and the status of the Node
// and of the Controller that run there, with no secret in them.
func init() {
	register("doctor", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runDoctor(ctx, args, os.Stdout, os.Stderr)
	})
}

// runDoctor is `ranz doctor`. It returns the exit code of the process: 0 when every check passed,
// 1 when one failed or when the bundle could not be written, and 2 for arguments, which the
// command does not take beyond its flags.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	makeBundle := flags.Bool("bundle", false, "also write the diagnostics bundle of this host: its logs, configuration and status in one ZIP archive, with no secret in it")
	file := flags.String("o", "", "with -bundle, the file to write, which must not exist; ranz-host-NAME-TIME.zip in the current directory when left out")
	nodeDir := flags.String("node-dir", defaultNodeDir(), "with -bundle, the data directory of the Node, whose log and configuration the bundle holds")
	controllerDir := flags.String("controller-dir", controllercmd.DefaultDataDir(), "with -bundle, the data directory of the Controller, whose service log the bundle holds")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: ranz doctor [-bundle [-o FILE]]")
		fmt.Fprintln(stderr, "runs the checks of the vpncmd command Check on this system: the kernel, memory, strings, the file system, threads and the network")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ranz doctor: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if *file != "" && !*makeBundle {
		fmt.Fprintln(stderr, "ranz doctor: -o names the file of a bundle, and needs -bundle")
		return 2
	}

	// A bundle is never written over a file: that is known before the checks run
	path := *file
	if *makeBundle {
		if path == "" {
			path = defaultBundleFile(time.Now())
		}
		if _, err := os.Lstat(path); err == nil {
			fmt.Fprintf(stderr, "ranz doctor: %s exists already, and a bundle is never written over a file\n", path)
			return 1
		}
	}

	// The report of the checks goes to the screen and, for a bundle, into it
	var report bytes.Buffer
	out := stdout
	if *makeBundle {
		out = io.MultiWriter(stdout, &report)
	}
	code := 0
	if !doctor.Run(ctx, out, doctor.Checks()) {
		code = 1
	}
	if !*makeBundle {
		return code
	}
	m, err := writeBundle(ctx, path, hostSources(report.String(), *nodeDir, *controllerDir))
	if err != nil {
		fmt.Fprintf(stderr, "ranz doctor: the diagnostics bundle: %v\n", err)
		return 1
	}
	reportBundle(stdout, path, m)
	return code
}
