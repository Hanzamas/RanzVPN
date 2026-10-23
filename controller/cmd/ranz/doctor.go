package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hanzamas/RanzVPN/controller/internal/doctor"
)

// ranz doctor is the system check, the successor of the Check command of vpncmd (SDN-53, #246):
// it runs the six checks that the command ran, the kernel, memory, strings, the file system,
// threads and the network, and prints a line for each and the verdict. It exits with 0 when every
// check passed and with 1 when one failed.
func init() {
	register("doctor", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runDoctor(ctx, args, os.Stdout, os.Stderr)
	})
}

// runDoctor is `ranz doctor`. It returns the exit code of the process: 0 when every check passed,
// 1 when one failed, and 2 for arguments, which the command does not take.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: ranz doctor")
		fmt.Fprintln(stderr, "runs the checks of the vpncmd command Check on this system: the kernel, memory, strings, the file system, threads and the network")
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
	if !doctor.Run(ctx, stdout, doctor.Checks()) {
		return 1
	}
	return 0
}
