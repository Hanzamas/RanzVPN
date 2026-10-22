// Command ranz-bgp is the BGP sidecar of a Ranz node (ADR-0010, ADR-0022, CORE-S7-1 #82): GoBGP
// as a library, peering with the operator's own routers on TCP 179. The node starts it with the
// name of a named pipe that the node created, and talks to it there with the JSON messages of
// internal/sidecar: the node sends the BGP settings and the prefixes to announce and withdraw,
// and ranz-bgp sends the session states and the routes it learns, which the node installs into
// Windows through IP Helper. ranz-bgp installs no route itself. It runs until the node closes
// the pipe.
//
// Usage:
//
//	ranz-bgp -pipe \\.\pipe\NAME [-log FILE] [-log-level LEVEL]
//	ranz-bgp -version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/sidecar"
)

// dialTimeout bounds the connection to the pipe of the node, which exists before the node starts
// ranz-bgp.
const dialTimeout = 10 * time.Second

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run is ranz-bgp with the arguments args; it returns the exit code: 0 when the node closed the
// pipe, 1 when the session failed, 2 for bad arguments.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz-bgp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pipe := flags.String("pipe", "", `the named pipe of the node, for example \\.\pipe\ranz-bgp-1234`)
	logFile := flags.String("log", "", "append the log to this file instead of standard error")
	logLevel := flags.String("log-level", "info", "the level of the log: debug, info, warn or error")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ranz-bgp: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, sidecar.Version())
		return 0
	}
	if *pipe == "" {
		fmt.Fprintln(stderr, "ranz-bgp: -pipe is required: ranz-bgp is started by the node")
		return 2
	}
	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(stderr, "ranz-bgp: -log-level %q: %v\n", *logLevel, err)
		return 2
	}

	out := stderr
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "ranz-bgp: %v\n", err)
			return 1
		}
		defer f.Close()
		out = f
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: &level}))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := dialNode(dctx, *pipe)
	cancel()
	if err != nil {
		log.Error("cannot connect to the node", "pipe", *pipe, "err", err)
		return 1
	}
	log.Info("connected to the node", "pipe", *pipe, "version", sidecar.Version(), "pid", os.Getpid())

	if err := sidecar.Run(ctx, conn, sidecar.Options{Logger: log, LogLevel: &level}); err != nil {
		log.Error("session failed", "err", err)
		return 1
	}
	log.Info("the node closed the pipe: BGP stopped")
	return 0
}
