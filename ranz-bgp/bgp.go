// Package bgpcmd is `ranz bgp`, the BGP sidecar of a Ranz node (ADR-0010, ADR-0022, CORE-S7-1
// #82): GoBGP as a library, peering with the operator's own routers on TCP 179. The node starts
// it with the name of a named pipe that the node created, and talks to it there with the JSON
// messages of internal/sidecar: the node sends the BGP settings and the prefixes to announce and
// withdraw, and the sidecar sends the session states and the routes it learns, which the node
// installs into Windows through IP Helper. The sidecar installs no route itself. It runs until
// the node closes the pipe. Since ONE-1 (#310) it is a subcommand of the one executable ranz
// (controller/cmd/ranz), which the node finds next to its own executable: Main runs it.
//
// Usage:
//
//	ranz bgp -pipe \\.\pipe\NAME [-log FILE] [-log-days N] [-log-mb N] [-log-level LEVEL]
//
// The log file is kept within an age limit and a disk limit that the node gives it with -log-days
// and -log-mb, as it keeps its own log (SDN-54, #247): see OpenLog.
package bgpcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/mitigation"
	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/sidecar"
)

// dialTimeout bounds the connection to the pipe of the node, which exists before the node starts
// the sidecar.
const dialTimeout = 10 * time.Second

// The limits of the log file without -log-days and -log-mb: those of the node log (NODE_LOG_DEFAULT_DAYS
// and NODE_LOG_DEFAULT_MB of src/Cedar/Node.h).
const (
	defaultLogDays = 30
	defaultLogMB   = 256
)

// OpenLog opens the file of the -log flag to append to it, within an age limit of days days and a disk
// limit of megabytes megabytes, 0 for none. This one ignores the limits and appends to the file. The
// ranz executable (controller/cmd/ranz) replaces it with one that keeps the files of the log within them
// (internal/logfile), which this package cannot import: it is not under controller/.
var OpenLog = func(path string, days, megabytes int) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

// mitigations and mitigationErr are what mitigation.Apply did in Main, which run logs; nil when a
// test calls run itself.
var (
	mitigations   []mitigation.Result
	mitigationErr error
)

// Main is `ranz bgp` with the arguments after the subcommand. It returns the exit code of the
// process (see run).
func Main(args []string) int {
	// The process mitigations of ADR-0039 before the sidecar starts anything
	mitigations, mitigationErr = mitigation.Apply()
	return run(context.Background(), args, os.Stderr)
}

// run is `ranz bgp` with the arguments args; it returns the exit code: 0 when the node closed the
// pipe, 1 when the session failed, 2 for bad arguments.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz bgp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pipe := flags.String("pipe", "", `the named pipe of the node, for example \\.\pipe\ranz-bgp-1234`)
	logFile := flags.String("log", "", "append the log to this file instead of standard error")
	logDays := flags.Int("log-days", defaultLogDays, "with -log, the age limit of the log files in days: older files are deleted; 0 for no limit")
	logMB := flags.Int("log-mb", defaultLogMB, "with -log, the disk limit of the log files in megabytes, which they never pass together; 0 for no limit")
	logLevel := flags.String("log-level", "info", "the level of the log: debug, info, warn or error")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ranz bgp: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if *pipe == "" {
		fmt.Fprintln(stderr, "ranz bgp: -pipe is required: the node starts the sidecar")
		return 2
	}
	if *logDays < 0 || *logMB < 0 {
		fmt.Fprintln(stderr, "ranz bgp: -log-days and -log-mb must not be negative")
		return 2
	}
	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(stderr, "ranz bgp: -log-level %q: %v\n", *logLevel, err)
		return 2
	}

	out := stderr
	if *logFile != "" {
		f, err := OpenLog(*logFile, *logDays, *logMB)
		if err != nil {
			fmt.Fprintf(stderr, "ranz bgp: %v\n", err)
			return 1
		}
		defer f.Close()
		out = f
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: &level}))
	mitigation.Log(log, mitigations, mitigationErr)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := dialNode(dctx, *pipe)
	cancel()
	if err != nil {
		log.Error("cannot connect to the node", "pipe", *pipe, "err", err)
		return 1
	}
	// The command line says how the node started the sidecar: ranz bgp, which the node's test reads
	log.Info("connected to the node", "pipe", *pipe, "command", strings.Join(os.Args, " "), "version", sidecar.Version(), "pid", os.Getpid())

	if err := sidecar.Run(ctx, conn, sidecar.Options{Logger: log, LogLevel: &level}); err != nil {
		log.Error("session failed", "err", err)
		return 1
	}
	log.Info("the node closed the pipe: BGP stopped")
	return 0
}
