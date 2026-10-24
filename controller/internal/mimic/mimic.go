// Package mimic is `ranz mimic`, the mimicry sidecar of a Ranz node (ADR-0023, CORE-P2-1 #85): the
// transport for a network that fingerprints and probes (a GFW-class network), in Go because the
// libraries that can do it are Go and native Schannel and msquic cannot shape a ClientHello.
//
// The server role terminates REALITY (github.com/xtls/reality, MPL-2.0) on TCP 443. A client that
// proves the key of the server is a Ranz client, and its inner stream, the Noise session of the node,
// goes to the node over a connection of a named pipe. A connection that does not is spliced to a
// real site, so a prober sees an ordinary website and never a VPN: the own decoy, a landing page
// with a certificate from an ACME service, or a big site that the operator borrows, whose
// certificate the prober sees and whose key the sidecar never holds.
//
// The client role dials a server for the node over a named pipe: the TCP connection, the TLS
// handshake with the ClientHello of a browser (uTLS, github.com/refraction-networking/utls,
// BSD-3-Clause: Edge by default, Chrome or Firefox for a link) with the proof of REALITY in it, and
// the stream. Both roles can shape what they send: the sizes of the frames that carry the inner
// stream and their timing (frame.go), against the length patterns of TLS in TLS.
//
// The node starts the sidecar as `ranz mimic -pipe NAME`, as it starts the BGP sidecar: the pipe is
// the control pipe, the sidecar connects to it, and the node sends the settings and reads what the
// sidecar tells (control.go). The inner streams use pipes of their own. The named pipe is also the
// licence boundary of ADR-0023: the sidecar is a program of its own that the node starts, and it
// links nothing of the node. Since ONE-1 (#310) it is a subcommand of the one executable ranz
// (controller/cmd/ranz): Main runs it.
//
// Usage:
//
//	ranz mimic -pipe \\.\pipe\NAME [-log FILE] [-log-level LEVEL]
//	ranz mimic -keygen
package mimic

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/mitigation"
)

// dialTimeout bounds the connection to the control pipe of the node, which exists before the node
// starts the sidecar.
const dialTimeout = 10 * time.Second

// mitigations and mitigationErr are what mitigation.Apply did in Main, which run logs; nil when a
// test calls run itself.
var (
	mitigations   []mitigation.Result
	mitigationErr error
)

// Main is `ranz mimic` with the arguments after the subcommand. It returns the exit code of the
// process (see run).
func Main(args []string) int {
	// The process mitigations of ADR-0039 before the sidecar starts anything
	mitigations, mitigationErr = mitigation.Apply()
	return run(context.Background(), args, os.Stdout, os.Stderr)
}

// run is `ranz mimic` with the arguments args; it returns the exit code: 0 when the node closed the
// pipe, 1 when the session failed, 2 for bad arguments.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz mimic", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pipe := flags.String("pipe", "", `the control pipe of the node, for example \\.\pipe\ranz-mimic-1234`)
	logFile := flags.String("log", "", "append the log to this file instead of standard error")
	logLevel := flags.String("log-level", "info", "the level of the log: debug, info, warn or error")
	keygen := flags.Bool("keygen", false, "print a new key pair for a server and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ranz mimic: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	if *keygen {
		if *pipe != "" {
			fmt.Fprintln(stderr, "ranz mimic: -keygen takes no -pipe")
			return 2
		}
		if err := printKeys(stdout); err != nil {
			fmt.Fprintf(stderr, "ranz mimic: %v\n", err)
			return 1
		}
		return 0
	}
	if *pipe == "" {
		fmt.Fprintln(stderr, "ranz mimic: -pipe is required: the node starts the sidecar")
		return 2
	}
	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(stderr, "ranz mimic: -log-level %q: %v\n", *logLevel, err)
		return 2
	}

	out := stderr
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "ranz mimic: %v\n", err)
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
	conn, err := dialPipe(dctx, *pipe)
	cancel()
	if err != nil {
		log.Error("cannot connect to the node", "pipe", *pipe, "err", err)
		return 1
	}
	// The command line says how the node started the sidecar: ranz mimic, which the node's test reads
	log.Info("connected to the node", "pipe", *pipe, "command", strings.Join(os.Args, " "), "version", Version(), "pid", os.Getpid())

	if err := Run(ctx, conn, Options{Logger: log}); err != nil {
		log.Error("session failed", "err", err)
		return 1
	}
	log.Info("the node closed the pipe: the sidecar stopped")
	return 0
}

// printKeys writes a new X25519 key pair as two lines, the private key of a server and the public
// key that its clients are given, each as 64 hex digits.
func printKeys(w io.Writer) error {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "private_key %s\npublic_key %s\n", hex.EncodeToString(key.Bytes()), hex.EncodeToString(key.PublicKey().Bytes()))
	return err
}
