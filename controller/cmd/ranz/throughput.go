package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
	"github.com/Hanzamas/RanzVPN/controller/internal/throughput"
)

// ranz test throughput is the traffic test, the successor of the commands TrafficServer and
// TrafficClient of vpncmd (SDN-53, #246): a server on one node and a client on another measure the
// rate between them over TCP connections, which over the overlay is the rate of the path that the
// traffic of a node takes. The package throughput holds the test.
func init() {
	registerTest("throughput", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runThroughput(ctx, args, os.Stdout, os.Stderr)
	})
}

const throughputUsage = `usage:
  ranz test throughput -listen ADDRESS
  ranz test throughput [flags] HOST[:PORT]

The first form runs the test server on a node, at an address of the node such as its overlay
address, until it is stopped. The second runs the test from another node against the server at
HOST, which is an address or a name; the port is 9821 unless it is given. The test opens
connections to the server, which carry data for the span, and prints the rate that they reached.
`

// runThroughput is `ranz test throughput`: the server with -listen, the client without it. It
// returns the exit code of the process: 0 when the server stopped or the test ran, 1 when either
// failed, and 2 for arguments that are wrong. A ctx that ends stops the server and the test.
func runThroughput(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz test throughput", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "", "run the test server on this `address`, for example 100.64.0.2:9821")
	connections := flags.Int("connections", throughput.DefaultConnections, "the number of TCP connections that the test opens, at most 32")
	kind := flags.String("type", "full", "the direction of the data: download (from the server), upload (to the server) or full (both: the number of connections must be even)")
	span := flags.Duration("span", throughput.DefaultSpan, "how long the data flows, for example 15s")
	double := flags.Bool("double", false, "double the rate of each direction, for a link whose device both receives and sends what the test sends")
	raw := flags.Bool("raw", false, "leave the TCP/IP and Ethernet headers out of the count, which the test adds to the data by default")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	flags.Usage = func() {
		fmt.Fprint(stderr, throughputUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *listen != "" {
		if flags.NArg() > 0 {
			fmt.Fprintf(stderr, "ranz test throughput: -listen runs the server and takes no address to test: %q\n", flags.Args())
			return 2
		}
		return serveThroughput(ctx, *listen, stdout, stderr)
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "ranz test throughput: give the address of the server, or -listen to run one")
		flags.Usage()
		return 2
	}
	direction, err := throughputDirection(*kind)
	if err != nil {
		fmt.Fprintln(stderr, "ranz test throughput:", err)
		return 2
	}
	address, err := throughputAddress(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "ranz test throughput:", err)
		return 2
	}
	opts := throughput.Options{Connections: *connections, Direction: direction, Span: *span, Raw: *raw, Double: *double}
	fmt.Fprintf(stderr, "ranz test throughput: %d connections to %s, %s, for %v\n", *connections, address, direction, *span)
	res, err := throughput.Run(ctx, address, opts)
	if err != nil {
		fmt.Fprintln(stderr, "ranz test throughput:", err)
		return 1
	}
	if *asJSON {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "ranz test throughput:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, res)
	return 0
}

// serveThroughput runs the test server on addr until ctx ends, and logs each connection to out. It
// returns the exit code of the process.
func serveThroughput(ctx context.Context, addr string, out, stderr io.Writer) int {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(stderr, "ranz test throughput:", err)
		return 1
	}
	defer ln.Close()
	// The port of the test in Windows Firewall while it serves (SDN-91, #396), so that a client on
	// another PC reaches it without a rule made by hand. A loopback address needs none: no other PC
	// reaches it.
	if a, ok := ln.Addr().(*net.TCPAddr); ok && !a.IP.IsLoopback() {
		defer install.AllowTestPort(out, a.Port)()
	}
	var mu sync.Mutex
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(out, "%s %s\n", time.Now().Format(time.TimeOnly), fmt.Sprintf(format, args...))
	}
	mu.Lock()
	fmt.Fprintf(out, "ranz test throughput: serving on %s; stop it with Ctrl+C\n", ln.Addr())
	mu.Unlock()
	if err := throughput.Serve(ctx, ln, logf); err != nil {
		fmt.Fprintln(stderr, "ranz test throughput:", err)
		return 1
	}
	return 0
}

// throughputDirection returns the direction that the flag -type names.
func throughputDirection(name string) (throughput.Direction, error) {
	switch strings.ToLower(name) {
	case "full":
		return throughput.Full, nil
	case "download":
		return throughput.Download, nil
	case "upload":
		return throughput.Upload, nil
	}
	return throughput.Full, fmt.Errorf("-type %q is none of full, download and upload", name)
}

// throughputAddress returns the address that the argument names, a host and a port: the host as
// it was given, a name or an IP address with or without brackets, and the port of the argument, or
// throughput.DefaultPort when it has none.
func throughputAddress(arg string) (string, error) {
	host, port, err := net.SplitHostPort(arg)
	if err != nil {
		// No port: the whole argument is the host, a name or an IP address. An IPv6 address may
		// come in brackets.
		host = strings.TrimSuffix(strings.TrimPrefix(arg, "["), "]")
		if _, err := netip.ParseAddr(host); err != nil && strings.Contains(host, ":") {
			return "", fmt.Errorf("%q is no address", arg)
		}
		port = strconv.Itoa(throughput.DefaultPort)
	}
	if host == "" {
		return "", fmt.Errorf("%q names no host", arg)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q is no port", port)
	}
	return net.JoinHostPort(host, port), nil
}
