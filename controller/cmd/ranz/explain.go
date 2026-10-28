package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// The subcommand explain (SDN-15, #191; ADR-0031 decision 7), a client of the controller's API as the CLI is:
//
//	ranz explain [flags] A B   walk the compiled model of the controller for a packet from A to B and print each
//	                           step: the VRF, the route of the forwarding table with the VRF that a leaked route comes
//	                           from and its route targets, the 1:1 NAT rules, the link with the endpoints of its Nodes
//	                           and whether it encrypts, the effective session profile of each end that runs under one,
//	                           with the User or the Group that gives it (SDN-40), and the rule of the policy of the VRF
//	                           at each end; then where the packet ends
//
// A is a Node, which sends from its address in the VRF, a WireGuard Device, or an address of either; B is a Node, a
// Device or an IP address. The flags come before A and B: the connection flags of the CLI (-server, -token-file,
// -tls-fingerprint, with the same environment variables), -vrf, -protocol, -sport, -port, and -o json for the
// answer of the API as it is.
func init() {
	register("explain", func(args []string) int { return runExplain(context.Background(), args, os.Stdout, os.Stderr) })
}

const explainUsage = `usage: ranz explain [flags] A B
  A: a Node, a WireGuard Device or an address of either, which sends the packet
  B: a Node, a WireGuard Device or an IP address
`

// runExplain runs ranz explain with the arguments that follow its name, and returns the exit code.
func runExplain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := os.Getenv("RANZ_SERVER")
	if server == "" {
		server = "https://127.0.0.1"
	}
	flags.StringVar(&server, "server", server, "the URL of the controller's HTTP API")
	tokenFile := flags.String("token-file", os.Getenv("RANZ_TOKEN_FILE"), "the file that holds the API token; without one, RANZ_TOKEN holds the token")
	fingerprint := flags.String("tls-fingerprint", os.Getenv("RANZ_TLS_FINGERPRINT"), "accept only the controller's certificate with this TLS fingerprint (ranz status prints it)")
	vrf := flags.String("vrf", "", "the VRF of A that the packet goes in; left out, the VRF that leads B to another Node")
	protocol := flags.String("protocol", "", "tcp, udp, icmp or the number of an IP protocol; icmp, an echo request, when left out")
	sport := flags.Uint("sport", 0, "the source port of TCP or UDP")
	port := flags.Uint("port", 0, "the destination port of TCP or UDP")
	format := flags.String("o", "text", "the form of the answer: text, or json as the API gives it")
	flags.Usage = func() {
		fmt.Fprint(stderr, explainUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 2 || *sport > 65535 || *port > 65535 || (*format != "text" && *format != "json") {
		flags.Usage()
		return 2
	}
	c, err := newClient(server, *tokenFile, os.Getenv("RANZ_TOKEN"), *fingerprint)
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	q := explain.Query{From: flags.Arg(0), To: flags.Arg(1), VRF: *vrf, Protocol: *protocol, SourcePort: uint16(*sport), Port: uint16(*port)}
	res, err := c.Explain(ctx, q)
	if err != nil {
		var refused *api.Error
		if errors.As(err, &refused) {
			fmt.Fprintf(stderr, "ranz: %v (%d %s)\n", err, refused.Status, http.StatusText(refused.Status))
		} else {
			fmt.Fprintln(stderr, "ranz:", err)
		}
		return 1
	}
	if *format == "json" {
		err = show(stdout, res)
	} else {
		err = printExplain(stdout, res)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	return 0
}

// printExplain prints the walk of r: the packet, one line for each step with its Node and its kind, and the verdict.
// The kinds take 6 columns, more when a step of a longer kind is there (profile, SDN-40).
func printExplain(out io.Writer, r explain.Result) error {
	width, kinds := len(r.Packet.Node), 6
	for _, s := range r.Steps {
		width = max(width, len(s.Node))
		kinds = max(kinds, len(s.Kind))
	}
	p := r.Packet
	if _, err := fmt.Fprintf(out, "%s from %s in VRF %s\n", p, p.Node, p.VRF); err != nil {
		return err
	}
	for _, s := range r.Steps {
		if _, err := fmt.Fprintf(out, "  %-*s  %-*s  %s\n", width, s.Node, kinds, s.Kind, s.Text); err != nil {
			return err
		}
	}
	v := r.Verdict
	if v.Delivered {
		_, err := fmt.Fprintf(out, "verdict: delivered to %s in VRF %s as %s > %s\n", v.Node, v.VRF, v.Source, v.Destination)
		return err
	}
	_, err := fmt.Fprintf(out, "verdict: dropped by %s (%s): %s\n", v.Node, v.Reason, v.Text)
	return err
}
