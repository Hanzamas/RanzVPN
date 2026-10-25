package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/acmecert"
)

// ranz acme is the ACME sidecar of the Listener of a node (SDN-45, #238): the node runs it
// (src/Cedar/NodeListener.c) to get the certificate of its Listener from an ACME service with the
// HTTP-01 challenge, or to renew it when it is due, as it runs ranz bgp for BGP. The package
// acmecert holds the run.
func init() {
	register("acme", func(args []string) int { return runACME(context.Background(), args, os.Stderr) })
}

// acmeTimeout bounds one run: the node waits 180 s for it (NODE_LISTENER_ACME_WAIT).
const acmeTimeout = 150 * time.Second

const acmeUsage = `usage: ranz acme -directory URL -names NAME[,NAME...] -state DIR -out FILE [flags]

ranz acme gets the certificate of the DNS names from the ACME service of the directory, with the
HTTP-01 challenge on -http-port, into the My certificate store of Windows, its key into the
Microsoft Software Key Storage Provider; or it keeps the certificate that -state names while it is
in the store and ends more than -renew-days from now. It writes its answer to -out: the line
"thumbprint <40 hex digits>" of the certificate, or "error <why>". The node of a Listener with an
ACME source runs it.
`

// runACME is `ranz acme`. It returns the exit code of the process: 0 with the certificate, 1 when
// the run failed, and 2 for arguments that are wrong.
func runACME(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz acme", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o acmecert.Options
	var names, out string
	var machine bool
	flags.StringVar(&o.Directory, "directory", "", "the https URL of the ACME directory")
	flags.StringVar(&names, "names", "", "the DNS names of the certificate, separated by commas")
	flags.StringVar(&o.Email, "email", "", "the contact of the ACME account; none when it is empty")
	flags.StringVar(&o.CAFile, "ca", "", "a PEM file with the roots of a private ACME service; the roots of the system when it is empty")
	flags.IntVar(&o.HTTPPort, "http-port", 80, "the TCP port that answers the HTTP-01 challenge")
	flags.IntVar(&o.RenewDays, "renew-days", 30, "renew the certificate this many days before its end")
	flags.StringVar(&o.State, "state", "", "the state directory of the Listener: its ACME account and its certificate")
	flags.StringVar(&out, "out", "", "the file for the answer")
	flags.BoolVar(&machine, "machine", false, "the machine key set and the LocalMachine store, where the node service finds them, which need an administrator")
	flags.Usage = func() {
		fmt.Fprint(stderr, acmeUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 || out == "" {
		fmt.Fprintf(stderr, "ranz acme: unexpected arguments %q, or no -out\n", flags.Args())
		return 2
	}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			o.Names = append(o.Names, n)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	r, err := acmecert.Run(ctx, o, acmecert.WindowsStore{Machine: machine}, time.Now())
	answer := "thumbprint " + r.Thumbprint
	if err != nil {
		// The answer is one line
		answer = "error " + strings.Join(strings.Fields(err.Error()), " ")
	}
	if werr := os.WriteFile(out, []byte(answer+"\n"), 0o600); werr != nil {
		fmt.Fprintln(stderr, "ranz acme:", werr)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz acme:", err)
		return 1
	}
	fmt.Fprintf(stderr, "ranz acme: the certificate %s of %s ends %s (renewed: %v)\n", r.Thumbprint, strings.Join(o.Names, ", "), r.NotAfter.Format(time.RFC3339), r.Renewed)
	return 0
}
