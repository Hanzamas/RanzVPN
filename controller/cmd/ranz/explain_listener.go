package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain -listener NAME (SDN-94, #423) asks the controller to explain a Listener, and prints what the Controller
// knows about its mimic server: the section, whether the Node reported the public key of the server, and the Nodes that
// have a link to it. A server whose Node has not reported yet has no client with a link, and the answer says that the
// Controller waits for the public key of that Node. With -o json it prints the answer of the API as it is.

// explainListener runs ranz explain -listener and returns the exit code.
func explainListener(ctx context.Context, c *api.Client, name, format string, stdout, stderr io.Writer) int {
	res, err := c.ExplainListener(ctx, name)
	if err != nil {
		var refused *api.Error
		if errors.As(err, &refused) {
			fmt.Fprintf(stderr, "ranz: %v (%d %s)\n", err, refused.Status, http.StatusText(refused.Status))
		} else {
			fmt.Fprintln(stderr, "ranz:", err)
		}
		return 1
	}
	if format == "json" {
		err = show(stdout, res)
	} else {
		err = printListener(stdout, res)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	return 0
}

// printListener prints the explanation r of a Listener.
func printListener(out io.Writer, r explain.ListenerResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Listener %s of Node %s\n", r.Listener, r.Node)
	m := r.Mimic
	if m == nil {
		b.WriteString("  no mimic section: the Node is no mimic server\n")
		_, err := io.WriteString(out, b.String())
		return err
	}
	fmt.Fprintf(&b, "  mimic server: the sidecar listens on %s, an address of its own, not the one of the front door\n", m.Listen)
	fmt.Fprintf(&b, "  server names: %s (the first is the name in the ClientHello of the links)\n", strings.Join(m.ServerNames, ", "))
	fmt.Fprintf(&b, "  decoy: %s\n", decoyText(m.Decoy))
	fmt.Fprintf(&b, "  clock tolerance: %d ms\n", m.MaxTimeDiffMs)
	if len(r.MimicEndpoints) == 0 {
		fmt.Fprintf(&b, "  endpoints: Node %s names no endpoint of the mimic transport, so no Node dials the server over mimic\n", r.Node)
	} else {
		fmt.Fprintf(&b, "  endpoints: %s (the clients dial these)\n", strings.Join(r.MimicEndpoints, ", "))
	}
	if r.KeyReported {
		fmt.Fprintf(&b, "  public key: reported by Node %s, %s (each client pins it)\n", r.Node, r.PublicKey)
	} else {
		fmt.Fprintf(&b, "  public key: not reported by Node %s\n", r.Node)
	}
	if r.Waiting != "" {
		fmt.Fprintf(&b, "  waiting: %s\n", r.Waiting)
	}
	fmt.Fprintf(&b, "  links: %d\n", len(r.Links))
	for _, l := range r.Links {
		fmt.Fprintf(&b, "    %s dials %s as %s\n", l.Node, l.Address, l.ServerName)
	}
	if len(r.Unlinked) > 0 {
		fmt.Fprintf(&b, "  no link yet: %s\n", strings.Join(r.Unlinked, ", "))
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// decoyText says the decoy d of a mimic section in a phrase.
func decoyText(d intent.MimicDecoy) string {
	switch {
	case d.Mode == intent.MimicDecoyBorrow:
		return "borrows the site at " + d.Dest + ", whose own certificate a prober sees"
	case d.ACME != nil:
		return "own site, certificate from the ACME service " + d.ACME.Directory + ", cache " + d.ACME.CacheDir
	case d.CertFile != "":
		return "own site, certificate in " + d.CertFile + ", key in " + d.KeyFile
	}
	return "own site, self-signed certificate (for tests only)"
}
