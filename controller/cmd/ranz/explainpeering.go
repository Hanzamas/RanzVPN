package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// ranz explain NODE (SDN-77, #357): the BGP peering of the standard mode of a Node, as the Node reported it last on its
// control stream. Each peer of its sidecar gets a line with the Node whose tunnel endpoint has its address, the address
// and the state of the session, and below it each prefix that the Node learned from it, with its VRF; a Node that the
// intent names as a peer and that the report lacks gets a line that says so.

// explainPeering prints the BGP peering of the Node name with c, as text or as the JSON of the API (format), and
// returns the exit code.
func explainPeering(ctx context.Context, c *api.Client, name, format string, stdout, stderr io.Writer) int {
	st, err := c.Peering(ctx, name)
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
		err = show(stdout, st)
	} else {
		err = printPeering(stdout, st)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	return 0
}

// printPeering prints the BGP peering st: a line for the Node, one for each peer of its sidecar with the prefixes
// learned from it below, and one for each Node that the intent names as a peer and the report lacks.
func printPeering(out io.Writer, st controller.PeeringStatus) error {
	if st.ASN == 0 && len(st.Peers) == 0 {
		_, err := fmt.Fprintf(out, "BGP peering of %s: none, no VRF of the Node peers by BGP\n", st.Node)
		return err
	}
	reported := "no report yet"
	if !st.Reported.IsZero() {
		reported = "reported " + st.Reported.UTC().Format(time.RFC3339)
	}
	if _, err := fmt.Fprintf(out, "BGP peering of %s in AS %d: %d peers, %d sessions refused (%s)\n", st.Node, st.ASN, len(st.Peers), st.Refused, reported); err != nil {
		return err
	}
	width := 0
	for _, p := range st.Peers {
		width = max(width, len(peerName(p)))
	}
	for _, name := range st.Expected {
		width = max(width, len(name))
	}
	var seen []string
	for _, p := range st.Peers {
		seen = append(seen, p.Node)
		if _, err := fmt.Fprintf(out, "  %-*s  %s  %s, %d prefixes learned\n", width, peerName(p), p.Address, p.State, len(p.Learned)); err != nil {
			return err
		}
		for _, r := range p.Learned {
			if _, err := fmt.Fprintf(out, "  %-*s    %s  %s\n", width, "", r.VRF, r.Prefix); err != nil {
				return err
			}
		}
	}
	for _, name := range st.Expected {
		if slices.Contains(seen, name) {
			continue
		}
		if _, err := fmt.Fprintf(out, "  %-*s  no session in the report\n", width, name); err != nil {
			return err
		}
	}
	return nil
}

// peerName is the Node of the peer p, or what stands for it when no Node has its address.
func peerName(p controller.PeeringPeer) string {
	if p.Node == "" {
		return "(no Node)"
	}
	return p.Node
}
