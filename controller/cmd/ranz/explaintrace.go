package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// ranz explain -trace ID (SDN-89, #388): the path of a traced packet, as the Nodes that it crossed reported it. A Network
// whose trace is on has the packets of its pools traced: the Node where such a packet enters the overlay gives it a trace
// ID, and each Node that handles it reports the trace ID, the group that the packet carried and its verdict on it. The
// trace prints a line with its ID, its ingress Node and when the controller took its first record, then a line for each
// Node, the ingress Node first, with the VRF of the packet there, the group that it carried with the tags of its set, and
// the verdict of the Node. -trace all prints every trace that the controller holds, the newest first.

// explainTrace prints the trace of the trace ID which, decimal or 0x and hex, or every trace with "all", with c, as text or
// as the JSON of the API (format), and returns the exit code.
func explainTrace(ctx context.Context, c *api.Client, which, format string, stdout, stderr io.Writer) int {
	var traces []controller.Trace
	var err error
	if which == "all" {
		traces, err = c.Traces(ctx)
	} else {
		id, ok := parseTraceID(which)
		if !ok {
			fmt.Fprintf(stderr, "ranz: -trace takes a trace ID, a number from 1 to 4294967295 (decimal, or 0x and hex), or all, not %q\n", which)
			return 2
		}
		traces, err = c.TraceOf(ctx, id)
	}
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
		err = show(stdout, api.TraceList{Traces: traces})
	} else {
		err = printTraces(stdout, traces)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz:", err)
		return 1
	}
	return 0
}

// parseTraceID reads the trace ID of -trace as the usage says (SDN-89-R1, #630): hex after 0x, else decimal, from 1 to
// 4294967295. The base 0 of strconv would read octal, binary and underscores too, so that -trace 042 asked for the trace
// 34; here 042 is 42, and 0b1, 0o52 and 1_0 are no trace ID.
func parseTraceID(which string) (uint32, bool) {
	digits, base := which, 10
	if len(which) > 1 && which[0] == '0' && (which[1] == 'x' || which[1] == 'X') {
		digits, base = which[2:], 16
	}
	id, err := strconv.ParseUint(digits, base, 32)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint32(id), true
}

// printTraces prints the traces: for each a line with its trace ID, its ingress Node, when it was reported and how many
// Nodes recorded it, then one for each of those Nodes with its role, the VRF, the group and the verdict, in columns.
func printTraces(out io.Writer, traces []controller.Trace) error {
	if len(traces) == 0 {
		_, err := fmt.Fprintln(out, "no traced packet: the controller holds no trace yet")
		return err
	}
	for _, t := range traces {
		nodesText := fmt.Sprintf("%d Nodes", len(t.Steps))
		if len(t.Steps) == 1 {
			nodesText = "1 Node"
		}
		if _, err := fmt.Fprintf(out, "trace %d (0x%08x) of %s, reported %s: %s\n", t.ID, t.ID, t.Ingress, t.Reported.UTC().Format(time.RFC3339), nodesText); err != nil {
			return err
		}
		nodes, vrfs, groups := 0, 0, 0
		for _, s := range t.Steps {
			nodes = max(nodes, len(s.Node))
			vrfs = max(vrfs, len("VRF "+s.VRF))
			groups = max(groups, len(groupText(s)))
		}
		for _, s := range t.Steps {
			role := ""
			if s.Ingress {
				role = "ingress"
			}
			if _, err := fmt.Fprintf(out, "  %-*s  %-7s  %-*s  %-*s  %s\n", nodes, s.Node, role, vrfs, "VRF "+s.VRF, groups, groupText(s), verdictText(s.Verdict)); err != nil {
				return err
			}
		}
	}
	return nil
}

// groupText says the group that the packet carried at the step s: "group 2 (guest)", "group 5 (admin, ops)", "group 1"
// for a group without tags, or "no group".
func groupText(s controller.TraceStep) string {
	if s.Group == 0 {
		return "no group"
	}
	if len(s.Tags) == 0 {
		return fmt.Sprintf("group %d", s.Group)
	}
	return fmt.Sprintf("group %d (%s)", s.Group, strings.Join(s.Tags, ", "))
}

// verdictText says the verdict of a Node on the packet.
func verdictText(v string) string {
	if v == controller.TraceAllow {
		return "allowed"
	}
	return "denied"
}
