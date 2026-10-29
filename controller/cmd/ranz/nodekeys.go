package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// The commands of the node keys (SDN-56 #249, ADR-0031 amendment of 2026-10-28), which main.go hands the arguments that
// follow node-key. Each makes one call of the API under /api/v1/operations, which needs the role operator, and prints
// the answer of the API:
//
//	ranz node-key list [-o json|table]   the key of every Node: its state (valid, expired or pending), when it last
//	                                     authenticated, when it ends, the days that are left, and whether the Node was
//	                                     approved
//	ranz node-key approve NODE           approve a Node that its Network holds for approval: it is admitted, and its key
//	                                     lives from now
//	ranz node-key refresh NODE           give the key of a Node that has no owner another period, as the login of its user
//	                                     does for a device
//
// JSON, the default, is the answer of the API. A table is one line for each Node: its name, its owner, the state of its
// key, when it ends and how many days are left (SDN-56-R1 #515).
//
// A Node of a Network that holds new Nodes for approval waits, and its control stream is refused, until it is approved;
// a Node whose key ended is refused until its user logs in again with `ranz node login`, or an operator refreshes it. The
// controller raises the Events node-waiting, node-key-expiring and node-key-ended for them (`ranz get events`).

// nodeKeyCommand runs the command of args, the arguments after node-key.
func nodeKeyCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) >= 1 && args[0] == "list":
		return nodeKeyList(ctx, c, args[1:], out)
	case len(args) == 2 && args[0] == "approve":
		info, err := c.ApproveNode(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, info)
	case len(args) == 2 && args[0] == "refresh":
		info, err := c.RefreshNodeKey(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, info)
	}
	return errUsage
}

// nodeKeyList prints the keys of the Nodes in the form that the flags of args ask for.
func nodeKeyList(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("node-key list", flag.ContinueOnError)
	format := flags.String("o", "json", "the form of the answer: json, as the API answers, or table")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || (*format != "json" && *format != "table") {
		return errUsage
	}
	keys, err := c.NodeKeys(ctx)
	if err != nil {
		return err
	}
	if *format == "json" {
		return show(out, api.NodeKeyList{NodeKeys: keys})
	}
	return nodeKeyTable(out, keys)
}

// nodeKeyTable prints the keys, one line each. A key that has no end says never, and the key of a Node that waits has none
// yet: its life begins when it is approved.
func nodeKeyTable(out io.Writer, keys []controller.NodeKeyInfo) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tOWNER\tSTATE\tENDS\tDAYS LEFT")
	for _, k := range keys {
		ends := "-"
		if k.State != controller.KeyPending {
			ends = "never"
			if !k.Expires.IsZero() {
				ends = k.Expires.UTC().Format(time.RFC3339)
			}
		}
		days := "-"
		if k.DaysLeft > 0 {
			days = fmt.Sprint(k.DaysLeft)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.Node, k.Owner, k.State, ends, days)
	}
	return tw.Flush()
}
