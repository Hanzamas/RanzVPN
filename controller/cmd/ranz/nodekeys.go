package main

import (
	"context"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
)

// The commands of the node keys (SDN-56 #249, ADR-0031 amendment of 2026-10-28), which main.go hands the arguments that
// follow node-key. Each makes one call of the API under /api/v1/operations, which needs the role operator, and prints
// the answer of the API:
//
//	ranz node-key list              the key of every Node: its state (valid, expired or pending), when it last
//	                                authenticated, when it ends, and whether the Node was approved
//	ranz node-key approve NODE      approve a Node that its Network holds for approval: it is admitted, and its key
//	                                lives from now
//	ranz node-key refresh NODE      give the key of a Node that has no owner another period, as the login of its user
//	                                does for a device
//
// A Node of a Network that holds new Nodes for approval waits, and its control stream is refused, until it is approved;
// a Node whose key ended is refused until its user logs in again with `ranz node login`, or an operator refreshes it.

// nodeKeyCommand runs the command of args, the arguments after node-key.
func nodeKeyCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		keys, err := c.NodeKeys(ctx)
		if err != nil {
			return err
		}
		return show(out, api.NodeKeyList{NodeKeys: keys})
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
