package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// The commands of the live operations (SDN-50 #243, ADR-0031 amendment of 2026-10-27), which main.go
// hands the arguments that follow session, ban, mac-table and ip-table. Each makes one call of the API
// under /api/v1/operations, which needs the role operator, and prints the answer of the API:
//
//	ranz session list [-user NAME] [-node NAME]     the sessions: who is connected, from where, with which addresses
//	                                                and how much traffic
//	ranz session disconnect ID                      end the session ID at once
//	ranz session disconnect -user NAME              end every session of the user NAME at once
//	ranz ban list                                   the banned users
//	ranz ban set [-reason TEXT] USER                ban the user: every device of the user is cut off at once and
//	                                                none gets in until the ban is lifted
//	ranz ban clear USER                             lift the ban of the user
//	ranz mac-table [-node NODE] NETWORK             the MAC table of the L2 Network on each node that holds it
//	ranz mac-table clear [-node NODE] [-mac ADDRESS] NETWORK
//	                                                remove one entry of it, or every entry
//	ranz ip-table [-node NODE] NETWORK              the IP table of the L2 Network
//	ranz ip-table clear [-node NODE] [-address ADDRESS] NETWORK
//	                                                remove one entry of it, or every entry
//
// A call on a table gets the result of every node, also of the ones that were down or did not answer,
// each with its status; the command prints them all, and ends with an error when a node did not do what
// was asked, so that a script sees it.

// sessionCommand runs the command of args, the arguments after session.
func sessionCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) >= 1 && args[0] == "list":
		flags := flag.NewFlagSet("session list", flag.ContinueOnError)
		user := flags.String("user", "", "only the sessions of the nodes that this user owns")
		node := flags.String("node", "", "only the session of this node")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() > 0 {
			return errUsage
		}
		sessions, err := c.Sessions(ctx, *user, *node)
		if err != nil {
			return err
		}
		return show(out, api.SessionList{Sessions: sessions})
	case len(args) >= 1 && args[0] == "disconnect":
		flags := flag.NewFlagSet("session disconnect", flag.ContinueOnError)
		user := flags.String("user", "", "end every session of the nodes that this user owns, and no id is given")
		if err := flags.Parse(args[1:]); err != nil {
			return errUsage
		}
		switch {
		case *user != "" && flags.NArg() == 0:
			sessions, err := c.DisconnectUser(ctx, *user)
			if err != nil {
				return err
			}
			return show(out, api.SessionList{Sessions: sessions})
		case *user == "" && flags.NArg() == 1:
			s, err := c.Disconnect(ctx, flags.Arg(0))
			if err != nil {
				return err
			}
			return show(out, api.SessionList{Sessions: []controller.Session{s}})
		}
	}
	return errUsage
}

// banCommand runs the command of args, the arguments after ban.
func banCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		bans, err := c.Bans(ctx)
		if err != nil {
			return err
		}
		return show(out, api.BanList{Bans: bans})
	case len(args) >= 1 && args[0] == "set":
		flags := flag.NewFlagSet("ban set", flag.ContinueOnError)
		reason := flags.String("reason", "", "why the user is banned: the node of the user shows it when the controller refuses it")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			return errUsage
		}
		res, err := c.Ban(ctx, flags.Arg(0), *reason)
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) == 2 && args[0] == "clear":
		ban, err := c.Unban(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, ban)
	}
	return errUsage
}

// macTableCommand runs ranz mac-table with args, the arguments after it.
func macTableCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	return tableCommand(ctx, c, controller.TableMAC, args, out)
}

// ipTableCommand runs ranz ip-table with args, the arguments after it.
func ipTableCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	return tableCommand(ctx, c, controller.TableIP, args, out)
}

// tableCommand reads the table of an L2 Network, or with clear as its first argument, which a Network
// of that name does not take for a subcommand when it is the only argument, removes its entries: on the
// node that -node names, else on every node that holds the Network. A removal takes -mac for the MAC
// table, or -address for the IP table, to remove one entry.
func tableCommand(ctx context.Context, c *api.Client, table controller.TableKind, args []string, out io.Writer) error {
	remove := len(args) >= 2 && args[0] == "clear"
	if remove {
		args = args[1:]
	}
	flags := flag.NewFlagSet("ranz "+string(table)+"-table", flag.ContinueOnError)
	node := flags.String("node", "", "only the table on this node")
	var entry *string
	switch {
	case remove && table == controller.TableMAC:
		entry = flags.String("mac", "", "remove only the entry of this MAC address, such as 02:00:5e:10:00:01")
	case remove:
		entry = flags.String("address", "", "remove only the entry of this IP address")
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return errUsage
	}
	network := flags.Arg(0)
	var arg string
	if entry != nil {
		arg = *entry
	}
	var res controller.TableResult
	var err error
	switch {
	case table == controller.TableMAC && !remove:
		res, err = c.MACTable(ctx, network, *node)
	case table == controller.TableMAC:
		res, err = c.ClearMACTable(ctx, network, *node, arg)
	case !remove:
		res, err = c.IPTable(ctx, network, *node)
	default:
		res, err = c.ClearIPTable(ctx, network, *node, arg)
	}
	if err != nil {
		return err
	}
	if err := show(out, res); err != nil {
		return err
	}
	failed := 0
	for _, n := range res.Nodes {
		if n.Status != controller.TableOK {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d nodes did not do it, as their status says", failed, len(res.Nodes))
	}
	return nil
}
