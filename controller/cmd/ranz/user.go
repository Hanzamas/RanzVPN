package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The commands of the users and the groups (SDN-31 #225), which main.go hands the arguments that
// follow user and group:
//
//	ranz user list                          print the users with their devices and whether each has a password
//	ranz user set [flags] NAME              make the user NAME, or change the fields that the flags name:
//	                                        -display, -groups, -expires, -max-devices, -may-change-password
//	                                        and -no-saved-password; the others keep their value
//	ranz user password [-f FILE] NAME       set the password of the user from FILE, or standard input
//	ranz user delete NAME                   delete the user and its password
//	ranz group list                         print the groups with their members
//	ranz group set [-display TEXT] NAME     make the group NAME, or change its display name
//	ranz group delete NAME                  delete the group
//
// The password is read from a file or standard input, one line, and never from an argument, which a
// process list and a shell history would show. The controller keeps it as a PBKDF2 hash, outside the
// intent.

// userCommand runs the command of args, the arguments after user.
func userCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		users, err := c.Users(ctx)
		if err != nil {
			return err
		}
		return show(out, api.UserList{Users: users})
	case len(args) >= 1 && args[0] == "set":
		return userSet(ctx, c, args[1:], out)
	case len(args) >= 1 && args[0] == "password":
		return userPassword(ctx, c, args[1:], out)
	case len(args) == 2 && args[0] == "delete":
		res, err := c.DeleteUser(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) >= 1 && args[0] == "role":
		// The API roles of users (userrole.go; SDN-32)
		return userRoleCommand(ctx, c, args[1:], out)
	}
	return errUsage
}

// userSet makes the user, or changes it, with the flags of args, which end with its name. The user
// that exists keeps every field that no flag names.
func userSet(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("user set", flag.ContinueOnError)
	display := flags.String("display", "", "the display name of the user")
	groups := flags.String("groups", "", "the groups of the user, separated by commas; empty for none")
	expires := flags.String("expires", "", "when the user expires, an RFC 3339 time such as 2026-12-31T23:59:59Z; none for never")
	maxDevices := flags.Uint("max-devices", 0, "the most devices of the user; 0 for no limit")
	mayChange := flags.Bool("may-change-password", true, "whether the user may change their own password")
	noSaved := flags.Bool("no-saved-password", false, "forbid a client to save the password of the user")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return errUsage
	}
	name := flags.Arg(0)
	given := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { given[f.Name] = true })

	var u intent.User
	users, err := c.Users(ctx)
	if err != nil {
		return err
	}
	for _, info := range users {
		if info.Name == name {
			u = info.User
		}
	}
	if given["display"] {
		u.DisplayName = *display
	}
	if given["groups"] {
		u.Groups = splitList(*groups)
	}
	if given["expires"] {
		u.Expires = time.Time{}
		if *expires != "none" {
			t, err := time.Parse(time.RFC3339, *expires)
			if err != nil {
				return fmt.Errorf("-expires %q is not an RFC 3339 time such as 2026-12-31T23:59:59Z, or none", *expires)
			}
			u.Expires = t
		}
	}
	if given["max-devices"] {
		if uint64(*maxDevices) > math.MaxUint32 {
			return fmt.Errorf("-max-devices %d is more than %d", *maxDevices, uint32(math.MaxUint32))
		}
		u.MaxDevices = uint32(*maxDevices)
	}
	if given["may-change-password"] {
		u.MayChangePassword = mayChange
	}
	if given["no-saved-password"] {
		u.NoSavedPassword = *noSaved
	}
	res, err := c.PutUser(ctx, name, u)
	if err != nil {
		return err
	}
	return show(out, res)
}

// userPassword sets the password of the user that args end with, from the file of -f or from
// standard input: the one line of it, without its line end.
func userPassword(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("user password", flag.ContinueOnError)
	file := flags.String("f", "-", "the file that holds the password, - for standard input")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return errUsage
	}
	b, err := readInput(*file)
	if err != nil {
		return err
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	res, err := c.SetUserPassword(ctx, flags.Arg(0), secret)
	if err != nil {
		return err
	}
	return show(out, res)
}

// groupCommand runs the command of args, the arguments after group.
func groupCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		groups, err := c.Groups(ctx)
		if err != nil {
			return err
		}
		return show(out, api.GroupList{Groups: groups})
	case len(args) >= 1 && args[0] == "set":
		flags := flag.NewFlagSet("group set", flag.ContinueOnError)
		display := flags.String("display", "", "the display name of the group")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			return errUsage
		}
		name := flags.Arg(0)
		var g intent.Group
		groups, err := c.Groups(ctx)
		if err != nil {
			return err
		}
		for _, info := range groups {
			if info.Name == name {
				g = info.Group
			}
		}
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "display" {
				g.DisplayName = *display
			}
		})
		res, err := c.PutGroup(ctx, name, g)
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) == 2 && args[0] == "delete":
		res, err := c.DeleteGroup(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, res)
	}
	return errUsage
}

// splitList splits a list of names on the command line, separated by commas, and leaves out the empty
// ones: an empty list is none.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
