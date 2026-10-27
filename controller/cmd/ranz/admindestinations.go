package main

import (
	"context"
	"flag"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
)

// The command of the admin destination lists (AUD1-DT-9 #457), which main.go hands the arguments that
// follow admin-destinations:
//
//	ranz admin-destinations list     print the three lists: the target hosts, the sensor prefixes and the
//	                                 UNC servers
//	ranz admin-destinations set [-targets LIST] [-sensors LIST] [-unc-servers LIST]
//	                                 replace the lists that a flag names, each a list separated by commas
//	                                 (empty for none); the others keep their entries
//
// The target hosts are the hosts and the prefixes that an export or audit target may name although
// they are loopback, link-local or the store of the controller; the sensor prefixes are the prefixes
// that the sensor of every Mirror must be inside; the UNC servers are the servers that a UNC path of a
// Listener may name. Only an admin reads or changes them.
func adminDestinationsCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		d, err := c.AdminDestinations(ctx)
		if err != nil {
			return err
		}
		return show(out, d)
	case len(args) >= 1 && args[0] == "set":
		flags := flag.NewFlagSet("admin-destinations set", flag.ContinueOnError)
		targets := flags.String("targets", "", "the target hosts: hosts and prefixes, separated by commas; empty for none")
		sensors := flags.String("sensors", "", "the sensor prefixes, separated by commas; empty for none")
		servers := flags.String("unc-servers", "", "the UNC servers, separated by commas; empty for none")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return errUsage
		}
		given := map[string]bool{}
		flags.Visit(func(f *flag.Flag) { given[f.Name] = true })
		if len(given) == 0 {
			return errUsage
		}
		d, err := c.AdminDestinations(ctx)
		if err != nil {
			return err
		}
		if given["targets"] {
			d.Targets = splitList(*targets)
		}
		if given["sensors"] {
			d.Sensors = splitList(*sensors)
		}
		if given["unc-servers"] {
			d.UNCServers = splitList(*servers)
		}
		d, err = c.SetAdminDestinations(ctx, d)
		if err != nil {
			return err
		}
		return show(out, d)
	}
	return errUsage
}
