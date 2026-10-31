package main

import (
	"context"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
)

// The verb of the Stretches of the L2 Networks (SDN-63 #290):
//
//	ranz get stretches  print every Stretch with its gateway, its Network, its VNI, its route targets, its ESI and its limits,
//	                    and whether the controller puts it into the desired state of its gateway
//
// A Stretch is made and changed with ranz apply -f, and deleted with ranz delete Stretch NAME, as any resource is.
func getStretches(ctx context.Context, c *api.Client, out io.Writer) error {
	stretches, err := c.Stretches(ctx)
	if err != nil {
		return err
	}
	return show(out, api.StretchList{Stretches: stretches})
}
