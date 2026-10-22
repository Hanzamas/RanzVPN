package controller

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The first start (ADR-0034, SDN-3 #179). A controller with Config.Defaults whose store holds no
// revision yet makes the intent of a first install (intent.FirstInstall) revision 1: VRF default
// with overlay DNS on, its Network default with the automatic IPv4 pool, and the starter rule
// that allows all traffic inside it. The Nodes that are applied later join VRF default and get
// their addresses from that pool. It is the controller's own change, not an operator's, and it
// adds no Node, so neither the licence nor a cluster of several members holds it back; once the
// store holds a revision, no later start makes it again.

// firstStart applies the intent of a first install as the first revision. c.mu is held.
func (c *Controller) firstStart(ctx context.Context) error {
	next, err := intent.Apply(c.intent, intent.FirstInstall(), c.random)
	if err != nil {
		return err
	}
	cp, err := c.compile(next, c.lic)
	if err != nil {
		return err
	}
	res, err := c.change(ctx, next, cp, c.nextRevision(intent.OpFirstStart), store.Changes{})
	if err != nil {
		return err
	}
	c.log.Info("first start: the intent of a first install", "revision", res.Revision, "vrf", intent.DefaultVRF,
		"pool", intent.DefaultPool, "rule", intent.StarterRule)
	return nil
}
