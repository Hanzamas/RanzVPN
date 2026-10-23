package controller

import (
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// IPAM (ADR-0028, SDN-10 #186). The controller alone owns the addresses of the overlay: it
// allocates them from the pools of the Networks when it applies the intent (intent.Apply), and it
// reports a pool before the pool runs out. A change of the intent that takes a pool to the
// percentage of its addresses in use that its Network sets (the pool threshold, 80 by default)
// raises a PoolNearExhaustion event in the same transaction as the change; the condition arises
// once, not again at each change while the pool stays there, and it arises again when the pool
// has fallen below its threshold and a later change takes it there once more.

// IPAM is the answer to a question about the addresses of the overlay (`ranz get ipam`): how full
// each pool of each Network is, and the routes that the LAN subnets behind gateway Nodes make. A
// route is never an allocation: no Node holds an address in one.
type IPAM struct {
	Pools  []intent.PoolUse `json:"pools"`
	Routes []intent.Route   `json:"routes"`
}

// IPAM returns how full each pool is and the routes of the LAN subnets, as of the intent now.
func (c *Controller) IPAM() IPAM {
	c.mu.Lock()
	defer c.mu.Unlock()
	return IPAM{Pools: c.intent.Pools(), Routes: c.intent.Routes()}
}

// poolEvents returns the events of the change from prev to next that revision rev makes: one for
// each pool of next that is at or above its threshold and was not in prev. A pool that the change
// gives another prefix counts as a new pool.
func poolEvents(prev, next intent.Intent, rev intent.Revision) []event.Event {
	was := map[string]bool{}
	for _, u := range prev.Pools() {
		was[poolKey(u)] = u.NearExhaustion
	}
	var out []event.Event
	for _, u := range next.Pools() {
		if !u.NearExhaustion || was[poolKey(u)] {
			continue
		}
		family := "IPv4"
		if u.Pool.Addr().Is6() {
			family = "IPv6"
		}
		ev := event.Event{Time: rev.Time, Type: event.PoolNearExhaustion, Revision: rev.ID}
		ev.Message = fmt.Sprintf("Network %q of VRF %q: the %s pool %s is %d%% used (%d of its %d addresses), at or above its threshold of %d%%",
			u.Network, u.VRF, family, u.Pool, u.Percent, u.Allocated+u.Reserved, u.Size, u.Threshold)
		out = append(out, ev)
	}
	return out
}

// poolKey names a pool by its Network and its prefix.
func poolKey(u intent.PoolUse) string {
	return u.Network + " " + u.Pool.String()
}
