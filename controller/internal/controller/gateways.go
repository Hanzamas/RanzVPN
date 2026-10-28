package controller

import (
	"context"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The health data of gateway HA (SDN-19 #195, ADR-0025 decision 12). A Node picks the gateway of a
// LAN subnet that several gateways advertise from its own probes inside their Noise sessions and from
// the health data of the Controller. A gateway that had a control stream and has had none for
// NodeDownAfter, when the Controller raises node-down for it (telemetry.go), is down: every Node that
// has it as the Peer of a prefix that another of its peers advertises too gets that Peer marked down
// (Peer.down) in its next Generation, and gives the traffic of the prefix to another gateway that
// answers its probes, to this one only while none does. The mark goes when the gateway opens a control
// stream again. A Controller that starts, or a member that becomes the leader, knows of no gateway that
// is down; the probes of the Nodes find one all the same.

// gatewayState is what the Controller keeps for the health data of gateway HA, guarded by
// Controller.mu.
type gatewayState struct {
	down map[string]bool // the Nodes that are down, by name
}

// routeKey is a route of a Peer object as the health data compares them: its VRF and its prefix.
type routeKey struct {
	vrf     uint32
	address string
	length  uint32
}

// setGatewayDown records that the Node name is down, or up again, and gives each Node whose state that
// changes the next Generation. A Node that opened a control stream again meanwhile is not down.
func (c *Controller) setGatewayDown(name string, down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.gw.down[name] == down {
		return
	}
	if n := c.nodes[name]; down && n != nil && n.stream != nil {
		return
	}
	if down {
		if c.gw.down == nil {
			c.gw.down = map[string]bool{}
		}
		c.gw.down[name] = true
	} else {
		delete(c.gw.down, name)
	}
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		c.log.Error("compiling the health data of gateway HA", "node", name, "down", down, "err", err)
		return
	}
	// Only a gateway of a prefix that another gateway advertises too changes a state
	changed := false
	for node, st := range cp.states {
		if n := c.nodes[node]; n == nil || !desired.Equal(n.state, st) {
			changed = true
			break
		}
	}
	if !changed {
		return
	}
	if _, err := c.commit(context.Background(), c.intent, cp, store.Changes{}); err != nil {
		c.log.Error("sending the health data of gateway HA to the nodes", "node", name, "down", down, "err", err)
		return
	}
	c.log.Info("gateway HA: the health data of a gateway changed", "node", name, "down", down)
}

// withHealth marks down, in each state, the Peer object of a Node that the Controller knows to be down
// and that advertises a prefix that another peer of the state advertises too. c.mu is held, and states
// are the fresh result of the compilation.
func (c *Controller) withHealth(states map[string]desired.State) {
	if len(c.gw.down) == 0 {
		return
	}
	for _, st := range states {
		// The prefixes of the routes of the peers, each with the number of peers that it leads to. A
		// leaked route goes into a VRF of its peer, and no other peer has it.
		peers := map[routeKey]int{}
		for k, o := range st {
			if k.Kind != controlpb.Kind_KIND_PEER {
				continue
			}
			for _, r := range o.GetPeer().GetRoutes() {
				if r.GetPeerVrfId() == 0 || r.GetPeerVrfId() == r.GetVrfId() {
					peers[keyOf(r)]++
				}
			}
		}
		for k, o := range st {
			p := o.GetPeer()
			if k.Kind != controlpb.Kind_KIND_PEER || !c.gw.down[p.GetName()] ||
				!slices.ContainsFunc(p.GetRoutes(), func(r *controlpb.Route) bool { return peers[keyOf(r)] > 1 }) {
				continue
			}
			peer, ok := proto.Clone(p).(*controlpb.Peer)
			if !ok {
				continue
			}
			peer.Down = true
			st[k] = &controlpb.Object{Kind: &controlpb.Object_Peer{Peer: peer}}
		}
	}
}

// keyOf returns the key of the route r.
func keyOf(r *controlpb.Route) routeKey {
	return routeKey{vrf: r.GetVrfId(), address: string(r.GetPrefix().GetAddress()), length: r.GetPrefix().GetLength()}
}
