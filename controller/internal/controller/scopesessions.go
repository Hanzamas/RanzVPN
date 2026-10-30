package controller

import (
	"fmt"
	"net"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The sessions quota of a Network (SDN-38 #231): the most control streams that the Nodes in its scope have open
// at once, which the delegation of the Network sets (scope.Quotas.Sessions). A session is the control stream of a
// Node (SDN-50), so the controller keeps the quota at the door: the stream of one more Node of a Network whose
// sessions are all open is refused, as a stream from outside the source prefixes of its Network is (SDN-39, enrol.go),
// with the reason REFUSE_REASON_UNKNOWN_NODE, the one reason of the control protocol for a Node that is not
// admitted, and a message that names the Network and the quota. The Node dials again after the delay of a refused
// stream and is admitted when a session of its Network has ended. The new stream of a Node that has one open
// replaces it, so it does not count against itself. A Node that is in no scope, and a Network that has no sessions
// quota, are never refused.

// sessionsFull returns the Network of the Node name, and its sessions quota, when the Network has as many open as
// the quota allows, not counting the stream of the Node itself. c.mu is held.
func (c *Controller) sessionsFull(name string) (network string, limit uint32, full bool) {
	network, _ = c.intent.ScopeOf(intent.KindNode, name)
	if network == "" {
		return "", 0, false
	}
	d, ok := c.scopes.get(network)
	if !ok || d.Quotas.Sessions == 0 {
		return "", 0, false
	}
	var open uint32
	for other, n := range c.nodes {
		if other == name || n.stream == nil {
			continue
		}
		if s, _ := c.intent.ScopeOf(intent.KindNode, other); s == network {
			open++
		}
	}
	return network, d.Quotas.Sessions, open >= d.Quotas.Sessions
}

// refuseSessions ends the control stream conn of the Node name, which a Network whose sessions are all open
// does not admit: it records the refusal as a failed authentication, as the refusal of a banned user is, and sends
// the Refuse.
func (c *Controller) refuseSessions(conn *control.Conn, name, network string, limit uint32, remote net.Addr) {
	c.log.Warn("node refused: the sessions of its Network are all open", "node", name, "network", network, "sessions", limit, "remote", remote.String())
	c.auditNode(audit.AuthFailed, audit.ActorNode(name), audit.Failure, fmt.Sprintf("Network %s allows %d sessions at most, and they are all open", network, limit), remote)
	writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "Network %q allows %d sessions at most, and they are all open: the node is admitted when one ends", network, limit))
}
