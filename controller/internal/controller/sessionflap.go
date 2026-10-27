package controller

import (
	"context"
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// takeSessionFlap raises the Event session-flap for the report of the node of s (AUD1-DT-11, #459): the
// node counted the replacements of the session of one of its peers in a window and found them above
// its limit, so two holders of one key replace each other's session (NS-12 of docs/threat-model.md). The
// subject of ne is the peer, and its message says how often and from which source addresses the sessions
// came. The node limits how often it reports one for a peer, so the store takes one write for each
// report, as for a gateway failover.
func (c *Controller) takeSessionFlap(s *stream, ne *controlpb.NodeEvent) {
	subject := clip(ne.GetSubject(), maxSubject)
	msg := clip(ne.GetMessage(), maxEventMessage)
	if msg == "" {
		msg = fmt.Sprintf("the session of peer %s of node %s was replaced again and again", subject, s.name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.Raise(ctx, event.Event{Type: event.SessionFlap, Node: s.name, Subject: subject, Message: msg}); err != nil {
		c.log.Error("raising the session flap that a node reported", "node", s.name, "peer", subject, "err", err)
	}
}
