package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The source prefixes of the Networks (SDN-39, #232): a Network may limit the addresses that its
// Nodes open their control stream from (intent.Network.EnrolSources), which is how a node enrols
// and enrols again. The controller checks the address of every stream against the Networks of the
// VRFs of its node, before the node reports anything or gets any state, and refuses a node that
// one of them does not allow; it records the refusal as an event. A change of the intent that
// tightens a restriction refuses the streams that it no longer allows at once. The Refuse says
// REFUSE_REASON_UNKNOWN_NODE, the one reason of the control protocol for a node that is not
// admitted, and its message names the address and the Network.

// auditTimeout bounds the write of the event of a refusal, so that a store that does not answer
// cannot hold the refusal back.
const auditTimeout = 5 * time.Second

// enrolFormat is the message of the Refuse for a node that opens its stream from an address that a
// Network of its VRFs does not allow to enrol: the address, and the Network.
const enrolFormat = "the source address %s is outside the source prefixes that Network %q allows to enrol"

// enrolRefused returns the Network that refuses the node name when it opens its control stream
// from remote, and the address of remote that it checked, when one does. c.mu is held.
func (c *Controller) enrolRefused(name string, remote net.Addr) (network string, from netip.Addr, refused bool) {
	from, _ = intent.SourceAddr(remote.String())
	network, refused = c.intent.EnrolRefusedBy(name, from)
	return network, from, refused
}

// refuseSource ends the stream conn of the node name, which opened it from the address from
// against the source prefixes of the Network network: it records the refusal and sends the Refuse.
func (c *Controller) refuseSource(conn *control.Conn, name, network string, from netip.Addr) {
	c.log.Warn("node refused: source address outside the source prefixes of its Network", "node", name, "network", network, "remote", from.String())
	c.recordEnrolRefusal(name, network, from)
	writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, enrolFormat, from, network))
}

// recordEnrolRefusal records the refusal of the node name, from the address from, by the Network
// network as an event, unless the throttle holds it back: a node that tries again and again is
// recorded once a minute, with the count of the tries that were not.
func (c *Controller) recordEnrolRefusal(name, network string, from netip.Addr) {
	now := time.Now()
	skipped, ok := c.enrolRefusals.Take(name+" "+from.String(), now)
	if !ok {
		return
	}
	msg := fmt.Sprintf("Node %q opened its control stream from %s, which Network %q does not allow to enrol", name, from, network)
	if skipped > 0 {
		msg += fmt.Sprintf(" (refusals not recorded since the last record: %d)", skipped)
	}
	ev := event.Event{Time: now.UTC().Truncate(time.Millisecond), Type: event.EnrolmentRefused, Message: msg}
	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()
	if err := c.store.Commit(ctx, store.Changes{AddEvents: []event.Event{ev}}); err != nil {
		c.log.Error("recording a refused enrolment", "node", name, "err", err)
	}
	// The audit log records it as a failed enrolment, as often as the event (SDN-49, audit.go)
	_ = c.RecordAudit(ctx, audit.Record{Kind: audit.Enrolment, Actor: audit.ActorNode(name), Source: from.String(), Outcome: audit.Failure, Message: msg})
}

// refuseOutsideSources refuses the stream of each node whose source address the Networks of the
// intent no longer allow to enrol, so that a tightened restriction takes effect at once. c.mu is
// held, and c.intent is the intent just committed.
func (c *Controller) refuseOutsideSources() {
	if !c.intent.HasEnrolSources() {
		return
	}
	for name, n := range c.nodes {
		if n.stream == nil {
			continue
		}
		from, _ := intent.SourceAddr(n.stream.conn.RemoteAddr().String())
		if network, refused := c.intent.EnrolRefusedBy(name, from); refused {
			c.refuse(n.stream, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, enrolFormat, from, network)
		}
	}
}
