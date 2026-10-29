package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The announcements of the lives of the node keys (SDN-56-R1 #515, ADR-0030 amendment of 2026-10-29). A key ends without a word
// to the people it is about, and every Node that existed when the first start gave the Nodes their lives ends on the same day,
// so the controller says what comes before it does. It raises an Event when a Network holds a new Node for approval
// (event.NodeWaiting), when the key of a Node ends within keyWarning (event.NodeKeyExpiring) and again when keyLastCall is left,
// and when a key ended (event.NodeKeyEnded). `ranz get events` lists them, a webhook target may name their types, and each is a
// record of the audit log under the actor system, with the Event as its action.
//
// Each is made once. The mark of what was announced of a key is in its row of the store (store.NodeKey.Announced), written in the
// same transaction as the Event (store.PutNodeKeys), so that a restart of the controller, and the next leader of a cluster, raise
// none twice and lose none. A state that ends takes its mark away: the refresh of a key and the approval of a Node begin a period
// (renewKey, approveNode), so the end of the next one is announced again, and a Node that its Network no longer holds is no longer
// waiting. A look that finds a key past some of the states of its life announces the one that it is in and not the ones that it
// missed: a key with 2 days left when the controller first looks at it is announced once, with the days that are left.

const (
	// keyWarning is how long before the end of a key the controller announces it for the first time: two working weeks, to mark
	// servers nonExpiring or to ask the users to log in again.
	keyWarning = 14 * 24 * time.Hour
	// keyLastCall is how long before the end of a key the controller announces it for the last time: the last call before a
	// weekend.
	keyLastCall = 3 * 24 * time.Hour
	// dayLength is the day that the days left of a key are counted in.
	dayLength = 24 * time.Hour
	// maxAnnouncements is the most Events that one look at the keys raises. Every Node that existed at the first start ends at the
	// same instant, so a controller with many Nodes finds them all in the span at once, and each Event is a write of the store while
	// the controller holds its lock. A look that reaches the limit leaves the other keys as they are, and the next look goes on
	// with them.
	maxAnnouncements = 200
)

// announce notes in life, the life of the key of the Node name at the instant now, what the controller announces of it, and returns
// it with the Events that make the announcements, none when there is nothing new to say. holder is the Network that holds the Node
// for approval, empty when none does.
func announce(name string, n intent.Node, life store.NodeKey, holder string, now time.Time) (store.NodeKey, []event.Event) {
	raise := func(typ, message string) []event.Event {
		return []event.Event{{Time: now, Type: typ, Node: name, Subject: n.Owner, Message: message}}
	}
	// A Node that waits has no life yet: its key lives from its approval, and it is announced once
	if holder != "" && !life.Approved {
		if life.Announced&store.AnnouncedWaiting != 0 {
			return life, nil
		}
		life.Announced |= store.AnnouncedWaiting
		return life, raise(event.NodeWaiting, waitingMessage(name, n, holder))
	}
	life.Announced &^= store.AnnouncedWaiting
	// The state of the key that holds now, and the marks that it has not got yet
	var state uint8
	left := life.Expires.Sub(now)
	switch {
	case n.NonExpiring || life.Expires.IsZero():
		// A key that has no end announces nothing
	case left <= 0:
		state = store.AnnouncedEnded
	case left <= keyLastCall:
		state = store.AnnouncedExpiring | store.AnnouncedLast
	case left <= keyWarning:
		state = store.AnnouncedExpiring
	}
	fresh := state &^ life.Announced
	life.Announced = life.Announced&^store.AnnouncedLife | state
	switch {
	case fresh&store.AnnouncedEnded != 0:
		return life, raise(event.NodeKeyEnded, endedMessage(name, n, life.Expires))
	case fresh != 0:
		return life, raise(event.NodeKeyExpiring, expiringMessage(name, n, life.Expires, left))
	}
	return life, nil
}

// announced does what follows the Events that the store took with the lives of the keys (store.PutNodeKeys): the log says each as it
// says every Event, the audit log records each under the actor system, with the type of the Event as its action and what it was
// about as its subject, and the event feed looks for them at once, to deliver them to the webhooks.
func (c *Controller) announced(ctx context.Context, events []event.Event) {
	if len(events) == 0 {
		return
	}
	for _, ev := range events {
		c.log.Warn("event raised", "type", ev.Type, "node", ev.Node, "subject", ev.Subject, "message", ev.Message)
		// RecordAudit logs what it could not store: the Event is made and stays
		_ = c.RecordAudit(ctx, audit.Record{Time: ev.Time, Kind: audit.Operation, Actor: audit.ActorSystem, Source: audit.SourceLocal,
			Outcome: audit.Success, Action: ev.Type, Subject: "node " + ev.Node, Message: ev.Message})
	}
	c.tel.feed.Poke()
}

// ownerOf says whose device the Node is in the text of an announcement, for a Node that has an owner.
func ownerOf(n intent.Node) string {
	if n.Owner == "" {
		return ""
	}
	return fmt.Sprintf(" of User %q", n.Owner)
}

// refreshAdvice says who gives the key of the Node another period, in the words of holdMessage: its User by logging in again, or,
// for a Node that has no User, an operator.
func refreshAdvice(n intent.Node) string {
	if n.Owner != "" {
		return "its user logs in again to refresh it"
	}
	return "an operator refreshes it, or marks the Node nonExpiring"
}

// waitingMessage is the message of the Event node-waiting for the Node name that the Network holder holds for approval.
func waitingMessage(name string, n intent.Node, holder string) string {
	return fmt.Sprintf("Node %q%s waits for an administrator to approve it in Network %q: ranz node-key approve %s", name, ownerOf(n), holder, name)
}

// expiringMessage is the message of the Event node-key-expiring for the Node name whose key ends at the instant expires, which is left
// from now.
func expiringMessage(name string, n intent.Node, expires time.Time, left time.Duration) string {
	return fmt.Sprintf("the key of Node %q%s ends at %s, in %s: %s", name, ownerOf(n), expires.UTC().Format(time.RFC3339), dayCount(left), refreshAdvice(n))
}

// endedMessage is the message of the Event node-key-ended for the Node name whose key ended at the instant expires.
func endedMessage(name string, n intent.Node, expires time.Time) string {
	return fmt.Sprintf("the key of Node %q%s expired at %s: %s", name, ownerOf(n), expires.UTC().Format(time.RFC3339), refreshAdvice(n))
}

// daysIn returns how many days the span left holds, counted up: a key that has 3 days and 2 hours left has 4.
func daysIn(left time.Duration) int {
	return int((left + dayLength - 1) / dayLength)
}

// dayCount says the days of the span left as text.
func dayCount(left time.Duration) string {
	if days := daysIn(left); days != 1 {
		return fmt.Sprintf("%d days", days)
	}
	return "1 day"
}
