package controller

import (
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// announce says, for the life of the key of a Node at an instant, what the controller announces of it, and notes it in the
// marks of the life so that each announcement is made once (SDN-56-R1). The cases walk the life of a key of a user's device
// from the span before its end to its end, and the other states of a key: one with no end, one that a Network holds for
// approval and a server that has no owner.
func TestAnnounceSaysWhatTheLifeOfAKeyCallsForOnce(t *testing.T) {
	const day = 24 * time.Hour
	ends := time.Date(2026, time.November, 30, 10, 0, 0, 0, time.UTC)
	device := intent.Node{Owner: "alice"}
	server := intent.Node{}
	life := func(marks uint8) store.NodeKey {
		return store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Expires: ends, Approved: true, Announced: marks}
	}

	for _, c := range []struct {
		what   string
		node   intent.Node
		life   store.NodeKey
		holder string
		now    time.Time
		// The event that is raised, none when typ is empty, and the marks that remain
		typ     string
		message string
		marks   uint8
	}{
		{"a key with 90 days left", device, life(0), "", ends.Add(-90 * day), "", "", 0},
		{"a key with 14 days and a second left", device, life(0), "", ends.Add(-14*day - time.Second), "", "", 0},
		{"a key that enters the span of 14 days", device, life(0), "", ends.Add(-14 * day), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" of User "alice" ends at 2026-11-30T10:00:00Z, in 14 days: its user logs in again to refresh it`, store.AnnouncedExpiring},
		{"a key in the span that was announced", device, life(store.AnnouncedExpiring), "", ends.Add(-10 * day), "", "", store.AnnouncedExpiring},
		{"a key with 13 days and 23 hours left, counted up", device, life(0), "", ends.Add(-13*day - 23*time.Hour), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" of User "alice" ends at 2026-11-30T10:00:00Z, in 14 days: its user logs in again to refresh it`, store.AnnouncedExpiring},
		{"a key with 3 days left after its first announcement", device, life(store.AnnouncedExpiring), "", ends.Add(-3 * day), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" of User "alice" ends at 2026-11-30T10:00:00Z, in 3 days: its user logs in again to refresh it`, store.AnnouncedExpiring | store.AnnouncedLast},
		{"a key with 3 days left that was announced twice", device, life(store.AnnouncedExpiring | store.AnnouncedLast), "", ends.Add(-2 * day), "", "",
			store.AnnouncedExpiring | store.AnnouncedLast},
		{"a key that the controller first looks at with 2 days and 1 hour left: one announcement, not the two it missed", device, life(0), "", ends.Add(-2*day - time.Hour), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" of User "alice" ends at 2026-11-30T10:00:00Z, in 3 days: its user logs in again to refresh it`, store.AnnouncedExpiring | store.AnnouncedLast},
		{"a key with 1 day left", device, life(store.AnnouncedExpiring), "", ends.Add(-day), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" of User "alice" ends at 2026-11-30T10:00:00Z, in 1 day: its user logs in again to refresh it`, store.AnnouncedExpiring | store.AnnouncedLast},
		{"a key that ends this instant", device, life(store.AnnouncedExpiring | store.AnnouncedLast), "", ends, event.NodeKeyEnded,
			`the key of Node "alice-laptop" of User "alice" expired at 2026-11-30T10:00:00Z: its user logs in again to refresh it`, store.AnnouncedEnded},
		{"a key that ended and was announced", device, life(store.AnnouncedEnded), "", ends.Add(5 * day), "", "", store.AnnouncedEnded},
		{"a key that ended before the controller looked", device, life(0), "", ends.Add(time.Hour), event.NodeKeyEnded,
			`the key of Node "alice-laptop" of User "alice" expired at 2026-11-30T10:00:00Z: its user logs in again to refresh it`, store.AnnouncedEnded},
		{"a key of a server that has no owner", server, life(0), "", ends.Add(-3 * day), event.NodeKeyExpiring,
			`the key of Node "alice-laptop" ends at 2026-11-30T10:00:00Z, in 3 days: an operator refreshes it, or marks the Node nonExpiring`, store.AnnouncedExpiring | store.AnnouncedLast},
		{"a key of a server that ended", server, life(0), "", ends.Add(day), event.NodeKeyEnded,
			`the key of Node "alice-laptop" expired at 2026-11-30T10:00:00Z: an operator refreshes it, or marks the Node nonExpiring`, store.AnnouncedEnded},
		{"a Node that its Network holds for approval", device, store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Expires: ends}, "corp-lan", ends.Add(-90 * day), event.NodeWaiting,
			`Node "alice-laptop" of User "alice" waits for an administrator to approve it in Network "corp-lan": ranz node-key approve alice-laptop`, store.AnnouncedWaiting},
		{"a server that its Network holds for approval", server, store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Expires: ends}, "corp-lan", ends.Add(-90 * day), event.NodeWaiting,
			`Node "alice-laptop" waits for an administrator to approve it in Network "corp-lan": ranz node-key approve alice-laptop`, store.AnnouncedWaiting},
		{"a Node that waits and was announced", device, store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Expires: ends, Announced: store.AnnouncedWaiting}, "corp-lan", ends.Add(-90 * day), "", "",
			store.AnnouncedWaiting},
		{"a Node that waits past the end that its key had before it was approved: it is waiting, and the key is not announced", device,
			store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Expires: ends, Announced: store.AnnouncedWaiting}, "corp-lan", ends.Add(30 * day), "", "", store.AnnouncedWaiting},
		{"a Node that was approved in a Network that holds new Nodes", device, life(store.AnnouncedWaiting), "corp-lan", ends.Add(-90 * day), "", "", 0},
		{"a Node that no Network holds any more", device, life(store.AnnouncedWaiting), "", ends.Add(-90 * day), "", "", 0},
		{"a key that ended on a Node that is marked nonExpiring", intent.Node{NonExpiring: true}, store.NodeKey{Key: []byte{1}, Node: "alice-laptop", Approved: true, Announced: store.AnnouncedEnded},
			"", ends.Add(30 * day), "", "", 0},
	} {
		got, events := announce("alice-laptop", c.node, c.life, c.holder, c.now)
		if got.Announced != c.marks {
			t.Errorf("%s: the marks are %b, want %b", c.what, got.Announced, c.marks)
		}
		if c.typ == "" {
			if len(events) != 0 {
				t.Errorf("%s: the events are %+v, want none", c.what, events)
			}
			continue
		}
		if len(events) != 1 {
			t.Errorf("%s: the events are %+v, want one %s", c.what, events, c.typ)
			continue
		}
		subject := c.node.Owner
		if e := events[0]; e.Type != c.typ || e.Node != "alice-laptop" || e.Subject != subject || !e.Time.Equal(c.now) || e.Message != c.message {
			t.Errorf("%s: the event is %+v, want %s of the node alice-laptop about %q at %v that says %q", c.what, e, c.typ, subject, c.now, c.message)
		}
		// What it noted is announced already: the same life at the same instant says nothing
		if again, events := announce("alice-laptop", c.node, got, c.holder, c.now); len(events) != 0 || again.Announced != got.Announced {
			t.Errorf("%s: the second look says %+v with the marks %b, want nothing", c.what, events, again.Announced)
		}
	}
}

// A key with no end announces nothing, whatever its marks said: the Node was marked nonExpiring after its key was announced.
func TestAKeyWithNoEndAnnouncesNothing(t *testing.T) {
	now := time.Date(2026, time.November, 30, 10, 0, 0, 0, time.UTC)
	life := store.NodeKey{Key: []byte{1}, Node: "files", Approved: true, Announced: store.AnnouncedExpiring | store.AnnouncedLast}
	got, events := announce("files", intent.Node{NonExpiring: true}, life, "", now)
	if len(events) != 0 || got.Announced != 0 {
		t.Errorf("a key that has no end is announced with %+v and the marks %b, want no event and no mark", events, got.Announced)
	}
	// The same life as a key that has an end in the past, which is not marked: it is not a key with no end
	if _, events := announce("files", intent.Node{}, store.NodeKey{Key: []byte{1}, Node: "files", Approved: true, Expires: now.Add(-time.Hour)}, "", now); len(events) != 1 || events[0].Type != event.NodeKeyEnded {
		t.Errorf("a key that ended an hour ago is announced with %+v, want node-key-ended", events)
	}
}

// The days left of a key are counted up, and said in the singular for one.
func TestTheDaysLeftOfAKeyAreCountedUp(t *testing.T) {
	const day = 24 * time.Hour
	for _, c := range []struct {
		left time.Duration
		days int
		text string
	}{
		{time.Second, 1, "1 day"},
		{day, 1, "1 day"},
		{day + time.Second, 2, "2 days"},
		{3*day - time.Millisecond, 3, "3 days"},
		{3 * day, 3, "3 days"},
		{14 * day, 14, "14 days"},
	} {
		if got := daysIn(c.left); got != c.days {
			t.Errorf("daysIn(%v) is %d, want %d", c.left, got, c.days)
		}
		if got := dayCount(c.left); got != c.text {
			t.Errorf("dayCount(%v) is %q, want %q", c.left, got, c.text)
		}
	}
}
