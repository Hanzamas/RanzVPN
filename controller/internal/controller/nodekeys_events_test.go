// Controller conformance for the announcements of the lives of the node keys (SDN-56-R1 #515, ADR-0030 amendment of
// 2026-10-29), with the harness and the clock of nodekeys_test.go: the controller raises an Event when the key of a node is to
// end, when it ended and when a Network holds a new node for approval, once for each key and state, also across a restart, and
// each Event is a record of the audit log. The controller of these tests runs on a clock that they move.
package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// eventsOfType returns the events of the type typ, oldest first.
func eventsOfType(evs []event.Event, typ string) []event.Event {
	var out []event.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// eventsAbout returns the events of the type typ that are about the node name, oldest first.
func eventsAbout(evs []event.Event, typ, name string) []event.Event {
	var out []event.Event
	for _, e := range eventsOfType(evs, typ) {
		if e.Node == name {
			out = append(out, e)
		}
	}
	return out
}

// announcementsOf returns the records of the audit log that the controller made, under the actor system, for the Events of the
// type typ: operations whose action is the type.
func announcementsOf(recs []audit.Record, typ string) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.Operation && r.Actor == audit.ActorSystem && r.Action == typ {
			out = append(out, r)
		}
	}
	return out
}

// operationsBy returns the records of the kind operation that the actor made, oldest first.
func operationsBy(recs []audit.Record, actor string) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.Operation && r.Actor == actor {
			out = append(out, r)
		}
	}
	return out
}

// waitEvents lists the events until n of the type typ are there, and returns them. It fails with the events that it saw when there
// are not n within waitTimeout.
func (h *harness) waitEvents(typ string, n int) []event.Event {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		evs := h.events()
		if got := eventsOfType(evs, typ); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the events do not hold %d of the type %s within %v: %+v", n, typ, waitTimeout, evs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkEventCounts waits quietTimeout, in which the controller looks at the keys many times, and then checks that the events of each
// type of the lives of the keys are as many as want says, none for a type that it leaves out.
func (h *harness) checkEventCounts(want map[string]int) {
	h.t.Helper()
	time.Sleep(quietTimeout)
	evs := h.events()
	for _, typ := range []string{event.NodeKeyExpiring, event.NodeKeyEnded, event.NodeWaiting} {
		if got := len(eventsOfType(evs, typ)); got != want[typ] {
			h.t.Errorf("the events hold %d of the type %s, want %d: %+v", got, typ, want[typ], evs)
		}
	}
}

// checkKeyEvent checks that e is the event of the type typ about the node name, whose owner is the user owner, made at the instant at,
// with the message msg.
func checkKeyEvent(t *testing.T, e event.Event, typ, name, owner string, at time.Time, msg string) {
	t.Helper()
	if e.ID == 0 || e.Type != typ || e.Node != name || e.Subject != owner || !e.Time.Equal(at) || e.Message != msg {
		t.Errorf("the event is %+v, want %s about the node %s of the user %q at %v that says %q", e, typ, name, owner, at, msg)
	}
}

// forgetTheLives deletes the lives of the keys from the store of h while its controller is stopped: the store as it was before the key
// life, which holds the Nodes and no life of any key. A controller that starts on it gives each Node a life, as the first start with
// key life does.
func (h *harness) forgetTheLives() {
	h.t.Helper()
	raw, err := gorqlite.Open(h.rq.URL() + "?disableClusterDiscovery=true")
	if err != nil {
		h.t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `DELETE FROM node_keys`}); err != nil {
		h.t.Fatal(err)
	}
}

// keyOwners are the nodes of testdata/nodekeys.json and nodekeys-manual.json, by the user that owns each: files is a server.
var keyOwners = map[string]string{"alice-laptop": "alice", "bob-laptop": "bob", "files": ""}

// expiringText is the message of the event node-key-expiring for the node name of the user owner (a server when it is empty),
// whose key ends at the instant end, with the days that are left as text.
func expiringText(name, owner string, end time.Time, days string) string {
	if owner == "" {
		return fmt.Sprintf(`the key of Node %q ends at %s, in %s: an operator refreshes it, or marks the Node nonExpiring`, name, end.UTC().Format(time.RFC3339), days)
	}
	return fmt.Sprintf(`the key of Node %q of User %q ends at %s, in %s: its user logs in again to refresh it`, name, owner, end.UTC().Format(time.RFC3339), days)
}

// TestTheEndOfAKeyIsAnnouncedBeforeItComes is the first criterion of SDN-56-R1: the controller raises the event node-key-expiring
// for each key that ends within 14 days, once when it enters that span and once when 3 days are left, naming the node, its owner
// and the end, and a key with no end raises none. The clock of the controller moves from day to day, and the listing of the keys
// says the days that are left.
func TestTheEndOfAKeyIsAnnouncedBeforeItComes(t *testing.T) {
	h, clk := newKeysHarness(t)
	start := clk.Now()
	h.apply("nodekeys.json")
	// files is a server that nobody logs in for: it is marked, and its key has no end
	h.applyJSON(keysNode("files", keyLab1, "10.10.0.3", `, "nonExpiring": true`))
	end := start.Add(90 * keyDay)
	devices := map[string]string{"alice-laptop": "alice", "bob-laptop": "bob"}
	checkLastOf := func(evs []event.Event, count int, at time.Time, days string) {
		t.Helper()
		for name, owner := range devices {
			got := eventsAbout(evs, event.NodeKeyExpiring, name)
			if len(got) != count {
				t.Errorf("the events about %s are %+v, want %d of the type %s", name, got, count, event.NodeKeyExpiring)
				continue
			}
			checkKeyEvent(t, got[count-1], event.NodeKeyExpiring, name, owner, at, expiringText(name, owner, end, days))
		}
	}

	// 15 days before the end nothing is said
	clk.Advance(75 * keyDay)
	h.checkEventCounts(nil)

	// 14 days before it each key that ends is announced, and the key that has no end is not
	clk.Advance(keyDay)
	h.waitEvents(event.NodeKeyExpiring, 2)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 2})
	checkLastOf(h.events(), 1, start.Add(76*keyDay), "14 days")
	infos := h.nodeKeys()
	for name := range devices {
		if k := infos[name]; k.State != controller.KeyValid || k.DaysLeft != 14 {
			t.Errorf("the key of %s is %+v 14 days before its end, want it valid with 14 days left", name, k)
		}
	}
	if k := infos["files"]; k.State != controller.KeyValid || !k.NonExpiring || !k.Expires.IsZero() || k.DaysLeft != 0 {
		t.Errorf("the key of files is %+v, want a valid key with no end and no days left", k)
	}

	// Between the two announcements nothing more is said
	clk.Advance(10 * keyDay)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 2})
	if k := h.nodeKeys()["alice-laptop"]; k.DaysLeft != 4 {
		t.Errorf("the key of alice-laptop is %+v 4 days before its end, want 4 days left", k)
	}

	// 3 days before the end each key is announced again, the last call
	clk.Advance(keyDay)
	h.waitEvents(event.NodeKeyExpiring, 4)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 4})
	checkLastOf(h.events(), 2, start.Add(87*keyDay), "3 days")
	if k := h.nodeKeys()["bob-laptop"]; k.DaysLeft != 3 {
		t.Errorf("the key of bob-laptop is %+v 3 days before its end, want 3 days left", k)
	}

	// The keys that end are announced as ended, and the key that has no end has raised no event of any type through all of it
	clk.Advance(4 * keyDay)
	h.waitEvents(event.NodeKeyEnded, 2)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 4, event.NodeKeyEnded: 2})
	for _, typ := range []string{event.NodeKeyExpiring, event.NodeKeyEnded, event.NodeWaiting} {
		if got := eventsAbout(h.events(), typ, "files"); len(got) != 0 {
			t.Errorf("the key of files has no end, and the events say %+v of the type %s", got, typ)
		}
	}
	infos = h.nodeKeys()
	checkKeyState(t, infos, "files", controller.KeyValid)
	checkKeyState(t, infos, "alice-laptop", controller.KeyExpired)
	if k := infos["alice-laptop"]; k.DaysLeft != 0 {
		t.Errorf("the key of alice-laptop is %+v after it ended, want no days left", k)
	}
}

// TestAnEndedKeyAndAWaitingNodeAreAnnouncedOnce is the second criterion of SDN-56-R1: the controller raises node-key-ended when a
// key ends and node-waiting when a Network holds a new node for approval, each once for each key, and a restart of the controller
// does not raise them again. A refresh ends the state of an ended key, so its next end is announced, and an approval ends the
// waiting of a node, so a node that waits again is announced again. A key that the controller first looks at past the span of
// the warning is announced as ended, with no warning that it missed.
func TestAnEndedKeyAndAWaitingNodeAreAnnouncedOnce(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys-manual.json")
	h.setPasswords("alice", "bob")
	waiting := func(name, owner string) string {
		who := ""
		if owner != "" {
			who = fmt.Sprintf(" of User %q", owner)
		}
		return fmt.Sprintf(`Node %q%s waits for an administrator to approve it in Network "corp-lan": ranz node-key approve %s`, name, who, name)
	}
	ended := func(name, owner string, at time.Time) string {
		return fmt.Sprintf(`the key of Node %q of User %q expired at %s: its user logs in again to refresh it`, name, owner, at.UTC().Format(time.RFC3339))
	}

	// The Network holds all three nodes for approval, and each is announced when it is held
	h.waitEvents(event.NodeWaiting, 3)
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3})
	evs := h.events()
	for name, owner := range keyOwners {
		if got := eventsAbout(evs, event.NodeWaiting, name); len(got) != 1 {
			t.Errorf("the events about %s are %+v, want one of the type %s", name, got, event.NodeWaiting)
		} else {
			checkKeyEvent(t, got[0], event.NodeWaiting, name, owner, start, waiting(name, owner))
		}
	}

	// A restart of the controller raises none of them again, and the approval of the two devices raises none
	h.stop()
	h.start()
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3})
	for _, name := range []string{"alice-laptop", "bob-laptop"} {
		if _, err := h.api.ApproveNode(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3})
	infos := h.nodeKeys()
	checkKeyState(t, infos, "alice-laptop", controller.KeyValid)
	checkKeyState(t, infos, "bob-laptop", controller.KeyValid)
	checkKeyState(t, infos, "files", controller.KeyPending)

	// On day 91 the keys of the two devices have ended, and a node that waits has no key that ends. The controller never looked
	// at them within the 14 days before, so it says that they ended and nothing of what it missed
	clk.Advance(91 * keyDay)
	h.waitEvents(event.NodeKeyEnded, 2)
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3, event.NodeKeyEnded: 2})
	firstEnd := start.Add(90 * keyDay)
	evs = h.events()
	for _, name := range []string{"alice-laptop", "bob-laptop"} {
		if got := eventsAbout(evs, event.NodeKeyEnded, name); len(got) != 1 {
			t.Errorf("the events about %s are %+v, want one of the type %s", name, got, event.NodeKeyEnded)
		} else {
			checkKeyEvent(t, got[0], event.NodeKeyEnded, name, keyOwners[name], start.Add(91*keyDay), ended(name, keyOwners[name], firstEnd))
		}
	}

	// A restart does not raise them again either
	h.stop()
	h.start()
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3, event.NodeKeyEnded: 2})

	// bob logs in again: the state of his key as an ended one is over, his key lives 90 days from day 91, and when it ends the
	// controller announces it again, while the key of alice that ended on day 90 is not announced a second time
	if err := h.reauthenticate("bob", "a good password", keyBranch2); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["bob-laptop"]; k.State != controller.KeyValid || !k.Expires.Equal(start.Add(181*keyDay)) {
		t.Fatalf("the key of bob-laptop is %+v after his login on day 91, want it valid until day 181", k)
	}
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3, event.NodeKeyEnded: 2})
	clk.Advance(91 * keyDay)
	h.waitEvents(event.NodeKeyEnded, 3)
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3, event.NodeKeyEnded: 3})
	evs = h.events()
	if got := eventsAbout(evs, event.NodeKeyEnded, "alice-laptop"); len(got) != 1 {
		t.Errorf("the events about alice-laptop are %+v, want its key announced once, as ended since day 90", got)
	}
	if got := eventsAbout(evs, event.NodeKeyEnded, "bob-laptop"); len(got) != 2 {
		t.Errorf("the events about bob-laptop are %+v, want two, one for each of its periods", got)
	} else {
		checkKeyEvent(t, got[1], event.NodeKeyEnded, "bob-laptop", "bob", start.Add(182*keyDay), ended("bob-laptop", "bob", start.Add(181*keyDay)))
	}

	// An approval ends the waiting of a node: files is approved, and when it is deleted and made again its Network holds it again,
	// which is announced again
	if _, err := h.api.ApproveNode(ctx, "files"); err != nil {
		t.Fatal(err)
	}
	h.checkEventCounts(map[string]int{event.NodeWaiting: 3, event.NodeKeyEnded: 3})
	if _, err := h.api.Delete(ctx, intent.KindNode, "files"); err != nil {
		t.Fatal(err)
	}
	h.applyJSON(keysNode("files", keyLab1, "10.10.0.3", ""))
	h.waitEvents(event.NodeWaiting, 4)
	h.checkEventCounts(map[string]int{event.NodeWaiting: 4, event.NodeKeyEnded: 3})
	got := eventsAbout(h.events(), event.NodeWaiting, "files")
	if len(got) != 2 {
		t.Fatalf("the events about files are %+v, want two of the type %s, one for each time that it waited", got, event.NodeWaiting)
	}
	checkKeyEvent(t, got[1], event.NodeWaiting, "files", "", start.Add(182*keyDay), waiting("files", ""))
}

// TestTheFirstStartWithKeyLifeAnnouncesTheSharedDeadline is the third criterion of SDN-56-R1. The first start with key life on a
// store that has Nodes gives each of them a life of a full period from that moment, so every key ends at the same instant, and
// without a word, all the nodes would leave the overlay on one day. 14 days before it, every node whose end is within 14 days gets
// its event node-key-expiring, in the list of the events (ranz get events) and in the audit log, and a restart of the controller
// says none of them again.
func TestTheFirstStartWithKeyLifeAnnouncesTheSharedDeadline(t *testing.T) {
	h, clk := newKeysHarness(t)
	h.apply("nodekeys.json")

	// The store as it was before the key life holds the nodes and no life of any key; the controller that starts on it gives each
	// Node a life from now
	h.stop()
	h.forgetTheLives()
	clk.Advance(time.Hour)
	first := clk.Now()
	h.start()
	shared := first.Add(90 * keyDay)
	for name, k := range h.nodeKeys() {
		if k.State != controller.KeyValid || !k.Refreshed.Equal(first) || !k.Expires.Equal(shared) {
			t.Errorf("the key of %s is %+v after the first start, want it valid and ending at %v, as every key does", name, k, shared)
		}
	}

	// Until 14 days before the end nothing is said; then every node is announced at once
	clk.Advance(75 * keyDay)
	h.checkEventCounts(nil)
	clk.Advance(keyDay)
	h.waitEvents(event.NodeKeyExpiring, 3)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 3})
	evs := h.events()
	for name, owner := range keyOwners {
		if got := eventsAbout(evs, event.NodeKeyExpiring, name); len(got) != 1 {
			t.Errorf("the events about %s are %+v, want one of the type %s", name, got, event.NodeKeyExpiring)
		} else {
			checkKeyEvent(t, got[0], event.NodeKeyExpiring, name, owner, first.Add(76*keyDay), expiringText(name, owner, shared, "14 days"))
		}
	}

	// Each is a record of the audit log too, made by the system, about the node, with the message of the event
	recs := h.waitAudit(h.api, "a record of each announcement", func(rs []audit.Record) bool {
		return len(announcementsOf(rs, event.NodeKeyExpiring)) >= 3
	})
	records := announcementsOf(recs, event.NodeKeyExpiring)
	if len(records) != 3 {
		t.Fatalf("the audit log holds %d announcements, want 3:\n%s", len(records), auditLines(recs))
	}
	for name, owner := range keyOwners {
		var got *audit.Record
		for i, r := range records {
			if r.Subject == "node "+name {
				got = &records[i]
			}
		}
		if got == nil {
			t.Errorf("the audit log holds no announcement about %s:\n%s", name, auditLines(recs))
			continue
		}
		if got.ID == 0 || got.Source != audit.SourceLocal || got.Outcome != audit.Success || !got.Time.Equal(first.Add(76*keyDay)) || got.Message != expiringText(name, owner, shared, "14 days") {
			t.Errorf("the announcement of %s is %+v, want a success of the system, local, at day 76, that says %q", name, *got, expiringText(name, owner, shared, "14 days"))
		}
	}

	// A restart of the controller says none of it again, in the events or in the audit log
	h.stop()
	h.start()
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 3})
	after := h.waitAudit(h.api, "the audit log", func([]audit.Record) bool { return true })
	if n := len(announcementsOf(after, event.NodeKeyExpiring)); n != 3 {
		t.Errorf("the audit log holds %d announcements after the restart, want the 3 of before:\n%s", n, auditLines(after))
	}

	// 3 days before the end every node is announced a second time
	clk.Advance(11 * keyDay)
	h.waitEvents(event.NodeKeyExpiring, 6)
	h.checkEventCounts(map[string]int{event.NodeKeyExpiring: 6})
	evs = h.events()
	for name, owner := range keyOwners {
		if got := eventsAbout(evs, event.NodeKeyExpiring, name); len(got) != 2 {
			t.Errorf("the events about %s are %+v, want two of the type %s", name, got, event.NodeKeyExpiring)
		} else {
			checkKeyEvent(t, got[1], event.NodeKeyExpiring, name, owner, first.Add(87*keyDay), expiringText(name, owner, shared, "3 days"))
		}
	}
	h.waitAudit(h.api, "the second announcements", func(rs []audit.Record) bool {
		return len(announcementsOf(rs, event.NodeKeyExpiring)) >= 6
	})
}

// TestNonExpiringIsRefusedOnANodeThatHasAnOwner is the fifth criterion of SDN-56-R1: the Intent refuses the mark on a node that has
// an owner and says that the key of such a node lives by the login of its user, so the mark is no way round the refresh that the
// operator cannot give a device; a node that has no owner takes the mark.
func TestNonExpiringIsRefusedOnANodeThatHasAnOwner(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys.json")
	clk.Advance(91 * keyDay)
	ended := start.Add(90 * keyDay)

	// The key of the device of alice ended. Marking the device nonExpiring and then taking the mark off would give its key another
	// period, which an operator cannot give it (the refresh of a node that has an owner is 409), so the mark is refused
	doc, err := intent.ParseDocument([]byte(`{"resources": [` + keysNode("alice-laptop", keyBranch1, "10.10.0.1", `, "owner": "alice", "nonExpiring": true`) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `Node "alice-laptop": nonExpiring is for a Node that has no owner: the key of a device of User "alice" lives by the login of its User`
	if _, err := h.api.Apply(ctx, doc); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), want) {
		t.Fatalf("marking the device of alice nonExpiring gave %v, want 400 with %q", err, want)
	}
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyExpired || k.NonExpiring || !k.Expires.Equal(ended) {
		t.Errorf("the key of alice-laptop is %+v after the mark was refused, want it as it was, expired on day 90", k)
	}
	if _, err := h.api.RefreshNodeKey(ctx, "alice-laptop"); httpStatus(err) != http.StatusConflict {
		t.Errorf("an operator refreshing the key of alice-laptop gave %v, want 409: its user refreshes it", err)
	}

	// A node that has no owner takes the mark: its key has no end, also one that ended
	h.applyJSON(keysNode("files", keyLab1, "10.10.0.3", `, "nonExpiring": true`))
	if k := h.nodeKeys()["files"]; k.State != controller.KeyValid || !k.NonExpiring || !k.Expires.IsZero() {
		t.Errorf("the key of files is %+v after it was marked nonExpiring, want a valid key with no end", k)
	}
}
