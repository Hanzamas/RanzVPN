// Controller conformance for revisions, diff, rollback and apply --confirm (SDN-13 #189,
// ADR-0031), with the harness and the node simulator of conformance_test.go.
package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// TestEveryApplyIsARevision is the first criterion of #189: each apply, and each delete, makes
// the next revision, which the API lists and which holds the intent it made.
func TestEveryApplyIsARevision(t *testing.T) {
	h := newHarness(t)
	if res := h.apply("apply1.json"); res.Revision != 1 {
		t.Errorf("apply1.json made revision %d, want 1", res.Revision)
	}
	after1 := h.resources()
	if res := h.apply("apply2.json"); res.Revision != 2 {
		t.Errorf("apply2.json made revision %d, want 2", res.Revision)
	}
	res, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-dmz")
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 3 {
		t.Errorf("the delete made revision %d, want 3", res.Revision)
	}
	if got, want := h.revisionLog(), "1 apply\n2 apply\n3 delete\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	if got := h.revisionResources(1); got != after1 {
		t.Errorf("revision 1 holds\n%s\nwant the intent after apply1.json\n%s", got, after1)
	}
	if got, want := h.revisionResources(3), h.resources(); got != want {
		t.Errorf("revision 3, the latest, holds\n%s\nwant the intent\n%s", got, want)
	}
	revs, err := h.api.Revisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range revs {
		if r.Time.IsZero() || len(r.Resources) != 0 {
			t.Errorf("revision %d in the list has the time %v and %d resources, want a time and no resources", r.ID, r.Time, len(r.Resources))
		}
	}
	if _, err := h.api.Revision(context.Background(), 4); err == nil || !strings.Contains(err.Error(), "no such revision") {
		t.Errorf("reading revision 4, which does not exist: %v", err)
	}
}

// TestDiffShowsResourceChanges is the second criterion of #189: the diff between two revisions
// names each resource that was added, removed or changed, with the fields that changed and the
// spec before and after.
func TestDiffShowsResourceChanges(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	h.apply("apply2.json")
	if _, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-lan"); err != nil {
		t.Fatal(err)
	}
	h.goldenDiff("diff-1-3", 1, 3)

	// Without revisions, the change of the latest one; from the empty revision 0, every
	// resource is added; and the way back is the other way round.
	h.checkDiff([]uint64{}, "2 3: removed Network corp-lan")
	h.checkDiff([]uint64{0, 1}, "0 1: added VRF corp, added Network corp-lan, added Node branch-1")
	h.checkDiff([]uint64{3, 1}, "3 1: changed VRF corp [mtu], removed Network corp-dmz, added Network corp-lan, removed Node branch-2")
	h.checkDiff([]uint64{2, 2}, "2 2: ")
	if _, err := h.api.Diff(context.Background(), 1, 4); err == nil || !strings.Contains(err.Error(), "no such revision") {
		t.Errorf("a diff to revision 4, which does not exist: %v", err)
	}
}

// TestRollbackRestoresRevision is the third criterion of #189: a rollback makes the intent of an
// earlier revision the intent again, as a new revision, and the node receives the generation
// that the intent of that revision compiles to.
func TestRollbackRestoresRevision(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	after1 := h.resources()
	h.apply("apply2.json")
	golden(t, "apply2-branch-1", b1.update(t))
	h.waitNode("branch-1", 2, true)

	res, err := h.api.Rollback(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 3}}; res.Revision != 3 || !equalGenerations(res.Nodes, want) {
		t.Errorf("the rollback made revision %d and changed %+v, want revision 3 and %+v", res.Revision, res.Nodes, want)
	}
	golden(t, "rollback-branch-1", b1.update(t))
	h.waitNode("branch-1", 3, true)
	h.checkState(b1)
	h.checkRevisionState(b1, 1)
	if after := h.resources(); after != after1 {
		t.Errorf("the intent after the rollback is\n%s\nwant the one of revision 1\n%s", after, after1)
	}
	if got, want := h.revisionLog(), "1 apply\n2 apply\n3 rollback restores 1\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	h.checkDiff([]uint64{1, 3}, "1 3: ")

	// A rollback is a revision like any other, so it can be rolled back too. branch-2, whose
	// Node resource the first rollback deleted, comes back with a new state at generation 1.
	res, err = h.api.Rollback(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 4}, {Name: "branch-2", Generation: 1}}; res.Revision != 4 || !equalGenerations(res.Nodes, want) {
		t.Errorf("the rollback to revision 2 made revision %d and changed %+v, want revision 4 and %+v", res.Revision, res.Nodes, want)
	}
	b1.update(t)
	h.waitNode("branch-1", 4, true)
	h.checkRevisionState(b1, 2)

	if _, err := h.api.Rollback(context.Background(), 9); err == nil || !strings.Contains(err.Error(), "no such revision") {
		t.Errorf("a rollback to revision 9, which does not exist: %v", err)
	}
}

// TestUnconfirmedApplyRollsBack is the fourth criterion of #189: an apply with a confirmation
// time that nobody confirms is rolled back by the controller once that time is up, the node
// receives the generation of the revision before it, and the rollback raises an event.
func TestUnconfirmedApplyRollsBack(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	before := h.resources()

	const confirm = 3 * time.Second
	start := time.Now()
	res := h.applyConfirm("apply3.json", confirm)
	if res.Revision != 2 || res.ConfirmBy.IsZero() {
		t.Errorf("apply3.json with a confirmation time made revision %d with the deadline %v, want revision 2 with a deadline", res.Revision, res.ConfirmBy)
	}
	golden(t, "confirm-branch-1", b1.update(t))
	if got, want := h.revisionLog(), "1 apply\n2 apply confirm pending\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	// While revision 2 waits, the controller takes no other change but a rollback.
	if _, err := h.api.Apply(context.Background(), h.document("apply2.json")); err == nil || !strings.Contains(err.Error(), "revision 2 waits for confirmation") {
		t.Errorf("an apply while revision 2 waits for confirmation: %v", err)
	}
	if _, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-lan"); err == nil || !strings.Contains(err.Error(), "revision 2 waits for confirmation") {
		t.Errorf("a delete while revision 2 waits for confirmation: %v", err)
	}

	golden(t, "auto-rollback-branch-1", b1.update(t))
	if elapsed := time.Since(start); elapsed < confirm {
		t.Errorf("the automatic rollback came %v after the apply, before its confirmation time of %v", elapsed, confirm)
	}
	h.waitNode("branch-1", 3, true)
	h.checkState(b1)
	h.checkRevisionState(b1, 1)
	if after := h.resources(); after != before {
		t.Errorf("the intent after the automatic rollback is\n%s\nwant the one before the apply\n%s", after, before)
	}
	if got, want := h.revisionLog(), "1 apply\n2 apply confirm rolled-back\n3 automatic-rollback restores 1 reverts 2\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	h.checkAutomaticRollback(3, 2)

	// The controller takes changes again.
	if res := h.apply("apply2.json"); res.Revision != 4 {
		t.Errorf("apply2.json after the automatic rollback made revision %d, want 4", res.Revision)
	}
}

// TestConfirmedApplyStays checks that a confirmed apply stays after its confirmation time, and
// that only a revision that waits for confirmation can be confirmed.
func TestConfirmedApplyStays(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)

	const confirm = time.Second
	res := h.applyConfirm("apply3.json", confirm)
	golden(t, "confirm-branch-1", b1.update(t))
	rev, err := h.api.Confirm(context.Background(), res.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if rev.ID != 2 || rev.Confirm == nil || rev.Confirm.State != intent.ConfirmConfirmed {
		t.Errorf("the confirmation answered %+v, want revision 2 confirmed", rev)
	}
	select {
	case u := <-b1.Updates:
		t.Errorf("branch-1 received generation %d after the confirmation", u.GetGeneration())
	case <-time.After(confirm + time.Second):
	}
	h.waitNode("branch-1", 2, true)
	if got, want := h.revisionLog(), "1 apply\n2 apply confirm confirmed\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	if evs := h.events(); len(evs) != 0 {
		t.Errorf("a confirmed apply raised the events %+v", evs)
	}
	if _, err := h.api.Confirm(context.Background(), 2); err == nil || !strings.Contains(err.Error(), "revision 2 does not wait for confirmation (confirmed)") {
		t.Errorf("confirming revision 2 again: %v", err)
	}
	if _, err := h.api.Confirm(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "revision 1 does not wait for confirmation (no confirmation time)") {
		t.Errorf("confirming revision 1, an apply without a confirmation time: %v", err)
	}
	if _, err := h.api.ApplyConfirm(context.Background(), h.document("apply2.json"), time.Millisecond); err == nil || !strings.Contains(err.Error(), "is not between") {
		t.Errorf("an apply with a confirmation time of 1ms: %v", err)
	}
}

// TestRollbackCancelsConfirmation checks that a rollback while a revision waits for
// confirmation ends the wait: the controller does not roll back a second time at the deadline,
// and raises no event.
func TestRollbackCancelsConfirmation(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	const confirm = time.Second
	h.applyConfirm("apply3.json", confirm)
	res, err := h.api.Rollback(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 3 {
		t.Errorf("the rollback made revision %d, want 3", res.Revision)
	}
	time.Sleep(confirm + time.Second)
	if got, want := h.revisionLog(), "1 apply\n2 apply confirm cancelled\n3 rollback restores 1\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	if evs := h.events(); len(evs) != 0 {
		t.Errorf("a cancelled confirmation raised the events %+v", evs)
	}
}

// TestConfirmationSurvivesRestart checks that the wait for a confirmation survives a restart of
// the controller: the restarted controller rolls the apply back at its deadline.
func TestConfirmationSurvivesRestart(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.applyConfirm("apply3.json", 3*time.Second)
	golden(t, "confirm-branch-1", b1.update(t))
	h.waitNode("branch-1", 2, true)

	h.stop()
	if err := b1.end(t); err == nil {
		t.Error("the stream of branch-1 ended without an error when the controller stopped")
	}
	h.start()
	b1.start(h)
	golden(t, "auto-rollback-branch-1", b1.update(t))
	h.waitNode("branch-1", 3, true)
	h.checkRevisionState(b1, 1)
	if got, want := h.revisionLog(), "1 apply\n2 apply confirm rolled-back\n3 automatic-rollback restores 1 reverts 2\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	h.checkAutomaticRollback(3, 2)
}

// applyConfirm applies testdata/file with a confirmation time, as `ranz apply -f file --confirm`.
func (h *harness) applyConfirm(file string, confirm time.Duration) controller.ApplyResult {
	h.t.Helper()
	res, err := h.api.ApplyConfirm(context.Background(), h.document(file), confirm)
	if err != nil {
		h.t.Fatalf("applying %s with a confirmation time of %v: %v", file, confirm, err)
	}
	return res
}

// revisionLog returns the revisions as the API lists them, one line each: the number, the
// operation, the revision it restores and the one it reverts, and the state of its
// confirmation.
func (h *harness) revisionLog() string {
	h.t.Helper()
	revs, err := h.api.Revisions(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range revs {
		fmt.Fprintf(&b, "%d %s", r.ID, r.Operation)
		if r.Restores != nil {
			fmt.Fprintf(&b, " restores %d", *r.Restores)
		}
		if r.Reverts != 0 {
			fmt.Fprintf(&b, " reverts %d", r.Reverts)
		}
		if r.Confirm != nil {
			fmt.Fprintf(&b, " confirm %s", r.Confirm.State)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// revisionResources returns the intent of revision id as the API reports it, as JSON in the form
// of resources.
func (h *harness) revisionResources(id uint64) string {
	h.t.Helper()
	r, err := h.api.Revision(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	if r.ID != id {
		h.t.Errorf("reading revision %d answered revision %d", id, r.ID)
	}
	b, err := json.MarshalIndent(r.Resources, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

// checkRevisionState checks that the state the simulated node built from its updates is the
// state that the intent of revision id compiles to for it.
func (h *harness) checkRevisionState(s *sim, id uint64) {
	h.t.Helper()
	r, err := h.api.Revision(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	in, err := intent.FromResources(r.Resources)
	if err != nil {
		h.t.Fatal(err)
	}
	states, err := desired.Compile(in)
	if err != nil {
		h.t.Fatal(err)
	}
	gen, got := s.State()
	if want := states[s.name]; !desired.Equal(got, want) {
		h.t.Errorf("%s: the state at generation %d differs from the intent of revision %d:\n--- node\n%s\n--- revision %d\n%s",
			s.name, gen, id, show(desired.Full(got, gen)), id, show(desired.Full(want, gen)))
	}
}

// checkDiff checks the diff of the revisions given (none, from, or from and to) against want:
// "FROM TO: " followed by the action, kind and name of each change, and the changed fields.
func (h *harness) checkDiff(revisions []uint64, want string) {
	h.t.Helper()
	d, err := h.api.Diff(context.Background(), revisions...)
	if err != nil {
		h.t.Fatal(err)
	}
	var changes []string
	for _, c := range d.Changes {
		s := c.Action + " " + c.Kind + " " + c.Name
		if len(c.Fields) > 0 {
			s += " [" + strings.Join(c.Fields, " ") + "]"
		}
		changes = append(changes, s)
	}
	if got := fmt.Sprintf("%d %d: %s", d.From, d.To, strings.Join(changes, ", ")); got != want {
		h.t.Errorf("the diff of %v is %q, want %q", revisions, got, want)
	}
}

// goldenDiff compares the diff from revision from to revision to with testdata/<name>.json,
// compared as JSON, or writes it there under -update.
func (h *harness) goldenDiff(name string, from, to uint64) {
	h.t.Helper()
	d, err := h.api.Diff(context.Background(), from, to)
	if err != nil {
		h.t.Fatal(err)
	}
	path := filepath.Join("testdata", name+".json")
	if *rewrite {
		b, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			h.t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	var want api.DiffResult
	if err := json.Unmarshal(b, &want); err != nil {
		h.t.Fatalf("%s: %v", path, err)
	}
	// Marshal writes both in one form, whatever the spacing of their specs.
	got, err := json.Marshal(d)
	if err != nil {
		h.t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		h.t.Fatal(err)
	}
	if string(got) != string(wantJSON) {
		h.t.Errorf("%s: the diff differs from the golden file\n--- got\n%s\n--- want\n%s", path, got, wantJSON)
	}
}

// events returns the events as the API lists them.
func (h *harness) events() []event.Event {
	h.t.Helper()
	evs, err := h.api.Events(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return evs
}

// checkAutomaticRollback checks that the only event is the automatic rollback of revision
// reverts by revision rev.
func (h *harness) checkAutomaticRollback(rev, reverts uint64) {
	h.t.Helper()
	evs := h.events()
	want := fmt.Sprintf("revision %d was not confirmed by ", reverts)
	if len(evs) != 1 || evs[0].Type != event.AutomaticRollback || evs[0].Revision != rev || evs[0].Reverts != reverts ||
		!strings.HasPrefix(evs[0].Message, want) || evs[0].ID == 0 || evs[0].Time.IsZero() {
		h.t.Errorf("the events are %+v, want one %s event of revision %d that reverts revision %d, with a message that starts %q",
			evs, event.AutomaticRollback, rev, reverts, want)
	}
}
