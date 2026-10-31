// Controller conformance for the export and the import of the intent and for the backup and the
// restore of the store (SDN-52 #245), with the harness and the node simulator of
// conformance_test.go.
package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestExportImportReproducesTheCompiledState is the first criterion of SDN-52 (#245): the intent
// exported from a controller, in JSON and in YAML, and imported into an empty controller is the
// same intent there and compiles to the same desired state: each simulated node receives from the
// new controller the state that it receives from the first one.
func TestExportImportReproducesTheCompiledState(t *testing.T) {
	ctx := context.Background()
	from := newHarness(t)
	from.apply("apply1.json")
	from.apply("apply2.json")
	from.apply("controllers1.json")
	simKeys := map[string]keys.Static{"branch-1": keyBranch1, "branch-2": keyBranch2}
	want := map[string]desired.State{}
	for name, key := range simKeys {
		s := from.sim(name, key)
		s.update(t)
		_, want[name] = s.State()
	}

	doc, err := from.api.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	y, err := doc.YAML()
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := intent.ParseDocument(y)
	if err != nil {
		t.Fatalf("the YAML export does not read back: %v\n%s", err, y)
	}
	for format, d := range map[string]intent.Document{"JSON": doc, "YAML": fromYAML} {
		to := newHarness(t)
		res, err := to.api.Import(ctx, d)
		if err != nil {
			t.Fatalf("importing the %s export: %v", format, err)
		}
		changed := []controller.NodeGeneration{{Name: "branch-1", Generation: 1}, {Name: "branch-2", Generation: 1}}
		if res.Revision != 1 || !equalGenerations(res.Nodes, changed) {
			t.Errorf("the import of the %s export made revision %d and changed %+v, want revision 1 and %+v", format, res.Revision, res.Nodes, changed)
		}
		if a, b := to.resources(), from.resources(); a != b {
			t.Errorf("the intent imported from the %s export differs:\n--- imported\n%s\n--- exported\n%s", format, a, b)
		}
		if got := to.revisionLog(); got != "1 import\n" {
			t.Errorf("after the import of the %s export the revisions are\n%s", format, got)
		}
		for name, key := range simKeys {
			s := to.sim(name, key)
			s.update(t)
			to.waitNode(name, 1, true)
			to.checkState(s)
			if gen, got := s.State(); !desired.Equal(got, want[name]) {
				t.Errorf("%s: the state imported from the %s export differs from the exporting controller's:\n--- imported\n%s\n--- exported\n%s",
					name, format, show(desired.Full(got, gen)), show(desired.Full(want[name], gen)))
			}
		}
	}
}

// An import makes its document the whole intent as the next revision: the resources it leaves
// out are deleted, so the node of a deleted Node resource is refused, and a VRF keeps the id and
// the ULA that the document leaves out. A document that cannot be applied is refused as an apply
// is, and changes nothing.
func TestImportReplacesTheIntent(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.apply("apply-relay.json")
	b2 := h.sim("branch-2", keyBranch2)
	b2.update(t)
	h.waitNode("branch-2", 1, true)

	doc := h.document("apply1.json")
	doc.Resources = append(doc.Resources, intent.Resource{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{}`)})
	res, err := h.api.Import(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 2 {
		t.Errorf("the import made revision %d, want 2", res.Revision)
	}
	whole := h.document("apply1.json")
	whole.Resources = append(whole.Resources, intent.Resource{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 20, "ula": "fd12:3456:789b::/48"}`)})
	in, err := intent.Apply(intent.New(), whole, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(in.Resources(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.resources(); got != string(b) {
		t.Errorf("after the import the intent is\n%s\nwant\n%s", got, b)
	}
	if r := b2.refusal(t).GetRefuse(); r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE {
		t.Errorf("branch-2, which the import deleted, was refused with %v %q", r.GetReason(), r.GetMessage())
	}

	before := h.resources()
	bad := intent.Document{Resources: []intent.Resource{{Kind: intent.KindNetwork, Name: "lan", Spec: json.RawMessage(`{"vrf": "nowhere"}`)}}}
	_, err = h.api.Import(ctx, bad)
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest || !strings.Contains(err.Error(), `Network "lan": VRF "nowhere" does not exist`) {
		t.Errorf("an import of a Network without its VRF: %v", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused import changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if got, want := h.revisionLog(), "1 apply\n2 import\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
}

// TestBackupRestoreBringsBackTheIntentAndRevisions is the second criterion of SDN-52 (#245): a
// backup of the store, restored into the store of another controller (one with an intent of its
// own) on the host of the first, brings back the intent, every revision, the generation of each
// node and the Capabilities it reported. The node goes on from the generation it acknowledged
// before the backup: the next change reaches it as a delta from there.
func TestBackupRestoreBringsBackTheIntentAndRevisions(t *testing.T) {
	rqlitetest.Own(t) // it restores a backup into rqlited
	ctx := context.Background()
	from := newHarness(t)
	from.apply("apply1.json")
	b1 := from.sim("branch-1", keyBranch1)
	b1.update(t)
	from.waitNode("branch-1", 1, true)
	from.apply("apply2.json")
	b1.update(t)
	from.waitNode("branch-1", 2, true)
	if _, err := from.api.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	b1.update(t)
	from.waitNode("branch-1", 3, true)
	var backup bytes.Buffer
	if err := from.st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	resources := from.resources()
	revisions, err := from.api.Revisions(ctx)
	if err != nil {
		t.Fatal(err)
	}

	to := newHarness(t)
	to.apply("apply-relay.json")
	to.stop()
	st, err := store.Open(ctx, to.rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.Restore(ctx, st, backup.Bytes(), time.Second); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// The controller of the host: its keys are in its data directory, not in the store. The
	// tokens are in the store, so the admin token is the one of the first controller.
	to.key, to.admin = from.key, from.admin
	to.start()

	if got := to.resources(); got != resources {
		t.Errorf("the restored intent differs:\n--- restored\n%s\n--- backed up\n%s", got, resources)
	}
	restored, err := to.api.Revisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := asJSON(t, restored), asJSON(t, revisions); a != b {
		t.Errorf("the restored revisions are %s, want %s", a, b)
	}
	nodes, err := to.api.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []controller.NodeStatus{{Name: "branch-1", Generation: 3, AckedGeneration: 3, Capabilities: capability.FromProto(capsServer)}}
	if a, b := asJSON(t, nodes), asJSON(t, want); a != b {
		t.Errorf("the restored nodes are %s, want %s", a, b)
	}

	b1.halt()
	b1.start(to)
	to.waitNode("branch-1", 3, true)
	if res := to.apply("apply3.json"); res.Revision != 4 {
		t.Errorf("the first apply after the restore made revision %d, want 4", res.Revision)
	}
	if u := b1.update(t).GetUpdate(); u.GetGeneration() != 4 || u.GetBaseGeneration() != 3 {
		t.Errorf("after the restore branch-1 received generation %d on base %d, want 4 on base 3", u.GetGeneration(), u.GetBaseGeneration())
	}
	to.waitNode("branch-1", 4, true)
	to.checkState(b1)
	if got, want := to.revisionLog(), "1 apply\n2 apply\n3 rollback restores 1\n4 apply\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
}
