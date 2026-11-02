package controller_test

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// heldOf returns the source groups that are held, as groupsOf gives them.
func heldOf(groups []*controlpb.SourceGroup) string {
	held := ""
	for _, g := range groups {
		if !g.GetHeld() {
			continue
		}
		if held != "" {
			held += ", "
		}
		held += groupsOf([]*controlpb.SourceGroup{g})
	}
	return held
}

// TestSourceGroupsHeld is the hold of the source groups of SDN-87 in the conformance seam. In VRF dc of sourcegroups.json
// gw-1 (tag web, group 3) and db (tag db, group 1) report the Capability tags and judge each other's claims. The tags of
// gw-1 move into [db], whose group ID 1 the state of db gives db alone: db would drop a claim of 1 from gw-1 as an unknown
// group while it runs that state, so a Node that runs ahead of db must not make it. With db away, as a Node that the
// Controller cannot reach, gw-1 gets its next Generation with its group 1 in dc held, and stamps none there, and no other
// until db acknowledges; when db comes back and acknowledges its next Generation, which lets gw-1 assert 1, gw-1 gets the
// Generation after, without the hold. The group generation of gw-1 is the one of the Generation that changed its groups,
// at gw-1 and at db, before and after the release, and each state is the compiled intent with its source groups again.
func TestSourceGroupsHeld(t *testing.T) {
	h := newHarness(t)
	h.apply("sourcegroups.json")
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = groupCaps(true, true)
	gw.start(h)
	gw.update(t)
	h.waitNode("gw-1", 2, true)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = groupCaps(true, false)
	db.start(h)
	db.update(t)
	gw.update(t)
	h.settle(map[string]uint64{"gw-1": 3, "db": 2})

	// db goes away, and the tags of gw-1 move into [db]
	db.halt()
	h.waitNode("db", 2, false)
	res := h.applyJSON(`{"kind": "Node", "name": "gw-1", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["dc"], "tags": ["db"], "vtep": {"address": "10.1.0.1"}, "wireguard": {"endpoint": "gw-1.example.net"}}}`)
	if want := []controller.NodeGeneration{{Name: "db", Generation: 3}, {Name: "gw-1", Generation: 4}, {Name: "lab-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the tags of gw-1 changed %+v, want %+v", res.Nodes, want)
	}
	gw.update(t)
	h.waitNode("gw-1", 4, true)
	groups := stateObject(gw, controlpb.Kind_KIND_NODE, "gw-1").GetNode().GetGroups()
	if got, held := groupsOf(groups), heldOf(groups); got != "30 1/0x1" || held != "30 1/0x1" {
		t.Errorf("while db runs the state before, gw-1 has the groups %q, held %q, want %q held", got, held, "30 1/0x1")
	}
	checkGenerations(t, "while db runs the state before", generationCase{gw, "", "30@4"})

	// db comes back and acknowledges the Generation that lets gw-1 assert 1: the hold goes
	db.start(h)
	db.update(t)
	gw.update(t)
	h.settle(map[string]uint64{"gw-1": 5, "db": 3})
	groups = stateObject(gw, controlpb.Kind_KIND_NODE, "gw-1").GetNode().GetGroups()
	if got, held := groupsOf(groups), heldOf(groups); got != "30 1/0x1" || held != "" {
		t.Errorf("once db acknowledged its Generation, gw-1 has the groups %q, held %q, want %q held nowhere", got, held, "30 1/0x1")
	}
	if got := groupsOf(stateObject(db, controlpb.Kind_KIND_PEER, "gw-1").GetPeer().GetGroups()); got != "30 1/0x1" {
		t.Errorf("the Peer gw-1 of db has the groups %q, want %q", got, "30 1/0x1")
	}
	checkGenerations(t, "once db acknowledged its Generation", generationCase{gw, "", "30@4"}, generationCase{db, "gw-1", "30@4"},
		generationCase{db, "", "30@2"}, generationCase{gw, "db", "30@2"})
	h.checkGroupState(gw, "gw-1", "db")
	h.checkGroupState(db, "gw-1", "db")
}
