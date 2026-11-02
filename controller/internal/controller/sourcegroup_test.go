// The source groups in the controller conformance seam (SDN-87 #386): the Controller numbers the groups of a VRF
// from the tags of its endpoints, gives each Node that reports the Capability tags its own group in each VRF, the
// group of each Device, and of each peer that reports it too the groups that the peer may assert and the frame version
// of the records that carry them; the tag mode of the Networks of a VRF reaches every Node in its Vrf object; a Node
// that starts or stops reporting the Capability changes the states of its peers in the Generation of its Hello; a
// Node without the Capability keeps the state that the intent compiles to without source groups, and its peers send
// it no record of frame version 1; and the counters by tag mode that a node reports reach the export.
package controller_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// groupCaps returns capsServer with the Capability plainLinks, which the VRF dc of sourcegroups.json needs, with tags
// when tags is set, and with wireguard and the key of a WireGuard interface for gw-1, the gateway of Device phone.
func groupCaps(tags, wireguard bool) *controlpb.Capabilities {
	c := proto.Clone(capsServer).(*controlpb.Capabilities)
	c.PlainLinks = true
	c.Tags = tags
	if wireguard {
		c.Wireguard = true
		c.WireguardKey = []byte(strings.Repeat("\x11", 32))
	}
	return c
}

// groupsOf returns the source groups as text, "vrf group/tagset" each, by commas.
func groupsOf(groups []*controlpb.SourceGroup) string {
	var parts []string
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("%d %d/%#x", g.GetVrfId(), g.GetGroup(), g.GetTagSet()))
	}
	return strings.Join(parts, ", ")
}

// generationsOf returns the group generations of the source groups as text, "vrf@generation" each, by commas.
func generationsOf(groups []*controlpb.SourceGroup) string {
	var parts []string
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("%d@%d", g.GetVrfId(), g.GetGeneration()))
	}
	return strings.Join(parts, ", ")
}

// generationCase is the group generations that a simulated node holds, as generationsOf gives them: of its NodeConfig
// when peer is empty, of its Peer object peer otherwise.
type generationCase struct {
	node       *sim
	peer, want string
}

// checkGenerations checks the group generations of each case.
func checkGenerations(t *testing.T, when string, cases ...generationCase) {
	t.Helper()
	for _, c := range cases {
		what := "the group generations of " + c.node.name
		groups := stateObject(c.node, controlpb.Kind_KIND_NODE, c.node.name).GetNode().GetGroups()
		if c.peer != "" {
			what = "the group generations of the Peer " + c.peer + " of " + c.node.name
			groups = stateObject(c.node, controlpb.Kind_KIND_PEER, c.peer).GetPeer().GetGroups()
		}
		if got := generationsOf(groups); got != c.want {
			t.Errorf("%s: %s are %q, want %q", when, what, got, c.want)
		}
	}
}

// stateObject returns the object of kind and name of the state that the simulated node s built, nil for none.
func stateObject(s *sim, kind controlpb.Kind, name string) *controlpb.Object {
	_, st := s.State()
	return st[desired.Key{Kind: kind, Name: name}]
}

// storedNumbers returns the numbers of the source groups that the store of the controller holds.
func (h *harness) storedNumbers() desired.GroupNumbers {
	h.t.Helper()
	stored, err := h.st.SourceGroups(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	out := desired.GroupNumbers{}
	for id, v := range stored {
		out[id] = desired.VrfGroupNumbers{Groups: v.Groups, Bits: v.Bits}
	}
	return out
}

// checkGroupState checks that the state that the simulated node s built is the full state that the intent of the
// controller compiles to for it, with the source groups of the Nodes tagged by the numbers that the store holds. The
// group generations come from the Generations that the states had (checkGenerations), so this leaves them out.
func (h *harness) checkGroupState(s *sim, tagged ...string) {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		h.t.Fatal(err)
	}
	lic, err := h.api.Licence(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	capped := in.Capped(lic.Nodes)
	states, err := desired.Compile(capped)
	if err != nil {
		h.t.Fatal(err)
	}
	desired.SourceGroups(capped, states, h.storedNumbers(), func(node string) bool { return slices.Contains(tagged, node) })
	gen, got := s.State()
	got = maps.Clone(got)
	desired.WithGroupGenerations(map[string]desired.State{s.name: got}, nil)
	if want := states[s.name]; !desired.Equal(got, want) {
		h.t.Errorf("%s: the state at generation %d differs from the compiled intent with the source groups of %v:\n--- node\n%s\n--- intent\n%s",
			s.name, gen, tagged, show(desired.Full(got, gen)), show(desired.Full(want, gen)))
	}
}

// TestSourceGroupsReachTheNodes is the sixth criterion of SDN-87: in VRF dc the groups are db 1, ops 2 (Device phone)
// and web 3 (gw-1 and lab-1, one group), and the tags db, ops and web are the bits 0, 1 and 2 of the tag set. gw-1 and
// db report the Capability tags and lab-1 does not: gw-1 and db get their groups, the group of phone and each other's
// groups with the frame version 1, and lab-1 gets the state that the intent compiles to without source groups, which
// its peers send records of frame version 0. When lab-1 reports the Capability, its Hello gives it and its peers the
// next Generation with its groups; when it stops, the next one takes them away. The Network setting reaches every
// Node in its Vrf object, and turning it off is one Generation of each Node of the VRF.
func TestSourceGroupsReachTheNodes(t *testing.T) {
	h := newHarness(t)
	res := h.apply("sourcegroups.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 1}, {Name: "gw-1", Generation: 1}, {Name: "lab-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("sourcegroups.json changed %+v, want %+v", res.Nodes, want)
	}

	// gw-1 reports the Capability tags: its Hello gives it the next Generation, with its groups; its peers report none yet
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = groupCaps(true, true)
	gw.start(h)
	m := gw.update(t)
	if got := m.GetUpdate().GetGeneration(); got != 2 {
		t.Errorf("gw-1, which reports the Capability tags, got generation %d first, want 2", got)
	}
	if n := nodeObject(m); groupsOf(n.GetGroups()) != "30 3/0x4" {
		t.Errorf("the NodeConfig of gw-1 has the groups %q, want 30 3/0x4", groupsOf(n.GetGroups()))
	}
	h.waitNode("gw-1", 2, true)
	h.checkGroupState(gw, "gw-1")
	if p := stateObject(gw, controlpb.Kind_KIND_PEER, "db").GetPeer(); len(p.GetGroups()) != 0 || p.GetFrameVersion() != 0 {
		t.Errorf("the Peer db of gw-1, before db reports the Capability tags, is %v", p)
	}

	// db reports it too: db gets its groups and those of gw-1, and gw-1 those of db, each with the frame version 1
	db := h.newSim("db", keyBranch2)
	db.Capabilities = groupCaps(true, false)
	db.start(h)
	if got := db.update(t).GetUpdate().GetGeneration(); got != 2 {
		t.Errorf("db got generation %d first, want 2", got)
	}
	if m := gw.update(t); m.GetUpdate().GetGeneration() != 3 || peerObject(m, "db") == nil {
		t.Errorf("the update of gw-1 when db reported the Capability tags is %v, want generation 3 with the Peer db", show(m))
	}
	h.waitNode("gw-1", 3, true)
	h.waitNode("db", 2, true)

	// lab-1 does not report it: it keeps the state of generation 1 without source groups, and neither peer changes
	lab := h.newSim("lab-1", keyLab1)
	lab.Capabilities = groupCaps(false, false)
	lab.start(h)
	if got := lab.update(t).GetUpdate().GetGeneration(); got != 1 {
		t.Errorf("lab-1, which does not report the Capability tags, got generation %d, want 1", got)
	}
	h.waitNode("lab-1", 1, true)
	h.waitNode("gw-1", 3, true)
	h.waitNode("db", 2, true)
	h.checkState(lab)
	h.checkGroupState(gw, "gw-1", "db")
	h.checkGroupState(db, "gw-1", "db")

	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of gw-1", groupsOf(stateObject(gw, controlpb.Kind_KIND_NODE, "gw-1").GetNode().GetGroups()), "30 3/0x4"},
		{"the groups of db", groupsOf(stateObject(db, controlpb.Kind_KIND_NODE, "db").GetNode().GetGroups()), "30 1/0x1"},
		{"the groups of lab-1", groupsOf(stateObject(lab, controlpb.Kind_KIND_NODE, "lab-1").GetNode().GetGroups()), ""},
		{"the Peer db of gw-1", groupsOf(stateObject(gw, controlpb.Kind_KIND_PEER, "db").GetPeer().GetGroups()), "30 1/0x1"},
		{"the Peer gw-1 of db", groupsOf(stateObject(db, controlpb.Kind_KIND_PEER, "gw-1").GetPeer().GetGroups()), "30 3/0x4"},
		{"the Peer lab-1 of gw-1", groupsOf(stateObject(gw, controlpb.Kind_KIND_PEER, "lab-1").GetPeer().GetGroups()), ""},
		{"the Peer gw-1 of lab-1", groupsOf(stateObject(lab, controlpb.Kind_KIND_PEER, "gw-1").GetPeer().GetGroups()), ""},
	} {
		if c.got != c.want {
			t.Errorf("%s are %q, want %q", c.what, c.got, c.want)
		}
	}
	for _, c := range []struct {
		node *sim
		peer string
		want uint32
	}{{gw, "db", 1}, {db, "gw-1", 1}, {gw, "lab-1", 0}, {db, "lab-1", 0}, {lab, "gw-1", 0}} {
		if got := stateObject(c.node, controlpb.Kind_KIND_PEER, c.peer).GetPeer().GetFrameVersion(); got != c.want {
			t.Errorf("the Peer %s of %s has the frame version %d, want %d", c.peer, c.node.name, got, c.want)
		}
	}
	for _, s := range []*sim{gw, db} {
		if d := stateObject(s, controlpb.Kind_KIND_DEVICE, "phone").GetDevice(); d.GetGroup() != 2 || d.GetTagSet() != 0x2 {
			t.Errorf("Device phone at %s has the group %d and the tag set %#x, want 2 and 0x2", s.name, d.GetGroup(), d.GetTagSet())
		}
	}
	if d := stateObject(lab, controlpb.Kind_KIND_DEVICE, "phone").GetDevice(); d.GetGroup() != 0 || d.GetTagSet() != 0 {
		t.Errorf("Device phone at lab-1, which does not report the Capability tags, has the group %d and the tag set %#x", d.GetGroup(), d.GetTagSet())
	}
	// Each group carries the group generation of its node, which its claims name: the Generation 2 of the Hello that gave
	// gw-1 and db their groups, at the node and in its Peer object at the other. The Peer db gave gw-1 its Generation 3,
	// which changed nothing that gw-1 may assert, its group web and the group ops of phone, so its group generation stays.
	checkGenerations(t, "gw-1 and db report the Capability tags",
		generationCase{gw, "", "30@2"}, generationCase{db, "", "30@2"}, generationCase{gw, "db", "30@2"}, generationCase{db, "gw-1", "30@2"})
	for _, s := range []*sim{gw, db, lab} {
		if mode := stateObject(s, controlpb.Kind_KIND_VRF, "dc").GetVrf().GetTagMode(); mode != controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY {
			t.Errorf("the Vrf dc of %s has the tag mode %v, want trusted-underlay", s.name, mode)
		}
	}

	// lab-1 reports the Capability tags from its next Hello on: it and both peers get the next Generation
	lab.halt()
	lab.Capabilities = groupCaps(true, false)
	lab.start(h)
	if got := lab.update(t).GetUpdate().GetGeneration(); got != 2 {
		t.Errorf("lab-1, once it reports the Capability tags, got generation %d, want 2", got)
	}
	gw.update(t)
	db.update(t)
	h.waitNode("lab-1", 2, true)
	h.waitNode("gw-1", 4, true)
	h.waitNode("db", 3, true)
	h.checkGroupState(gw, "gw-1", "db", "lab-1")
	h.checkGroupState(db, "gw-1", "db", "lab-1")
	h.checkGroupState(lab, "gw-1", "db", "lab-1")
	if p := stateObject(gw, controlpb.Kind_KIND_PEER, "lab-1").GetPeer(); groupsOf(p.GetGroups()) != "30 3/0x4" || p.GetFrameVersion() != 1 {
		t.Errorf("the Peer lab-1 of gw-1, once lab-1 reports the Capability tags, is %v", p)
	}
	// lab-1 may assert its group from its Generation 2 on; gw-1 and db, whose Generations went on, still assert what they did
	checkGenerations(t, "lab-1 reports the Capability tags",
		generationCase{lab, "", "30@2"}, generationCase{gw, "lab-1", "30@2"}, generationCase{db, "lab-1", "30@2"},
		generationCase{gw, "", "30@2"}, generationCase{lab, "gw-1", "30@2"}, generationCase{lab, "db", "30@2"})

	// ... and when it stops, the next Generation takes its groups away again
	lab.halt()
	lab.Capabilities = groupCaps(false, false)
	lab.start(h)
	if got := lab.update(t).GetUpdate().GetGeneration(); got != 3 {
		t.Errorf("lab-1, once it stops reporting the Capability tags, got generation %d, want 3", got)
	}
	gw.update(t)
	db.update(t)
	h.waitNode("lab-1", 3, true)
	h.waitNode("gw-1", 5, true)
	h.waitNode("db", 4, true)
	h.checkState(lab)
	h.checkGroupState(gw, "gw-1", "db")

	// The Network setting off is one Generation of each Node of the VRF, whose Vrf object carries no tag mode
	res = h.apply("sourcegroups-off.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 5}, {Name: "gw-1", Generation: 6}, {Name: "lab-1", Generation: 4}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("sourcegroups-off.json changed %+v, want %+v", res.Nodes, want)
	}
	for _, s := range []*sim{gw, db, lab} {
		m := s.update(t)
		if v := vrfObject(m, "dc"); v == nil || v.GetTagMode() != controlpb.TagMode_TAG_MODE_UNSPECIFIED {
			t.Errorf("the update of %s for the tag mode off has the Vrf dc %v", s.name, v)
		}
	}
	h.waitNode("gw-1", 6, true)
	h.waitNode("db", 5, true)
	h.waitNode("lab-1", 4, true)
	h.checkGroupState(gw, "gw-1", "db")
	h.checkGroupState(db, "gw-1", "db")
}

// TestSourceGroupNumbersStay is the stable numbering of SDN-87 in the conformance seam. In VRF dc of sourcegroups.json the
// sets of tags are numbered [db] 1, [ops] 2 (Device phone) and [web] 3 (gw-1 and lab-1), and the tags db, ops and web are
// the bits 0, 1 and 2. Deleting Device phone retires [ops] and ops: gw-1 and db get their next Generation without phone,
// and their groups keep their numbers, db 1/0x1 and web 3/0x4, where numbers by rank would make web 2/0x2, which a Node
// that still holds phone reads as ops. The store keeps the retired numbers: a restart of the controller and of rqlite gives
// no Node a Generation, and a new Device tablet with the tag admin takes the group ID 4 and the bit 3, never the retired 2
// and 1. Each state is the compiled intent with the numbers that the store holds.
//
// The group generations follow what each node may assert. gw-1, the gateway of phone and then of tablet, may assert other
// groups from its Generation 4, which deletes phone, and from its Generation 5, which brings tablet: a claim of gw-1 names
// the group generation 2, 4 or 5, and a node that holds another one for gw-1 ignores the claim of a group that its state
// does not let gw-1 assert instead of dropping it as an unknown group. db asserts its group db alone from its Generation 2
// on, whatever goes, so its group generation stays 2.
func TestSourceGroupNumbersStay(t *testing.T) {
	const tabletKey = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	rqlitetest.Own(t) // it restarts rqlited
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

	// The groups of gw-1 and db, which keep their numbers whatever goes
	check := func(when string) {
		t.Helper()
		for _, c := range []struct {
			what, got, want string
		}{
			{"the groups of gw-1", groupsOf(stateObject(gw, controlpb.Kind_KIND_NODE, "gw-1").GetNode().GetGroups()), "30 3/0x4"},
			{"the groups of db", groupsOf(stateObject(db, controlpb.Kind_KIND_NODE, "db").GetNode().GetGroups()), "30 1/0x1"},
			{"the Peer db of gw-1", groupsOf(stateObject(gw, controlpb.Kind_KIND_PEER, "db").GetPeer().GetGroups()), "30 1/0x1"},
			{"the Peer gw-1 of db", groupsOf(stateObject(db, controlpb.Kind_KIND_PEER, "gw-1").GetPeer().GetGroups()), "30 3/0x4"},
		} {
			if c.got != c.want {
				t.Errorf("%s: %s are %q, want %q", when, c.what, c.got, c.want)
			}
		}
		h.checkGroupState(gw, "gw-1", "db")
		h.checkGroupState(db, "gw-1", "db")
	}
	// The group generations of gw-1 and db, at each and at the other
	generations := func(when, gwGen, dbGen string) {
		t.Helper()
		checkGenerations(t, when, generationCase{gw, "", gwGen}, generationCase{db, "gw-1", gwGen}, generationCase{db, "", dbGen}, generationCase{gw, "db", dbGen})
	}
	check("with Device phone")
	generations("with Device phone", "30@2", "30@2")
	if d := stateObject(gw, controlpb.Kind_KIND_DEVICE, "phone").GetDevice(); d.GetGroup() != 2 || d.GetTagSet() != 0x2 {
		t.Errorf("Device phone at gw-1 has the group %d and the tag set %#x, want 2 and 0x2", d.GetGroup(), d.GetTagSet())
	}
	if got := h.storedNumbers()[30].String(); got != "[db]=1 [ops]=2 [web]=3; db:0 ops:1 web:2" {
		t.Errorf("the store holds the numbers %q of VRF dc", got)
	}

	// Device phone goes: no group changes its number, and the store keeps those of [ops] and ops
	res, err := h.api.Delete(context.Background(), intent.KindDevice, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "db", Generation: 3}, {Name: "gw-1", Generation: 4}, {Name: "lab-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the deletion of Device phone changed %+v, want %+v", res.Nodes, want)
	}
	gw.update(t)
	db.update(t)
	h.settle(map[string]uint64{"gw-1": 4, "db": 3})
	check("once Device phone is deleted")
	generations("once Device phone is deleted", "30@4", "30@2")
	if o := stateObject(gw, controlpb.Kind_KIND_DEVICE, "phone"); o != nil {
		t.Errorf("the state of gw-1 still holds Device phone: %v", o)
	}
	if got := h.storedNumbers()[30].String(); got != "[db]=1 [ops]=2 [web]=3; db:0 ops:1 web:2" {
		t.Errorf("once Device phone is deleted, the store holds the numbers %q of VRF dc, want those of before", got)
	}

	// A restart of the controller and of rqlite: the numbers come back from the store, so no Node gets a Generation
	h.stop()
	for _, s := range []*sim{gw, db} {
		if err := s.end(t); err == nil {
			t.Errorf("the stream of %s ended without an error when the controller stopped", s.name)
		}
	}
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	gw.start(h)
	db.start(h)
	h.settle(map[string]uint64{"gw-1": 4, "db": 3})
	check("after the restart")
	generations("after the restart", "30@4", "30@2")

	// A new set of tags and a new tag take the numbers after the largest ones, never the retired ones of [ops] and ops
	res = h.applyJSON(`{"kind": "Device", "name": "tablet", "spec": {"network": "dc-net", "gateway": "gw-1", "publicKey": "` + tabletKey + `", "tags": ["admin"]}}`)
	if want := []controller.NodeGeneration{{Name: "db", Generation: 4}, {Name: "gw-1", Generation: 5}, {Name: "lab-1", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("Device tablet changed %+v, want %+v", res.Nodes, want)
	}
	gw.update(t)
	db.update(t)
	h.settle(map[string]uint64{"gw-1": 5, "db": 4})
	check("with Device tablet")
	generations("with Device tablet", "30@5", "30@2")
	for _, s := range []*sim{gw, db} {
		if d := stateObject(s, controlpb.Kind_KIND_DEVICE, "tablet").GetDevice(); d.GetGroup() != 4 || d.GetTagSet() != 0x8 {
			t.Errorf("Device tablet at %s has the group %d and the tag set %#x, want 4 and 0x8", s.name, d.GetGroup(), d.GetTagSet())
		}
	}
	if got := h.storedNumbers()[30].String(); got != "[db]=1 [ops]=2 [web]=3 [admin]=4; db:0 ops:1 web:2 admin:3" {
		t.Errorf("with Device tablet, the store holds the numbers %q of VRF dc", got)
	}
}

// TestSourceGroupCountersReachTheExport is the seventh criterion of SDN-87 at the controller: the counters by tag mode
// that a node reports, of the packets that carried their source group, carried none or a refused claim, are in the
// Prometheus export and in the JSON of the API.
func TestSourceGroupCountersReachTheExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	b1 := h.joined()
	if err := b1.Telemetry(&controlpb.Telemetry{Groups: []*controlpb.SourceGroupCounters{
		{Mode: controlpb.TagMode_TAG_MODE_SESSION, Carried: 40, Missing: 2, Refused: 1},
		{Mode: controlpb.TagMode_TAG_MODE_OFF, Missing: 7, Ignored: 3},
		{Mode: controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY, Carried: 9, Missing: 4, Refused: 5},
	}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(
		`ranz_source_group_packets_total{mode="session",node="branch-1",result="carried"} 40`,
		`ranz_source_group_packets_total{mode="session",node="branch-1",result="missing"} 2`,
		`ranz_source_group_packets_total{mode="session",node="branch-1",result="refused"} 1`,
		`ranz_source_group_packets_total{mode="off",node="branch-1",result="ignored"} 3`,
		`ranz_source_group_packets_total{mode="trusted-underlay",node="branch-1",result="carried"} 9`,
		`ranz_source_group_packets_total{mode="trusted-underlay",node="branch-1",result="refused"} 5`,
	)

	snap, err := h.api.Telemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []telemetry.SourceGroupCounters{
		{Mode: telemetry.ModeOff, Missing: 7, Ignored: 3},
		{Mode: telemetry.ModeSession, Carried: 40, Missing: 2, Refused: 1},
		{Mode: telemetry.ModeTrustedUnderlay, Carried: 9, Missing: 4, Refused: 5},
	}
	if len(snap) != 1 || asJSON(t, snap[0].SourceGroups) != asJSON(t, want) {
		t.Errorf("the telemetry of the API is %+v, want the source groups %+v", snap, want)
	}
}
