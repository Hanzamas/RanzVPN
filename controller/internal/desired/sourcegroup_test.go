package desired

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// sourceGroupResources returns VRF dc (30), whose Network dc-net is in the tag mode mode, and VRF corp (10); gw
// (tag web) in both, the gateway of Device phone (tag ops) of dc-net; db (tag db) and lab (tag web) in dc; and old,
// with no tag, in both.
func sourceGroupResources(mode string) []intent.Resource {
	const phoneKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`),
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24", "tagMode": "`+mode+`"}`),
		res(intent.KindNetwork, "corp-net", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc", "corp"], "tags": ["web"], "vtep": {"address": "10.1.0.1"}, "wireguard": {"endpoint": "gw.example.net"}}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "tags": ["db"], "vtep": {"address": "10.1.0.2"}}`),
		res(intent.KindNode, "lab", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "tags": ["web"], "vtep": {"address": "10.1.0.3"}}`),
		res(intent.KindNode, "old", `{"publicKey": "`+key4+`", "vrfs": ["dc", "corp"], "vtep": {"address": "10.1.0.4"}}`),
		res(intent.KindDevice, "phone", `{"network": "dc-net", "gateway": "gw", "publicKey": "`+phoneKey+`", "tags": ["ops"]}`),
	}
}

// groupsText returns the source groups as text: "vrf group/tagset" each, by commas.
func groupsText(groups []*controlpb.SourceGroup) string {
	var parts []string
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("%d %d/%#x", g.GetVrfId(), g.GetGroup(), g.GetTagSet()))
	}
	return strings.Join(parts, ", ")
}

// SDN-87: the Controller numbers the groups of each VRF from the sets of tags of its endpoints, the empty set first
// (old), then db, ops (Device phone) and web (gw and lab, one group); each of the tags of the VRF in name order is a
// bit of the tag set. A Node that reports the Capability tags gets its own group in each VRF by VRF id, the group of
// each Device, and of each peer that reports it too the peer's group in each shared VRF and the frame version 1; a
// Node that does not report it gets its state as Compile made it, and so does its Peer object at the others.
func TestSourceGroups(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: sourceGroupResources(intent.TagModeTrustedUnderlay)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	tagged := map[string]bool{"gw": true, "db": true, "lab": true}
	SourceGroups(in, states, NumberGroups(in, nil), func(node string) bool { return tagged[node] })

	node := func(name string) *controlpb.NodeConfig {
		return states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode()
	}
	peer := func(name, other string) *controlpb.Peer {
		return states[name][Key{controlpb.Kind_KIND_PEER, other}].GetPeer()
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of gw", groupsText(node("gw").GetGroups()), "10 2/0x1, 30 4/0x4"},
		{"the groups of db", groupsText(node("db").GetGroups()), "30 2/0x1"},
		{"the groups of lab", groupsText(node("lab").GetGroups()), "30 4/0x4"},
		{"the groups of old", groupsText(node("old").GetGroups()), ""},
		{"the Peer db of gw", groupsText(peer("gw", "db").GetGroups()), "30 2/0x1"},
		{"the Peer lab of gw", groupsText(peer("gw", "lab").GetGroups()), "30 4/0x4"},
		{"the Peer gw of db", groupsText(peer("db", "gw").GetGroups()), "30 4/0x4"},
		{"the Peer old of gw", groupsText(peer("gw", "old").GetGroups()), ""},
		{"the Peer gw of old", groupsText(peer("old", "gw").GetGroups()), ""},
	} {
		if c.got != c.want {
			t.Errorf("%s are %q, want %q", c.what, c.got, c.want)
		}
	}
	for _, c := range []struct {
		node, peer string
		want       uint32
	}{{"gw", "db", 1}, {"gw", "lab", 1}, {"db", "gw", 1}, {"gw", "old", 0}, {"old", "gw", 0}} {
		if got := peer(c.node, c.peer).GetFrameVersion(); got != c.want {
			t.Errorf("the Peer %s of %s has the frame version %d, want %d", c.peer, c.node, got, c.want)
		}
	}
	for _, name := range []string{"gw", "db", "lab"} {
		d := states[name][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice()
		if d.GetGroup() != 3 || d.GetTagSet() != 0x2 {
			t.Errorf("Device phone at %s has the group %d and the tag set %#x, want 3 and 0x2", name, d.GetGroup(), d.GetTagSet())
		}
	}
	if d := states["old"][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice(); d.GetGroup() != 0 || d.GetTagSet() != 0 {
		t.Errorf("Device phone at old, which does not report the Capability tags, has the group %d and the tag set %#x", d.GetGroup(), d.GetTagSet())
	}
	if !Equal(states["old"], plain["old"]) {
		t.Error("the state of old, which does not report the Capability tags, is not the one that Compile made")
	}
	if got := peer("gw", "old"); !proto.Equal(got, plain["gw"][Key{controlpb.Kind_KIND_PEER, "old"}].GetPeer()) {
		t.Errorf("the Peer old of gw is %v, not the one that Compile made", got)
	}
	// The objects that Compile made, which the states share, are not changed
	if groups := plain["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetGroups(); len(groups) != 0 {
		t.Errorf("SourceGroups changed the NodeConfig of gw that Compile made: %v", groups)
	}
	if d := plain["gw"][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice(); d.GetGroup() != 0 {
		t.Errorf("SourceGroups changed the Device phone that Compile made: %v", d)
	}
	for name := range states {
		for vrf, want := range map[string]controlpb.TagMode{"dc": controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY, "corp": controlpb.TagMode_TAG_MODE_UNSPECIFIED} {
			if o, ok := states[name][Key{controlpb.Kind_KIND_VRF, vrf}]; ok && o.GetVrf().GetTagMode() != want {
				t.Errorf("the Vrf %s of %s has the tag mode %v, want %v", vrf, name, o.GetVrf().GetTagMode(), want)
			}
		}
	}
}

// The tag mode off leaves the Vrf object as it was before the source groups, and a change of the mode is a change
// of the Vrf object of each Node of the VRF.
func TestSourceGroupsTagMode(t *testing.T) {
	off := compile(t, sourceGroupResources(intent.TagModeOff)...)
	none := compile(t, sourceGroupResources("")...)
	trusted := compile(t, sourceGroupResources(intent.TagModeTrustedUnderlay)...)
	for name := range off {
		if !Equal(off[name], none[name]) {
			t.Errorf("%s: the tag mode off compiles otherwise than no tag mode", name)
		}
		key := Key{controlpb.Kind_KIND_VRF, "dc"}
		if got := off[name][key].GetVrf().GetTagMode(); got != controlpb.TagMode_TAG_MODE_UNSPECIFIED {
			t.Errorf("%s: the Vrf dc in the tag mode off has the tag mode %v", name, got)
		}
		if proto.Equal(off[name][key], trusted[name][key]) {
			t.Errorf("%s: the Vrf dc is the same in the tag modes off and trusted-underlay", name)
		}
	}
}

// A VRF gives a bit of the tag set to 64 tags at most, in name order when they come in one intent: the tags after them
// are in no tag set, and the group still tells them apart.
func TestSourceGroupsTagBits(t *testing.T) {
	keys := []string{key1, key2, key3, key4, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}
	rs := []intent.Resource{res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48"}`)}
	for n := range 5 {
		var tags []string
		for i := range 16 {
			tags = append(tags, fmt.Sprintf(`"t%02d"`, n*16+i))
		}
		rs = append(rs, res(intent.KindNode, fmt.Sprintf("n%d", n), `{"publicKey": "`+keys[n]+`", "vrfs": ["dc"], "tags": [`+strings.Join(tags, ", ")+`]}`))
	}
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	SourceGroups(in, states, NumberGroups(in, nil), func(string) bool { return true })
	for n, want := range []string{"30 1/0xffff", "30 2/0xffff0000", "30 3/0xffff00000000", "30 4/0xffff000000000000", "30 5/0x0"} {
		name := fmt.Sprintf("n%d", n)
		if got := groupsText(states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups()); got != want {
			t.Errorf("the groups of %s are %q, want %q", name, got, want)
		}
	}
}

// numbered returns the states that in compiles to, with the source groups of every Node by the numbers of before and those
// that in takes beside them, and those numbers.
func numbered(t *testing.T, in intent.Intent, before GroupNumbers) (map[string]State, GroupNumbers) {
	t.Helper()
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	numbers := before.With(NumberGroups(in, before))
	SourceGroups(in, states, numbers, func(string) bool { return true })
	return states, numbers
}

// SDN-87: the numbers of the source groups stay. VRF dc of sourceGroupResources numbers the sets of tags [] 1 (old), [db] 2,
// [ops] 3 (Device phone) and [web] 4 (gw and lab), and the tags db, ops and web are the bits 0, 1 and 2. Deleting Device phone
// takes the set [ops] and the tag ops out of dc, and gives no number: the other groups keep their group IDs and tag sets,
// web 4/0x4 and db 2/0x1, where numbers by rank would make web 3/0x2, the numbers of ops in the Generation before.
func TestNumberGroupsKeep(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: sourceGroupResources(intent.TagModeTrustedUnderlay)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, numbers := numbered(t, in, nil)
	for id, want := range map[uint32]string{30: "[]=1 [db]=2 [ops]=3 [web]=4; db:0 ops:1 web:2", 10: "[]=1 [web]=2; web:0"} {
		if got := numbers[id].String(); got != want {
			t.Errorf("the numbers of VRF %d are %q, want %q", id, got, want)
		}
	}

	without, err := intent.Delete(in, intent.KindDevice, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if added := NumberGroups(without, numbers); len(added) != 0 {
		t.Errorf("the deletion of Device phone gave the numbers %v", added)
	}
	states, after := numbered(t, without, numbers)
	if got := after[30].String(); got != "[]=1 [db]=2 [ops]=3 [web]=4; db:0 ops:1 web:2" {
		t.Errorf("the numbers of VRF dc once Device phone is deleted are %q, want those of before", got)
	}
	node := func(name string) *controlpb.NodeConfig {
		return states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode()
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of gw", groupsText(node("gw").GetGroups()), "10 2/0x1, 30 4/0x4"},
		{"the groups of db", groupsText(node("db").GetGroups()), "30 2/0x1"},
		{"the groups of lab", groupsText(node("lab").GetGroups()), "30 4/0x4"},
		{"the groups of old", groupsText(node("old").GetGroups()), "10 1/0x0, 30 1/0x0"},
		{"the Peer gw of db", groupsText(states["db"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetGroups()), "30 4/0x4"},
	} {
		if c.got != c.want {
			t.Errorf("once Device phone is deleted, %s are %q, want %q", c.what, c.got, c.want)
		}
	}
	if o, ok := states["gw"][Key{controlpb.Kind_KIND_DEVICE, "phone"}]; ok {
		t.Errorf("the state of gw still holds Device phone: %v", o)
	}
}

// SDN-87: a number that a VRF gave never goes to another set of tags or tag. Once Device phone is deleted, the group ID 3 of
// [ops] and the bit 1 of ops are retired: a new Device tablet with the tag admin takes the group ID 5 and the bit 3, the
// next after the largest ones, and not 3 and 1, which a Node that still holds phone reads as ops. Phone made again with the
// tag ops takes its numbers of before, which mean the same tags in every Generation.
func TestNumberGroupsRetired(t *testing.T) {
	const tabletKey = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	in, err := intent.Apply(intent.New(), intent.Document{Resources: sourceGroupResources(intent.TagModeTrustedUnderlay)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, numbers := numbered(t, in, nil)
	without, err := intent.Delete(in, intent.KindDevice, "phone")
	if err != nil {
		t.Fatal(err)
	}
	_, numbers = numbered(t, without, numbers)

	tablet, err := intent.Apply(without, intent.Document{Resources: []intent.Resource{
		res(intent.KindDevice, "tablet", `{"network": "dc-net", "gateway": "gw", "publicKey": "`+tabletKey+`", "tags": ["admin"]}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := NumberGroups(tablet, numbers)[30].String(); got != "[admin]=5; admin:3" {
		t.Errorf("Device tablet takes the numbers %q, want the group ID 5 and the bit 3, after the retired ones of ops", got)
	}
	states, numbers := numbered(t, tablet, numbers)
	seen := map[uint32]string{}
	for set, g := range numbers[30].Groups {
		if other, ok := seen[g]; ok {
			t.Errorf("the group ID %d went to the sets [%s] and [%s]", g, other, set)
		}
		seen[g] = set
	}
	for _, name := range []string{"gw", "db", "lab"} {
		if d := states[name][Key{controlpb.Kind_KIND_DEVICE, "tablet"}].GetDevice(); d.GetGroup() != 5 || d.GetTagSet() != 0x8 {
			t.Errorf("Device tablet at %s has the group %d and the tag set %#x, want 5 and 0x8", name, d.GetGroup(), d.GetTagSet())
		}
	}

	again, err := intent.Apply(tablet, intent.Document{Resources: []intent.Resource{
		res(intent.KindDevice, "phone", `{"network": "dc-net", "gateway": "gw", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "tags": ["ops"]}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if added := NumberGroups(again, numbers); len(added) != 0 {
		t.Errorf("Device phone made again gave the numbers %v", added)
	}
	states, _ = numbered(t, again, numbers)
	if d := states["gw"][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice(); d.GetGroup() != 3 || d.GetTagSet() != 0x2 {
		t.Errorf("Device phone made again has the group %d and the tag set %#x at gw, want 3 and 0x2, its numbers of before", d.GetGroup(), d.GetTagSet())
	}
}

// generationsText returns the group generations of the source groups as text: "vrf@generation" each, by commas.
func generationsText(groups []*controlpb.SourceGroup) string {
	var parts []string
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("%d@%d", g.GetVrfId(), g.GetGeneration()))
	}
	return strings.Join(parts, ", ")
}

// SDN-87: the group generation of a Node in a VRF is the Generation of its state from which on it may assert what it
// asserts there (GroupGenerations), in its NodeConfig and in its Peer object at the others (WithGroupGenerations). Every
// Node of sourceGroupResources gets its groups in the Generation 3. Device phone is deleted in the Generation 7 of each:
// gw, the gateway of phone in dc, may assert its group web alone there from then on, so its group generation of dc is 7,
// at gw and at every peer of it; it keeps 3 in corp, where it asserts what it did, and so do db, lab and old everywhere,
// which no Device has as its gateway. A claim of gw that names 3 in dc was made on the state before, which let gw assert
// ops, the group of phone. The objects that the states share are not changed.
func TestGroupGenerations(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: sourceGroupResources(intent.TagModeTrustedUnderlay)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, numbers := numbered(t, in, nil)
	gens := map[string]map[uint32]uint64{}
	for name, st := range before {
		gens[name] = GroupGenerations(st, nil, name, 3)
	}
	shared := before["db"][Key{controlpb.Kind_KIND_PEER, "gw"}]
	WithGroupGenerations(before, gens)
	if g := shared.GetPeer().GetGroups(); len(g) != 1 || g[0].GetGeneration() != 0 {
		t.Errorf("WithGroupGenerations changed the Peer gw of db that SourceGroups made: %v", g)
	}

	without, err := intent.Delete(in, intent.KindDevice, "phone")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := numbered(t, without, numbers)
	gens = map[string]map[uint32]uint64{}
	for name, st := range after {
		gens[name] = GroupGenerations(st, before[name], name, 7)
	}
	WithGroupGenerations(after, gens)

	node := func(states map[string]State, name string) *controlpb.NodeConfig {
		return states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode()
	}
	peer := func(states map[string]State, name, other string) *controlpb.Peer {
		return states[name][Key{controlpb.Kind_KIND_PEER, other}].GetPeer()
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of gw with phone", generationsText(node(before, "gw").GetGroups()), "10@3, 30@3"},
		{"the Peer gw of db with phone", generationsText(peer(before, "db", "gw").GetGroups()), "30@3"},
		{"the groups of gw without phone", generationsText(node(after, "gw").GetGroups()), "10@3, 30@7"},
		{"the Peer gw of db without phone", generationsText(peer(after, "db", "gw").GetGroups()), "30@7"},
		{"the Peer gw of lab without phone", generationsText(peer(after, "lab", "gw").GetGroups()), "30@7"},
		{"the Peer gw of old without phone", generationsText(peer(after, "old", "gw").GetGroups()), "10@3, 30@7"},
		{"the groups of db without phone", generationsText(node(after, "db").GetGroups()), "30@3"},
		{"the Peer db of gw without phone", generationsText(peer(after, "gw", "db").GetGroups()), "30@3"},
		{"the groups of lab without phone", generationsText(node(after, "lab").GetGroups()), "30@3"},
		{"the groups of old without phone", generationsText(node(after, "old").GetGroups()), "10@3, 30@3"},
	} {
		if c.got != c.want {
			t.Errorf("%s have the group generations %q, want %q", c.what, c.got, c.want)
		}
	}

	// A Node without a state before takes the Generation that its state goes out as, and so does a state before without
	// group generations
	if got := GroupGenerations(after["db"], nil, "db", 1); got[30] != 1 {
		t.Errorf("db without a state before has the group generations %v, want 1 in dc", got)
	}
	plain, err := Compile(without)
	if err != nil {
		t.Fatal(err)
	}
	if got := GroupGenerations(after["gw"], plain["gw"], "gw", 9); got[10] != 9 || got[30] != 9 {
		t.Errorf("gw after a state without source groups has the group generations %v, want 9 in both VRFs", got)
	}
}

// A VRF that gave its largest group ID, or its MaxTagBits bits, gives no more: a Node whose set of tags has no group ID in
// it has no group there, a Device none, and a tag without a bit is in no tag set. The numbers of another VRF are its own.
func TestNumberGroupsFull(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: sourceGroupResources(intent.TagModeTrustedUnderlay)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	full := GroupNumbers{30: {Groups: map[string]uint32{"gone": maxGroup}, Bits: map[string]uint{"gone": MaxTagBits - 1}}}
	added := NumberGroups(in, full)
	if v, ok := added[30]; ok {
		t.Errorf("VRF dc, which gave its last group ID and its last bit, gave %q", v)
	}
	if got := added[10].String(); got != "[]=1 [web]=2; web:0" {
		t.Errorf("VRF corp took the numbers %q, want its own", got)
	}
	states, _ := numbered(t, in, full)
	if got := groupsText(states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetGroups()); got != "10 2/0x1" {
		t.Errorf("the groups of gw are %q, want its group of corp alone", got)
	}
	if p := states["gw"][Key{controlpb.Kind_KIND_PEER, "db"}].GetPeer(); len(p.GetGroups()) != 0 || p.GetFrameVersion() != FrameVersion {
		t.Errorf("the Peer db of gw is %v, want no group and the frame version %d", p, FrameVersion)
	}
	if d := states["gw"][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice(); d.GetGroup() != 0 || d.GetTagSet() != 0 {
		t.Errorf("Device phone at gw has the group %d and the tag set %#x, want none", d.GetGroup(), d.GetTagSet())
	}
}
