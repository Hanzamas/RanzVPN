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
	SourceGroups(in, states, func(node string) bool { return tagged[node] })

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

// A VRF gives a bit of the tag set to its first 64 tags in name order: the tags after them are in no tag set, and the
// group still tells them apart.
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
	SourceGroups(in, states, func(string) bool { return true })
	for n, want := range []string{"30 1/0xffff", "30 2/0xffff0000", "30 3/0xffff00000000", "30 4/0xffff000000000000", "30 5/0x0"} {
		name := fmt.Sprintf("n%d", n)
		if got := groupsText(states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups()); got != want {
			t.Errorf("the groups of %s are %q, want %q", name, got, want)
		}
	}
}
