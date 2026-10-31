package desired

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// mayAssert returns the source groups that the Node name may assert in the VRF id by st, the state of another Node, as that
// Node reads them (Cedar/NodeSourceGroup.c, NodeSourceGroupAttach): the groups of its Peer object and those of the Devices of
// st whose gateway it is, each group ID with its tag set, in order, each once.
func mayAssert(st State, name string, id uint32) string {
	var groups []string
	for _, g := range st[Key{controlpb.Kind_KIND_PEER, name}].GetPeer().GetGroups() {
		if g.GetVrfId() == id {
			groups = append(groups, fmt.Sprintf("%d/%#x", g.GetGroup(), g.GetTagSet()))
		}
	}
	for k, o := range st {
		if d := o.GetDevice(); k.Kind == controlpb.Kind_KIND_DEVICE && d.GetGateway() == name && d.GetVrfId() == id && d.GetGroup() != 0 {
			groups = append(groups, fmt.Sprintf("%d/%#x", d.GetGroup(), d.GetTagSet()))
		}
	}
	slices.Sort(groups)
	return strings.Join(slices.Compact(groups), " ")
}

// ownedDeviceResources returns VRF lab (7) with gw (tag guest), the gateway of Device alice-phone (tag phones), whose owner
// alice is a member of the Group staff, and host (tag servers), with the rule staff-to-servers that is written by the Group.
func ownedDeviceResources() []intent.Resource {
	const phoneKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	return []intent.Resource{
		res(intent.KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(intent.KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "tagMode": "trusted-underlay"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "tags": ["guest"], "wireguard": {"endpoint": "gw.example.net"}}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["lab"], "tags": ["servers"]}`),
		res(intent.KindGroup, "staff", `{}`),
		res(intent.KindUser, "alice", `{"groups": ["staff"]}`),
		res(intent.KindDevice, "alice-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+phoneKey+`", "owner": "alice", "tags": ["phones"]}`),
		res(intent.KindPolicy, "staff-to-servers", `{"vrf": "lab", "action": "allow", "from": {"tags": ["staff"]}, "to": {"tags": ["servers"]}}`),
	}
}

// SDN-87: a Device of an owner carries the Groups of its owner as tags (intent.DeviceTags), and its source group is the group
// of that set of tags, as the group of a Node with an owner is. Device alice-phone (tag phones) of alice, a member of the Group
// staff, is the set [phones,staff] of VRF lab: the group ID 2 between [guest] 1 (gw) and [servers] 3 (host), and the bits of
// phones and staff in its tag set. Its gateway gw and host hold it with that group, and gw may assert it, so a rule written by
// the Group judges the Device by the group that its packets carry. Numbered by the tags set on it alone, the Device was the set
// [phones], which no Device object has: it had the group 0 at both Nodes, and they judged its packets as gw's.
func TestSourceGroupsOwnedDevice(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: ownedDeviceResources()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, numbers := numbered(t, in, nil)
	if got := numbers[7].String(); got != "[guest]=1 [phones,staff]=2 [servers]=3; guest:0 phones:1 servers:2 staff:3" {
		t.Errorf("the numbers of VRF lab are %q, want the set of the Device with the Group of its owner", got)
	}
	for _, node := range []string{"gw", "host"} {
		d := states[node][Key{controlpb.Kind_KIND_DEVICE, "alice-phone"}].GetDevice()
		if d.GetGroup() != 2 || d.GetTagSet() != 0xa {
			t.Errorf("Device alice-phone (tags %v) at %s has the group %d and the tag set %#x, want 2 and 0xa", d.GetTags(), node, d.GetGroup(), d.GetTagSet())
		}
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups that gw may assert by its own state", asserted(states["gw"], "gw", 7), "1/0x1 2/0xa"},
		{"the groups that gw may assert by the state of host", mayAssert(states["host"], "gw", 7), "1/0x1 2/0xa"},
		{"the groups that host may assert by the state of gw", mayAssert(states["gw"], "host", 7), "3/0x4"},
	} {
		if c.got != c.want {
			t.Errorf("%s are %q, want %q", c.what, c.got, c.want)
		}
	}
}

// SDN-87: a Device that cannot get a group, as in a VRF that gave all of its group IDs, has the group 0 at every Node, and its
// gateway may assert nothing for it: gw keeps its own group, guest, and host lets gw assert guest alone. The gateway then stamps
// no group on the packets of the Device, and a Node judges them by the map of address to group, the Device as an end of its own
// and never as gw (Cedar/NodeSourceGroup.c, NodePolicy.c; vpntest grouppolicy runs both ends).
func TestSourceGroupsDeviceWithoutAGroup(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: ownedDeviceResources()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	full := GroupNumbers{7: {Groups: map[string]uint32{"guest": 1, "servers": 3, "gone": maxGroup}, Bits: map[string]uint{"guest": 0, "servers": 1}}}
	if added := NumberGroups(in, full); len(added[7].Groups) != 0 {
		t.Errorf("VRF lab, which gave its last group ID, gave the groups %q", added[7])
	}
	states, _ := numbered(t, in, full)
	for _, node := range []string{"gw", "host"} {
		if d := states[node][Key{controlpb.Kind_KIND_DEVICE, "alice-phone"}].GetDevice(); d.GetGroup() != 0 || d.GetTagSet() != 0 {
			t.Errorf("Device alice-phone at %s has the group %d and the tag set %#x, want none", node, d.GetGroup(), d.GetTagSet())
		}
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of gw", groupsText(states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetGroups()), "7 1/0x1"},
		{"the groups that gw may assert by its own state", asserted(states["gw"], "gw", 7), "1/0x1"},
		{"the groups that gw may assert by the state of host", mayAssert(states["host"], "gw", 7), "1/0x1"},
	} {
		if c.got != c.want {
			t.Errorf("%s are %q, want %q", c.what, c.got, c.want)
		}
	}
}

// SDN-87: the states that vpntest grouppolicy (src/vpntest/grouppolicytest.c) builds by hand are the ones that the Controller
// compiles. VRF red (101) in trusted-underlay holds node-a (tag guest, 10.0.0.1), the gateway of Device phone, whose owner bob
// is a member of the Group admin, and node-b (tag server, 10.0.0.2), which the rule admin-in from the tag admin to the tag server
// reaches. The Controller numbers [admin] 1, [guest] 2 and [server] 3 with the bits 0, 1 and 2, the constants GPTEST_ADMIN,
// GPTEST_GUEST and GPTEST_SERVER with their tag sets, and gives each Node of the C test the groups that it holds there.
func TestSourceGroupsOfTheGroupPolicyTest(t *testing.T) {
	const phoneKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	in, err := intent.Apply(intent.New(), intent.Document{Resources: []intent.Resource{
		res(intent.KindVRF, "red", `{"id": 101, "ula": "fd00:101:101::/48"}`),
		res(intent.KindNetwork, "red-net", `{"vrf": "red", "ipv4Pool": "10.0.0.0/24", "tagMode": "trusted-underlay"}`),
		res(intent.KindNode, "node-a", `{"publicKey": "`+key1+`", "vrfs": ["red"], "tags": ["guest"], "addresses": {"red-net": "10.0.0.1"}, "wireguard": {"endpoint": "node-a.example.net"}}`),
		res(intent.KindNode, "node-b", `{"publicKey": "`+key2+`", "vrfs": ["red"], "tags": ["server"], "addresses": {"red-net": "10.0.0.2"}}`),
		res(intent.KindGroup, "admin", `{}`),
		res(intent.KindUser, "bob", `{"groups": ["admin"]}`),
		res(intent.KindDevice, "phone", `{"network": "red-net", "gateway": "node-a", "publicKey": "`+phoneKey+`", "owner": "bob"}`),
		res(intent.KindPolicy, "admin-in", `{"vrf": "red", "action": "allow", "from": {"tags": ["admin"]}, "to": {"tags": ["server"]}}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, numbers := numbered(t, in, nil)
	if got := numbers[101].String(); got != "[admin]=1 [guest]=2 [server]=3; admin:0 guest:1 server:2" {
		t.Errorf("the numbers of VRF red are %q, want those of vpntest grouppolicy", got)
	}
	node := func(name string) *controlpb.NodeConfig {
		return states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode()
	}
	peer := func(name, other string) *controlpb.Peer {
		return states[name][Key{controlpb.Kind_KIND_PEER, other}].GetPeer()
	}
	for _, c := range []struct {
		what, got, want string
	}{
		{"the groups of node-a (guest)", groupsText(node("node-a").GetGroups()), "101 2/0x2"},
		{"the groups of node-b (server)", groupsText(node("node-b").GetGroups()), "101 3/0x4"},
		{"the Peer node-b of node-a", groupsText(peer("node-a", "node-b").GetGroups()), "101 3/0x4"},
		{"the Peer node-a of node-b", groupsText(peer("node-b", "node-a").GetGroups()), "101 2/0x2"},
		{"the groups that node-a may assert by the state of node-b", mayAssert(states["node-b"], "node-a", 101), "1/0x1 2/0x2"},
	} {
		if c.got != c.want {
			t.Errorf("%s are %q, want %q", c.what, c.got, c.want)
		}
	}
	for _, name := range []string{"node-a", "node-b"} {
		d := states[name][Key{controlpb.Kind_KIND_DEVICE, "phone"}].GetDevice()
		if d.GetGroup() != 1 || d.GetTagSet() != 0x1 || d.GetGateway() != "node-a" {
			t.Errorf("Device phone at %s has the group %d, the tag set %#x and the gateway %q, want admin 1/0x1 behind node-a", name, d.GetGroup(), d.GetTagSet(), d.GetGateway())
		}
		if v := states[name][Key{controlpb.Kind_KIND_VRF, "red"}].GetVrf(); v.GetTagMode() != controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY {
			t.Errorf("the Vrf red of %s has the tag mode %v, want trusted-underlay", name, v.GetTagMode())
		}
	}
	for _, c := range []struct {
		node, peer string
	}{{"node-a", "node-b"}, {"node-b", "node-a"}} {
		if v := peer(c.node, c.peer).GetFrameVersion(); v != FrameVersion {
			t.Errorf("the Peer %s of %s has the frame version %d, want %d", c.peer, c.node, v, FrameVersion)
		}
	}
	if r := states["node-b"][Key{controlpb.Kind_KIND_RULE, "admin-in"}].GetRule(); r == nil {
		t.Error("node-b does not get the rule admin-in, which vpntest grouppolicy enforces there")
	}
}
