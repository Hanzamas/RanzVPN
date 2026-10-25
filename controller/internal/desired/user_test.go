package desired

import (
	"slices"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The Groups of the owner of a Node are tags of the Node (SDN-31): in its own object, in the Peer
// object of every other Node, and so in the rules that it gets. A rule written for the tag of a Group
// reaches the devices of its members and the Nodes that the rule names at its other end, and no
// other Node: the laptop of alice (group staff) and the file server get staff-to-db, the phone of
// carol (group guests) and the file server get guests-to-db, and the kiosk, which has an owner of no
// Group, gets none.
func TestCompileGroupTags(t *testing.T) {
	const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	const key4 = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindGroup, "staff", `{}`),
		res(intent.KindGroup, "guests", `{}`),
		res(intent.KindUser, "alice", `{"groups": ["staff"]}`),
		res(intent.KindUser, "carol", `{"groups": ["guests"]}`),
		res(intent.KindUser, "dave", `{}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "owner": "alice", "tags": ["laptop", "staff"]}`),
		res(intent.KindNode, "phone", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "carol"}`),
		res(intent.KindNode, "files", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "tags": ["db"]}`),
		res(intent.KindNode, "kiosk", `{"publicKey": "`+key4+`", "vrfs": ["corp"], "owner": "dave"}`),
		res(intent.KindPolicy, "staff-to-db", `{"vrf": "corp", "action": "allow", "from": {"tags": ["staff"]}, "to": {"tags": ["db"]}}`),
		res(intent.KindPolicy, "guests-to-db", `{"vrf": "corp", "action": "deny", "from": {"tags": ["guests"]}, "to": {"tags": ["db"]}}`),
	)

	// The tags of each Node in its own object: its own and those of the Groups of its owner, once each
	for node, want := range map[string][]string{
		"laptop": {"laptop", "staff"},
		"phone":  {"guests"},
		"files":  {"db"},
		"kiosk":  nil,
	} {
		if got := states[node][Key{controlpb.Kind_KIND_NODE, node}].GetNode().GetTags(); !slices.Equal(got, want) {
			t.Errorf("the object of %s has the tags %v, want %v", node, got, want)
		}
	}
	// And in the Peer object that another Node holds of it
	for _, c := range []struct {
		holder string
		peer   string
		want   []string
	}{
		{"files", "laptop", []string{"laptop", "staff"}},
		{"files", "phone", []string{"guests"}},
		{"files", "kiosk", nil},
		{"kiosk", "laptop", []string{"laptop", "staff"}},
		{"laptop", "files", []string{"db"}},
	} {
		if got := states[c.holder][Key{controlpb.Kind_KIND_PEER, c.peer}].GetPeer().GetTags(); !slices.Equal(got, c.want) {
			t.Errorf("the peer %s of %s has the tags %v, want %v", c.peer, c.holder, got, c.want)
		}
	}
	// The rules reach the devices of the members of the Group and the Node at the other end
	for node, want := range map[string][]string{
		"laptop": {"staff-to-db"},
		"phone":  {"guests-to-db"},
		"files":  {"guests-to-db", "staff-to-db"},
		"kiosk":  nil,
	} {
		var got []string
		for _, k := range states[node].keys() {
			if k.Kind == controlpb.Kind_KIND_RULE {
				got = append(got, k.Name)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("node %s gets the rules %v, want %v", node, got, want)
		}
	}
}

// A change of the Groups of a User changes the state of its devices and of the Nodes that hold them
// as peers, and of no other Node.
func TestGroupChangeReachesTheDevicesAndTheirPeers(t *testing.T) {
	const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	base := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindGroup, "staff", `{}`),
		res(intent.KindGroup, "ops", `{}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "owner": "alice"}`),
		res(intent.KindNode, "files", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "lab-box", `{"publicKey": "`+key3+`", "vrfs": ["lab"]}`),
	}
	before := compile(t, append(slices.Clone(base), res(intent.KindUser, "alice", `{"groups": ["staff"]}`))...)
	after := compile(t, append(slices.Clone(base), res(intent.KindUser, "alice", `{"groups": ["ops", "staff"]}`))...)

	if Equal(before["laptop"], after["laptop"]) || Equal(before["files"], after["files"]) {
		t.Error("a new group of alice did not change the state of her laptop and of the Node that holds it as a peer")
	}
	if !Equal(before["lab-box"], after["lab-box"]) {
		t.Error("a new group of alice changed the state of a Node of another VRF, which shares nothing with her laptop")
	}
	u := Delta(before["files"], 1, after["files"], 2)
	if len(u.GetSet()) != 1 || u.GetSet()[0].GetPeer().GetName() != "laptop" || len(u.GetRemove()) != 0 {
		t.Fatalf("the delta of files is %v, want the peer laptop alone", u)
	}
	if tags := u.GetSet()[0].GetPeer().GetTags(); !slices.Equal(tags, []string{"ops", "staff"}) {
		t.Errorf("the peer laptop of files has the tags %v, want [ops staff]", tags)
	}
}
