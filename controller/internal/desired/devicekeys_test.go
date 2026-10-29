package desired

import (
	"bytes"
	"slices"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The PresharedKeys of the Devices are no part of the intent, so Compile does not know them (SDN-82, #377):
// WithPresharedKeys puts the key of each Device into the Device object of its gateway, in a copy, since the
// states share their objects, and into no other. A key of a Device that no state holds is left, a Device
// without a key keeps its object, and the key that goes in is a copy too.
func TestWithPresharedKeys(t *testing.T) {
	const gw2Key = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	const phoneKey = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="
	const laptopKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	states := compile(t,
		res(intent.KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(intent.KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`),
		res(intent.KindNode, "gw2", `{"publicKey": "`+gw2Key+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw2.example.net"}}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
		res(intent.KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+phoneKey+`"}`),
		res(intent.KindDevice, "laptop", `{"network": "lab-net", "gateway": "gw2", "publicKey": "`+laptopKey+`"}`),
	)
	phone := Key{controlpb.Kind_KIND_DEVICE, "phone"}
	laptop := Key{controlpb.Kind_KIND_DEVICE, "laptop"}
	before := states["gw"][phone]
	laptopBefore := states["gw2"][laptop]
	if len(before.GetDevice().GetPresharedKey()) != 0 {
		t.Fatalf("Compile put a PresharedKey into Device phone: %x", before.GetDevice().GetPresharedKey())
	}

	psk := bytes.Repeat([]byte{0x33}, intent.KeySize)
	WithPresharedKeys(states, map[string][]byte{"phone": psk, "ghost": bytes.Repeat([]byte{0x44}, intent.KeySize)})

	got := states["gw"][phone].GetDevice()
	if !bytes.Equal(got.GetPresharedKey(), psk) || len(got.GetPublicKey()) != intent.KeySize || got.GetGateway() != "gw" {
		t.Errorf("Device phone at its gateway is %v, want its key and the PresharedKey", got)
	}
	if states["gw"][phone] == before {
		t.Error("the Device object of the gateway is the one that the other states share, not a copy that holds the PresharedKey")
	}
	if len(before.GetDevice().GetPresharedKey()) != 0 {
		t.Errorf("the object that WithPresharedKeys replaced got the PresharedKey: %x", before.GetDevice().GetPresharedKey())
	}
	// No other node holds the key: the Device is in the state of every node of the VRF, and the key in the state of its gateway only
	for _, node := range []string{"gw2", "host"} {
		d := states[node][phone].GetDevice()
		if d == nil || len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != 0 {
			t.Errorf("%s holds Device phone as %v, want it without its key and without the PresharedKey", node, d)
		}
	}
	// A Device that has no key is the same object as before, and so is a key that no Device has
	if states["gw2"][laptop] != laptopBefore || len(states["gw2"][laptop].GetDevice().GetPresharedKey()) != 0 {
		t.Errorf("Device laptop, which has no key in the map, is %v", states["gw2"][laptop])
	}
	if _, ok := states["gw"][Key{controlpb.Kind_KIND_DEVICE, "ghost"}]; ok {
		t.Error("a key of a Device that no state holds made a Device")
	}

	// What goes in is a copy of the key: the map may be changed or wiped afterwards
	psk[0] ^= 0xff
	if got := states["gw"][phone].GetDevice().GetPresharedKey(); got[0] != 0x33 {
		t.Errorf("the PresharedKey in the state changed with the key that was given: %x", got)
	}

	// No keys, no change: the objects are the ones that they were
	given := states["gw"][phone]
	WithPresharedKeys(states, nil)
	WithPresharedKeys(states, map[string][]byte{})
	if states["gw"][phone] != given || states["gw2"][laptop] != laptopBefore {
		t.Error("a call with no key to give replaced an object of a state")
	}
}

// A Device of an owner is in every state of its VRF with the tags that policy sees (SDN-82, #377): its own and
// the groups of its owner, and the rule that names a group reaches the gateway of a Device of a member and
// the node that its other end names, and no other.
func TestCompileDeviceOfAnOwner(t *testing.T) {
	const phoneKey = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="
	const routerKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	const gw2Key = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	states := compile(t,
		res(intent.KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(intent.KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`),
		res(intent.KindNode, "gw2", `{"publicKey": "`+gw2Key+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw2.example.net"}}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["lab"], "tags": ["servers"]}`),
		res(intent.KindGroup, "staff", `{}`),
		res(intent.KindUser, "alice", `{"groups": ["staff"]}`),
		res(intent.KindDevice, "alice-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+phoneKey+`", "owner": "alice", "tags": ["phones"]}`),
		res(intent.KindDevice, "router", `{"network": "lab-net", "gateway": "gw2", "publicKey": "`+routerKey+`", "tags": ["routers"]}`),
		res(intent.KindPolicy, "staff-to-servers", `{"vrf": "lab", "action": "allow", "from": {"tags": ["staff"]}, "to": {"tags": ["servers"]}}`),
	)
	for _, node := range []string{"gw", "gw2", "host"} {
		phone := states[node][Key{controlpb.Kind_KIND_DEVICE, "alice-phone"}].GetDevice()
		if !slices.Equal(phone.GetTags(), []string{"phones", "staff"}) {
			t.Errorf("%s holds Device alice-phone with the tags %v, want its own and the group of its owner", node, phone.GetTags())
		}
		router := states[node][Key{controlpb.Kind_KIND_DEVICE, "router"}].GetDevice()
		if !slices.Equal(router.GetTags(), []string{"routers"}) {
			t.Errorf("%s holds the standalone Device router with the tags %v, want the tags set on it", node, router.GetTags())
		}
	}
	rule := Key{controlpb.Kind_KIND_RULE, "staff-to-servers"}
	for node, want := range map[string]bool{"gw": true, "host": true, "gw2": false} {
		if _, ok := states[node][rule]; ok != want {
			t.Errorf("%s holds the rule for the group staff: %v, want %v", node, ok, want)
		}
	}
}
