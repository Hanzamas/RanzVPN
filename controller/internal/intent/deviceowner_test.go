package intent

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ownerLab returns the intent of the lab of device_test.go with two Groups, staff and ops, the User alice, in
// both of them, with the Devices that rs add.
func ownerLab(t *testing.T, maxDevices int, rs ...Resource) (Intent, error) {
	t.Helper()
	base := []Resource{
		res(KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`),
		res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`),
		res(KindGroup, "staff", `{}`),
		res(KindGroup, "ops", `{}`),
		res(KindUser, "alice", fmt.Sprintf(`{"groups": ["staff", "ops"], "maxDevices": %d}`, maxDevices)),
	}
	return Apply(New(), doc(append(base, rs...)...), nil)
}

// A Device with an owner carries the name of every Group of the owner as a tag besides the tags set on it,
// each tag once, in order; a standalone Device only the tags set on it; a Device that is not in the intent
// none (SDN-82, #377).
func TestDeviceTagsTakeTheGroupsOfTheOwner(t *testing.T) {
	in, err := ownerLab(t, 0,
		res(KindDevice, "alice-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key2+`", "owner": "alice", "tags": ["phones", "ops"]}`),
		res(KindDevice, "router", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key3+`", "tags": ["routers"]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"alice-phone": "ops,phones,staff", "router": "routers", "nobody": ""} {
		if got := strings.Join(in.DeviceTags(name), ","); got != want {
			t.Errorf("the tags of Device %s are %q, want %q", name, got, want)
		}
	}
	if in.DeviceTags("nobody") != nil {
		t.Error("a Device that is not in the intent has tags")
	}
	// The tags of the Device in the intent are the ones set on it: the groups come from the owner as they stand
	if got := strings.Join(in.Devices["alice-phone"].Tags, ","); got != "ops,phones" {
		t.Errorf("the tags set on Device alice-phone are %q, want ops,phones", got)
	}

	// The groups of the owner change, and the tags of the Device with them
	moved, err := Apply(in, doc(res(KindUser, "alice", `{"groups": ["staff"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(moved.DeviceTags("alice-phone"), ","); got != "ops,phones,staff" {
		t.Errorf("after alice left ops the tags of Device alice-phone are %q, want ops,phones,staff: ops is still set on the Device", got)
	}
	moved, err = Apply(in, doc(res(KindUser, "alice", `{}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(moved.DeviceTags("alice-phone"), ","); got != "ops,phones" {
		t.Errorf("after alice left every group the tags of Device alice-phone are %q, want the ones set on it, ops,phones", got)
	}
}

// The devices of a User are its Nodes and its Devices, in name order, the Nodes first, and they count
// against its maximum; the owner of a Device cannot be deleted, and a Device needs an owner that exists, and
// tags that its Groups leave room for.
func TestDeviceOwners(t *testing.T) {
	phone := res(KindDevice, "alice-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key2+`", "owner": "alice"}`)
	laptop := res(KindDevice, "alice-laptop", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key3+`", "owner": "alice"}`)
	in, err := ownerLab(t, 3, phone, laptop, res(KindNode, "alice-node", `{"publicKey": "`+deviceKey+`", "vrfs": ["lab"], "owner": "alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := deviceList(in.DevicesOf("alice")); got != `Node "alice-node", Device "alice-laptop", Device "alice-phone"` {
		t.Errorf("the devices of alice are %s, want her Node first and her Devices in name order", got)
	}
	if got := in.DevicesOf("nobody"); got != nil {
		t.Errorf("the devices of a User that does not exist are %v", got)
	}
	if _, err := Delete(in, KindUser, "alice"); err == nil || !strings.Contains(err.Error(), `User "alice" is the owner of Node "alice-node", Device "alice-laptop", Device "alice-phone"`) {
		t.Errorf("deleting the owner of Devices: %v, want an error that names them", err)
	}

	// A fourth device is one too many
	tabletKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, KeySize))
	_, err = Apply(in, doc(res(KindDevice, "alice-tablet", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+tabletKey+`", "owner": "alice"}`)), nil)
	if err == nil || !strings.Contains(err.Error(), `User "alice": 4 devices`) || !strings.Contains(err.Error(), "and the maximum is 3") {
		t.Errorf("a fourth device of a User whose maximum is 3: %v", err)
	}

	// An owner that does not exist
	if _, err := ownerLab(t, 0, res(KindDevice, "ghost-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key2+`", "owner": "ghost"}`)); err == nil ||
		!strings.Contains(err.Error(), `Device "ghost-phone": the owner User "ghost" does not exist`) {
		t.Errorf("a Device of a User that does not exist: %v", err)
	}

	// 15 tags of its own and the two groups of its owner are 17, one more than a Device carries; 14 are 16
	tags := func(n int) string {
		var names []string
		for i := range n {
			names = append(names, fmt.Sprintf("%q", fmt.Sprintf("t%02d", i)))
		}
		return strings.Join(names, ", ")
	}
	full := func(n int) Resource {
		return res(KindDevice, "alice-phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+key2+`", "owner": "alice", "tags": [`+tags(n)+`]}`)
	}
	if _, err := ownerLab(t, 0, full(15)); err == nil ||
		!strings.Contains(err.Error(), `Device "alice-phone": 17 tags, its own and those of the Groups of its owner, and a Device carries at most 16`) {
		t.Errorf("15 tags and two groups: %v, want a Device with 17 tags refused", err)
	}
	if in, err := ownerLab(t, 0, full(14)); err != nil || len(in.DeviceTags("alice-phone")) != MaxDeviceTags {
		t.Errorf("14 tags and two groups: %v, %v, want a Device with %d tags", err, in.DeviceTags("alice-phone"), MaxDeviceTags)
	}
	// A Device whose own tags are too many is refused for them alone, with no count of the groups of its owner
	_, err = ownerLab(t, 0, full(17))
	if err == nil || !strings.Contains(err.Error(), `Device "alice-phone": 17 tags, at most 16`) || strings.Contains(err.Error(), "Groups of its owner") {
		t.Errorf("17 tags of its own: %v", err)
	}

	// A Group that a User of a Device belongs to cannot be deleted, as it cannot for the owner of a Node
	if _, err := Delete(in, KindGroup, "staff"); err == nil || !strings.Contains(err.Error(), `Group "staff" is used by User "alice"`) {
		t.Errorf("deleting a Group of the owner of Devices: %v", err)
	}
	if got := in.Members("staff"); !slices.Equal(got, []string{"alice"}) {
		t.Errorf("the members of staff are %v", got)
	}
}
