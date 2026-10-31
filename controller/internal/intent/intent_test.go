package intent

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const key1 = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="

func doc(rs ...Resource) Document {
	return Document{Resources: rs}
}

func res(kind, name, spec string) Resource {
	return Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
}

// A VRF that leaves out its id, ULA and MTU gets the lowest free id, a random ULA /48 and the
// default MTU, and keeps the id and ULA when it is applied again without them.
func TestApplyCompletesVRF(t *testing.T) {
	random := bytes.NewReader([]byte{0x11, 0x12, 0x13, 0x14, 0x15})
	in, err := Apply(New(), doc(
		res(KindVRF, "used", `{"id": 1, "ula": "fd00:1:2::/48"}`),
		res(KindVRF, "new", `{}`),
	), random)
	if err != nil {
		t.Fatal(err)
	}
	want := VRF{ID: 2, ULA: "fd11:1213:1415::/48", MTU: DefaultMTU}
	if got := in.VRFs["new"]; !reflect.DeepEqual(got, want) {
		t.Errorf("the completed VRF is %+v, want %+v", got, want)
	}
	again, err := Apply(in, doc(res(KindVRF, "new", `{"mtu": 1400}`)), bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	want.MTU = 1400
	if got := again.VRFs["new"]; !reflect.DeepEqual(got, want) {
		t.Errorf("the VRF applied again is %+v, want %+v", got, want)
	}
	if _, err := Apply(again, doc(res(KindVRF, "new", `{"id": 9}`)), nil); err == nil || !strings.Contains(err.Error(), "cannot change") {
		t.Errorf("changing the id of a VRF: %v, want an error", err)
	}
}

func TestApplyRejects(t *testing.T) {
	base, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindController, "c1", `{"address": "192.0.2.1:443", "publicKey": "`+key1+`"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 250) + ".example:443"
	for _, c := range []struct {
		doc  Document
		want string
	}{
		{doc(res("Router", "r1", `{}`)), `Router "r1": the kind must be VRF, Network, Node, Policy, Mirror, Controller, NAT, DnsRecord, Group, User, Listener, Device, SessionProfile or Stretch`},
		{doc(res(KindPolicy, "p", `{"vrf": "lab", "action": "allow"}`)), `Policy "p": VRF "lab" does not exist`},
		{doc(res(KindPolicy, "p", `{"vrf": "corp", "action": "permit"}`)), `Policy "p": the action must be allow or deny, not "permit"`},
		{doc(res(KindController, "c2", `{"address": "192.0.2.2", "publicKey": "`+key1+`"}`)), `Controller "c2": address "192.0.2.2" is not host:port`},
		{doc(res(KindController, "c2", `{"address": ":443", "publicKey": "`+key1+`"}`)), `address ":443" is not host:port: there is no host`},
		{doc(res(KindController, "c2", `{"address": "192.0.2.2:https", "publicKey": "`+key1+`"}`)), `the port "https" is not a number from 1 to 65535`},
		{doc(res(KindController, "c2", `{"address": "`+long+`", "publicKey": "`+key1+`"}`)), `is longer than 255 characters`},
		{doc(res(KindController, "c2", `{"address": "192.0.2.1:443", "publicKey": "`+key1+`"}`)), `Controller "c2": the address is already the address of Controller "c1"`},
		{doc(res(KindController, "c2", `{"address": "192.0.2.2:443", "publicKey": "c2hvcnQ="}`)), `Controller "c2": publicKey "c2hvcnQ=" is not the base64 of a 32-byte key`},
		{doc(res(KindVRF, "-bad", `{}`)), `VRF "-bad": the name must be`},
		{doc(res(KindVRF, "a", `{"colour": "red"}`)), `VRF "a": spec: json: unknown field "colour"`},
		{doc(res(KindVRF, "a", `{}`), res(KindVRF, "a", `{}`)), `VRF "a": declared twice`},
		{doc(res(KindVRF, "a", `{"id": 10}`)), `id 10 is already the id of VRF`},
		{doc(res(KindVRF, "a", `{"ula": "fc00:1:2::/48"}`)), `VRF "a": ula "fc00:1:2::/48" is not a ULA /48`},
		{doc(res(KindVRF, "a", `{"ula": "fd00:1:2::/56"}`)), `is not a ULA /48`},
		{doc(res(KindVRF, "a", `{"mtu": 576}`)), `VRF "a": mtu 576 is not between 1280 and 65535`},
		{doc(res(KindNetwork, "n", `{"vrf": "lab"}`)), `Network "n": VRF "lab" does not exist`},
		{doc(res(KindNetwork, "n", `{"vrf": "corp", "mode": "L4"}`)), `Network "n": the mode must be L3 or L2, not "L4"`},
		{doc(res(KindNetwork, "n", `{"vrf": "corp", "ipv4Pool": "10.0.0.1/24"}`)), `has host bits set, the prefix is 10.0.0.0/24`},
		{doc(res(KindNetwork, "n", `{"vrf": "corp", "ipv4Pool": "fd00::/64"}`)), `is not an IPv4 prefix`},
		{doc(res(KindNetwork, "n", `{"vrf": "corp", "ipv6Pool": "10.0.0.0/24"}`)), `is not an IPv6 prefix`},
		{doc(res(KindNode, "n", `{"publicKey": "c2hvcnQ="}`)), `Node "n": publicKey "c2hvcnQ=" is not the base64 of a 32-byte key`},
		{doc(res(KindNode, "n", `{"publicKey": "`+key1+`"}`)), `Node "n": the publicKey is already the key of Node "branch-1"`},
		{doc(res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp", "corp"]}`)), `VRF "corp" is listed twice`},
		{doc(res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "tags": ["Finance"]}`)), `tag "Finance" must be`},
		{doc(res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "relay": "relay.example:7000"}`)), `relay "relay.example:7000" is not an IP address and a port`},
		{doc(res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "relay": "192.0.2.10:0"}`)), `a port other than 0`},
	} {
		next, err := Apply(base, c.doc, nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: the error is %v, want one with %q", c.doc.Resources, err, c.want)
		}
		if len(next.VRFs) != len(base.VRFs) || len(next.Networks) != len(base.Networks) || len(next.Nodes) != len(base.Nodes) ||
			len(next.Controllers) != len(base.Controllers) {
			t.Errorf("%+v: a failed apply changed the intent", c.doc.Resources)
		}
	}
}

func TestDelete(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindVRF, "corp"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `VRF "corp" is used by Network "lan", Node "branch-1"`) {
		t.Errorf("deleting a VRF in use: %v", err)
	}
	if _, err := Delete(in, KindNetwork, "wan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a Network that does not exist: %v", err)
	}
	next, err := Delete(in, KindNetwork, "lan")
	if err != nil {
		t.Fatal(err)
	}
	put, gone := Changed(in, next)
	if len(put) != 0 || len(gone) != 1 || gone[0].Kind != KindNetwork || gone[0].Name != "lan" {
		t.Errorf("the change of a delete is put %+v, gone %+v", put, gone)
	}
	if _, ok := in.Networks["lan"]; !ok {
		t.Error("Delete changed the intent it was given")
	}
}

// The stored form of an intent reads back as the same intent.
func TestResourcesRoundTrip(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["b", "a"]}`),
		res(KindController, "c1", `{"address": "ctl1.example:443", "publicKey": "`+key1+`"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindController, "c2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a Controller that does not exist: %v", err)
	}
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	if got := back.Nodes["branch-1"].Tags; strings.Join(got, ",") != "a,b" {
		t.Errorf("the tags are %v, want them sorted", got)
	}
	if got := back.Controllers["c1"].Address; got != "ctl1.example:443" {
		t.Errorf("the Controller read back has the address %q", got)
	}
}

// A node cap keeps the first Nodes in name order and leaves the intent it was given unchanged.
func TestCapped(t *testing.T) {
	in := New()
	for _, name := range []string{"c", "a", "b"} {
		in.Nodes[name] = Node{PublicKey: key1}
	}
	for _, c := range []struct {
		n    int
		want string
	}{{0, ""}, {2, "a,b"}, {3, "a,b,c"}, {10, "a,b,c"}} {
		if got := strings.Join(sortedNames(in.Capped(c.n).Nodes), ","); got != c.want {
			t.Errorf("a cap of %d keeps %q, want %q", c.n, got, c.want)
		}
	}
	if len(in.Nodes) != 3 {
		t.Errorf("Capped changed the intent it was given: %v", in.Nodes)
	}
}
