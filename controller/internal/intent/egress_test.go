package intent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The internet exit of a VRF is a Node that is a member of it: a Node is the exit of each VRF that
// names it as its egress, and the egress reads back from the resources and applies again unchanged.
// A VRF that names none has no exit, and its resource holds no egress.
func TestApplyEgress(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "gw"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48", "egress": "gw"}`),
		res(KindVRF, "dev", `{"id": 30, "ula": "fd12:3456:789c::/48"}`),
		res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab", "dev"]}`),
		res(KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp", "dev"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.EgressVRFs("gw"); !slices.Equal(got, []string{"corp", "lab"}) {
		t.Errorf("Node gw is the exit of %v, want corp and lab", got)
	}
	if got := in.EgressVRFs("laptop"); len(got) != 0 {
		t.Errorf("Node laptop is the exit of %v", got)
	}
	if got := in.EgressVRFs(""); len(got) != 0 {
		t.Errorf("no Node is the exit of %v", got)
	}

	rs := in.Resources()
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || again.VRFs["corp"].Egress != "gw" || again.VRFs["lab"].Egress != "gw" || again.VRFs["dev"].Egress != "" {
		t.Errorf("the resources applied again: %v, VRF corp %+v, VRF dev %+v", err, again.VRFs["corp"], again.VRFs["dev"])
	}
	for _, r := range rs {
		if r.Kind == KindVRF && r.Name == "dev" && strings.Contains(string(r.Spec), "egress") {
			t.Errorf("the resource of VRF dev, which has no exit, is %s", r.Spec)
		}
	}
}

// An exit that does not exist or is not a member of the VRF is refused, and a Node that is the exit of
// a VRF cannot be deleted until the VRF names another or none.
func TestEgressRejects(t *testing.T) {
	for _, c := range []struct{ egress, want string }{
		{"edge", `VRF "corp": egress: Node "edge" does not exist`},
		{"lab-1", `VRF "corp": egress: Node "lab-1" is not a member of the VRF`},
	} {
		_, err := Apply(New(), doc(
			res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "`+c.egress+`"}`),
			res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
			res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
			res(KindNode, "lab-1", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
		), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("egress %q: the error is %v, want one with %q", c.egress, err, c.want)
		}
	}

	// In a VRF of topology hub-and-spoke the spokes reach only the hub, so the hub is the exit and a spoke is none
	hub := func(egress string) []Resource {
		return []Resource{
			res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "topology": "hub-and-spoke", "hub": "gw", "egress": "`+egress+`"}`),
			res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
			res(KindNode, "site-1", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		}
	}
	want := `VRF "corp": egress: Node "site-1" is a spoke of the VRF of topology hub-and-spoke, whose other spokes reach only its hub: the egress is the hub "gw"`
	if _, err := Apply(New(), doc(hub("site-1")...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("a spoke as the exit: the error is %v, want one with %q", err, want)
	}
	if in, err := Apply(New(), doc(hub("gw")...), nil); err != nil || !slices.Equal(in.EgressVRFs("gw"), []string{"corp"}) {
		t.Errorf("the hub as the exit: %v", err)
	}

	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "gw"}`),
		res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindNode, "gw"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "gw" is the internet exit of VRF "corp"`) {
		t.Errorf("deleting the exit of a VRF: %v", err)
	}
	next, err := Apply(in, doc(res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(next, KindNode, "gw"); err != nil {
		t.Errorf("deleting a Node that is the exit of no VRF: %v", err)
	}
}

// The default route of an exit counts towards the routes that lead to one peer: the outside prefixes
// of the 16 1:1 NAT rules of x with the default route of the VRF whose exit x is are 17 routes from y.
func TestEgressRoutesAreBounded(t *testing.T) {
	rs := []Resource{
		res(KindVRF, "e", `{"id": 1, "ula": "fd00:1::/48", "egress": "x"}`),
		res(KindNetwork, "e-lan", `{"vrf": "e", "ipv4Pool": "10.5.0.0/24"}`),
		res(KindNode, "x", `{"publicKey": "`+key1+`", "vrfs": ["e"]}`),
		res(KindNode, "y", `{"publicKey": "`+key2+`", "vrfs": ["e"]}`),
	}
	for k := range MaxNATRules {
		rs = append(rs, nat(fmt.Sprintf("x-%02d", k), "e", "x", fmt.Sprintf("192.168.%d.0/24", k), fmt.Sprintf("10.200.%d.0/24", k)))
	}
	if _, err := Apply(New(), doc(rs...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "y": 17 routes lead to its peer "x"`) {
		t.Errorf("16 routes of 1:1 NAT rules and a default route to one peer: %v", err)
	}
	if _, err := Apply(New(), doc(rs[:len(rs)-1]...), nil); err != nil {
		t.Errorf("15 routes of 1:1 NAT rules and a default route to one peer: %v", err)
	}
}
