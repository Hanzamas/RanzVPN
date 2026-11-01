package intent

import (
	"slices"
	"strings"
	"testing"
)

// key5 is a fifth key of a Node, for a VRF of two reflectors and three clients.
const key5 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// reflectorResources returns VRF dc, which peers by BGP with the reflectors of the JSON reflectors (a list
// of names, or "" for none), and VRF lab, which peers in a full mesh; the reflectors r and s in dc, the
// clients a and b in dc and lab, and the client c in dc.
func reflectorResources(reflectors string) Document {
	peering := `{"protocol": "bgp"`
	if reflectors != "" {
		peering += `, "reflectors": ` + reflectors
	}
	return doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": `+peering+`}}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res(KindNode, "r", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res(KindNode, "s", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
		res(KindNode, "a", `{"publicKey": "`+key3+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.3"}}`),
		res(KindNode, "b", `{"publicKey": "`+key4+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.4"}}`),
		res(KindNode, "c", `{"publicKey": "`+key5+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.5"}}`),
	)
}

// A VRF that peers by BGP names its route reflectors, which complete in name order and read back from the
// resources (SDN-79). Each Node of the VRF has a role for each other: a reflector is one for every Node, a
// client is one for a reflector, and two clients are reflected for each other. Two Nodes have a session
// unless they are clients of the reflectors of every VRF that they share: a and b keep theirs for lab, a
// and c have none, and the two reflectors have one.
func TestApplyReflectors(t *testing.T) {
	in, err := Apply(New(), reflectorResources(`["s", "r"]`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.VRFs["dc"].Peering.Reflectors; !slices.Equal(got, []string{"r", "s"}) {
		t.Errorf("the reflectors of dc are %v, want r and s", got)
	}
	for _, c := range []struct {
		node, peer, vrf, want string
	}{
		{"a", "r", "dc", RoleReflector},
		{"r", "a", "dc", RoleClient},
		{"r", "s", "dc", RoleReflector},
		{"a", "c", "dc", RoleReflected},
		{"a", "b", "lab", RoleMesh},
	} {
		if got := in.PeeringRole(c.node, c.peer, c.vrf); got != c.want {
			t.Errorf("the role of %s for %s in %s is %q, want %q", c.peer, c.node, c.vrf, got, c.want)
		}
	}
	for _, c := range []struct {
		node, peer string
		want       bool
	}{
		{"a", "r", true},
		{"r", "s", true},
		{"a", "c", false},
		{"c", "b", false},
		{"a", "b", true},
		{"a", "a", false},
	} {
		if got := in.PeeringSession(c.node, c.peer); got != c.want {
			t.Errorf("%s and %s have a session %v, want %v", c.node, c.peer, got, c.want)
		}
	}

	again, err := Apply(in, doc(in.Resources()...), nil)
	if err != nil || !slices.Equal(again.VRFs["dc"].Peering.Reflectors, []string{"r", "s"}) {
		t.Errorf("the resources applied again: %v, the reflectors of dc %v", err, again.VRFs["dc"].Peering.Reflectors)
	}
	for _, r := range in.Resources() {
		if r.Kind == KindVRF && r.Name == "lab" && strings.Contains(string(r.Spec), "reflectors") {
			t.Errorf("the resource of VRF lab, which names no reflectors, is %s", r.Spec)
		}
	}

	// Without reflectors every two Nodes of dc peer, and have a session
	mesh, err := Apply(New(), reflectorResources(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := mesh.PeeringRole("a", "c", "dc"); got != RoleMesh || !mesh.PeeringSession("a", "c") {
		t.Errorf("without reflectors the role of c for a is %q and their session %v, want a full mesh", got, mesh.PeeringSession("a", "c"))
	}
}

// Route reflectors are refused, naming the VRF and the reflector, without the protocol bgp, more than two of
// them, one named twice, one that is no Node, and one that is no member of the VRF.
func TestApplyReflectorsRejects(t *testing.T) {
	for _, c := range []struct {
		reflectors string
		want       string
	}{
		{`["r", "s", "a"]`, `VRF "dc": the peering names 3 reflectors, and a VRF has 2 at most`},
		{`["r", "r"]`, `VRF "dc": the peering names the reflector "r" twice`},
		{`["nowhere"]`, `VRF "dc": the peering reflector "nowhere" is no Node`},
	} {
		_, err := Apply(New(), reflectorResources(c.reflectors), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("the reflectors %s gave %v, want an error that says %q", c.reflectors, err, c.want)
		}
	}

	// A reflector outside the VRF: lab peers in a full mesh of a and b, and r is no member of it
	in := reflectorResources("")
	in.Resources[1] = res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan", "peering": {"protocol": "bgp", "reflectors": ["r"]}}`)
	if _, err := Apply(New(), in, nil); err == nil || !strings.Contains(err.Error(), `VRF "lab": the peering reflector "r" is not a member of the VRF`) {
		t.Errorf("a reflector outside the VRF gave %v", err)
	}

	// Reflectors without the protocol bgp
	in = reflectorResources("")
	in.Resources[1] = res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan", "peering": {"reflectors": ["a"]}}`)
	if _, err := Apply(New(), in, nil); err == nil || !strings.Contains(err.Error(), `VRF "lab": the peering reflectors need the peering protocol bgp`) {
		t.Errorf("reflectors without the protocol gave %v", err)
	}
}
