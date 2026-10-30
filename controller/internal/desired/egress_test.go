package desired

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// egressResources returns the resources of a VRF corp whose internet exit is the Node exit, a VRF lab
// with no exit, the Nodes gw and laptop in both, and lab-1 in lab only.
func egressResources(exit string) []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "`+exit+`"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["lab"]}`),
	}
}

// The exit of corp gets the id of corp in its NodeConfig, and every other Node of corp the default route
// 0.0.0.0/0 of corp as a route of the Peer of the exit; no Node gets a default route in lab, which has no
// exit, and the exit gets none to itself or to the other Nodes.
func TestCompileEgress(t *testing.T) {
	states := compile(t, egressResources("gw")...)

	if got := states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetEgressVrfIds(); !slices.Equal(got, []uint32{10}) {
		t.Errorf("the NodeConfig of gw has the egress VRFs %v, want [10]", got)
	}
	for _, name := range []string{"laptop", "lab-1"} {
		if got := states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetEgressVrfIds(); len(got) != 0 {
			t.Errorf("the NodeConfig of %s has the egress VRFs %v", name, got)
		}
	}

	want := &controlpb.Route{VrfId: 10, Prefix: &controlpb.Prefix{Address: netip.IPv4Unspecified().AsSlice(), Length: 0}}
	if got := states["laptop"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetRoutes(); len(got) != 1 || !proto.Equal(got[0], want) {
		t.Errorf("the Peer gw of laptop has the routes %v, want the default route of corp", got)
	}
	if got := states["lab-1"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetRoutes(); len(got) != 0 {
		t.Errorf("the Peer gw of lab-1, which shares only lab, has the routes %v", got)
	}
	if got := states["gw"][Key{controlpb.Kind_KIND_PEER, "laptop"}].GetPeer().GetRoutes(); len(got) != 0 {
		t.Errorf("the Peer laptop of gw, the exit, has the routes %v", got)
	}
}

// A move of the exit of corp from gw to laptop changes the states of the Nodes of corp, and of no other:
// the NodeConfig of the old and the new exit and their Peer objects. The delta of each changed Node takes
// its old state to the new one. A VRF without an exit compiles as before the exits existed.
func TestCompileEgressMove(t *testing.T) {
	gw := compile(t, egressResources("gw")...)
	laptop := compile(t, egressResources("laptop")...)
	none := compile(t, egressResources("")...)

	if got := laptop["gw"][Key{controlpb.Kind_KIND_PEER, "laptop"}].GetPeer().GetRoutes(); len(got) != 1 || got[0].GetVrfId() != 10 || got[0].GetPrefix().GetLength() != 0 {
		t.Errorf("once laptop is the exit, the Peer laptop of gw has the routes %v", got)
	}
	for _, name := range []string{"gw", "laptop"} {
		if Equal(gw[name], laptop[name]) {
			t.Errorf("%s: the move of the exit does not change its state", name)
			continue
		}
		u := Delta(gw[name], 7, laptop[name], 8)
		got, err := Apply(gw[name], 7, u)
		if err != nil || !Equal(got, laptop[name]) {
			t.Errorf("%s: the delta of the move does not take the old state to the new one: %v", name, err)
		}
		for _, o := range u.GetSet() {
			if k := KeyOf(o); k.Kind != controlpb.Kind_KIND_NODE && k.Kind != controlpb.Kind_KIND_PEER {
				t.Errorf("%s: the delta of the move sets %v", name, k)
			}
		}
		if len(u.GetRemove()) != 0 {
			t.Errorf("%s: the delta of the move removes %v", name, u.GetRemove())
		}
	}
	if !Equal(gw["lab-1"], laptop["lab-1"]) {
		t.Errorf("lab-1, outside corp, changes with the move of the exit of corp")
	}
	for name, s := range none {
		for _, o := range s.Objects() {
			if ids := o.GetNode().GetEgressVrfIds(); len(ids) != 0 {
				t.Errorf("%s: with no exit, the NodeConfig has the egress VRFs %v", name, ids)
			}
			if routes := o.GetPeer().GetRoutes(); len(routes) != 0 {
				t.Errorf("%s: with no exit, the Peer %s has the routes %v", name, o.GetPeer().GetName(), routes)
			}
		}
	}
}
