package desired

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// sameEndpoints reports whether got holds the endpoints of want, in the same order.
func sameEndpoints(got, want []*controlpb.Endpoint) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

// The endpoints of a Node are in the Peer object of every Node that has it as a peer, in the order of its
// resource, and in its own NodeConfig; a Node that has none has none in either place. A change of the endpoints
// of one Node changes the state of that Node and of its peers, and of no other Node.
func TestCompileEndpoints(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "hub", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "endpoints": [{"transport": "quic", "address": "hub.example.com:443"}, {"transport": "tls", "address": "192.0.2.10:443"}, {"transport": "mimic", "address": "[2001:db8::10]:8443"}]}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["lab"]}`),
	}
	want := []*controlpb.Endpoint{
		{Transport: controlpb.Transport_TRANSPORT_QUIC, Address: "hub.example.com:443"},
		{Transport: controlpb.Transport_TRANSPORT_TLS, Address: "192.0.2.10:443"},
		{Transport: controlpb.Transport_TRANSPORT_MIMIC, Address: "[2001:db8::10]:8443"},
	}
	states := compile(t, rs...)

	if got := states["hub"][Key{controlpb.Kind_KIND_NODE, "hub"}].GetNode().GetEndpoints(); !sameEndpoints(got, want) {
		t.Errorf("the NodeConfig of hub has the endpoints %v, want %v", got, want)
	}
	if got := states["gw"][Key{controlpb.Kind_KIND_PEER, "hub"}].GetPeer().GetEndpoints(); !sameEndpoints(got, want) {
		t.Errorf("the Peer hub of gw has the endpoints %v, want %v", got, want)
	}
	if got := states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetEndpoints(); len(got) != 0 {
		t.Errorf("the NodeConfig of gw, which names none, has the endpoints %v", got)
	}
	if got := states["hub"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetEndpoints(); len(got) != 0 {
		t.Errorf("the Peer gw of hub, which names none, has the endpoints %v", got)
	}
	for k := range states["lab-1"] {
		if k.Kind == controlpb.Kind_KIND_PEER {
			t.Errorf("lab-1, which shares no VRF with another Node, has the peer %q", k.Name)
		}
	}

	// The endpoints of hub change: its state and the state of gw change, the state of lab-1 does not
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := intent.Apply(in, intent.Document{Resources: []intent.Resource{
		res(intent.KindNode, "hub", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "endpoints": [{"transport": "tls", "address": "192.0.2.10:443"}, {"transport": "quic", "address": "hub.example.com:443"}]}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Compile(next)
	if err != nil {
		t.Fatal(err)
	}
	moved := []*controlpb.Endpoint{want[1], want[0]}

	u := Delta(states["hub"], 1, after["hub"], 2)
	if len(u.GetSet()) != 1 || len(u.GetRemove()) != 0 || !sameEndpoints(u.GetSet()[0].GetNode().GetEndpoints(), moved) {
		t.Errorf("the update of hub is %v, want its NodeConfig alone, with the endpoints in their new order", u)
	}
	u = Delta(states["gw"], 1, after["gw"], 2)
	if len(u.GetSet()) != 1 || len(u.GetRemove()) != 0 || u.GetSet()[0].GetPeer().GetName() != "hub" || !sameEndpoints(u.GetSet()[0].GetPeer().GetEndpoints(), moved) {
		t.Errorf("the update of gw is %v, want its Peer hub alone, with the endpoints in their new order", u)
	}
	if u := Delta(states["lab-1"], 1, after["lab-1"], 2); len(u.GetSet()) != 0 || len(u.GetRemove()) != 0 {
		t.Errorf("the endpoints of hub changed the state of lab-1, which shares no VRF with it: %v", u)
	}

	// The same endpoints applied again change nothing
	same, err := intent.Apply(in, intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Compile(same)
	if err != nil {
		t.Fatal(err)
	}
	for node := range states {
		if !Equal(states[node], again[node]) {
			t.Errorf("the state of %s changed when the same intent was applied again", node)
		}
	}
}

// A peer that a leak joins to a node, which shares no VRF with it, has its endpoints too: the node dials it
// there, and a node that no leak joins to it, or that it does not join, gets none of them.
func TestCompileEndpointsOfLeakedPeers(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "shared", `{"id": 10, "ula": "fd00:10::/48", "exportTargets": ["64512:10"], "importTargets": ["64512:1"]}`),
		res(intent.KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(intent.KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(intent.KindNetwork, "shared-lan", `{"vrf": "shared", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(intent.KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(intent.KindNode, "dns", `{"publicKey": "`+key1+`", "vrfs": ["shared"], "endpoints": [{"transport": "tls", "address": "dns.example.com:443"}]}`),
		res(intent.KindNode, "r", `{"publicKey": "`+key2+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key3+`", "vrfs": ["blue"]}`),
	)
	want := []*controlpb.Endpoint{{Transport: controlpb.Transport_TRANSPORT_TLS, Address: "dns.example.com:443"}}

	for _, node := range []string{"r", "b"} {
		p := states[node][Key{controlpb.Kind_KIND_PEER, "dns"}].GetPeer()
		if len(p.GetVrfIds()) != 0 || !sameEndpoints(p.GetEndpoints(), want) {
			t.Errorf("the Peer dns of %s shares the VRFs %v and has the endpoints %v, want no shared VRF and %v", node, p.GetVrfIds(), p.GetEndpoints(), want)
		}
	}
	for _, peer := range []string{"r", "b"} {
		p := states["dns"][Key{controlpb.Kind_KIND_PEER, peer}].GetPeer()
		if p == nil || len(p.GetEndpoints()) != 0 {
			t.Errorf("the Peer %s of dns is %v, want it without endpoints", peer, p)
		}
	}
	if _, ok := states["r"][Key{controlpb.Kind_KIND_PEER, "b"}]; ok {
		t.Error("r and b are peers, which no leak joins")
	}
}
