package desired

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// reflectorResources returns VRF dc, which peers by BGP with the reflector rr, and VRF lab, which peers in a
// full mesh; the Network dc-net; the reflector rr in dc, the client a in dc and lab, and the client b in dc,
// each with a LAN subnet in dc.
func reflectorResources() []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp", "holdTime": 9, "reflectors": ["rr"]}}`),
		res(intent.KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan", "peering": {"protocol": "bgp", "holdTime": 9}}`),
		res(intent.KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}`),
		res(intent.KindNode, "rr", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}, "addresses": {"dc-net": "10.30.0.1"}, "lanSubnets": {"dc": ["192.168.10.0/24"]}}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key2+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.2"}, "addresses": {"dc-net": "10.30.0.2"}, "lanSubnets": {"dc": ["192.168.20.0/24"]}}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.3"}, "addresses": {"dc-net": "10.30.0.3"}, "lanSubnets": {"dc": ["192.168.30.0/24"]}}`),
	}
}

// The Controller writes the peer configuration of the reflector and of each client (SDN-79). The Vrf object of
// dc names its reflector. The reflector gets each client as a client in dc, with what it may announce there; a
// client gets the reflector as a reflector in dc, and the other client as reflected there, with what it may
// announce, which it needs to check the routes of the reflector. A VRF of a full mesh gives no role.
func TestCompileReflectors(t *testing.T) {
	states := compile(t, reflectorResources()...)

	for _, node := range []string{"rr", "a", "b"} {
		if got := states[node][Key{controlpb.Kind_KIND_VRF, "dc"}].GetVrf().GetReflectors(); !slices.Equal(got, []string{"rr"}) {
			t.Errorf("the Vrf dc of %s names the reflectors %v, want rr", node, got)
		}
	}
	if got := states["a"][Key{controlpb.Kind_KIND_VRF, "lab"}].GetVrf().GetReflectors(); len(got) != 0 {
		t.Errorf("the Vrf lab, a full mesh, names the reflectors %v", got)
	}

	addr := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	ofA := &controlpb.PeerPeering{Address: addr("10.1.0.2"), HoldTime: 9, VrfIds: []uint32{30},
		Accept: []*controlpb.Route{route(30, "10.30.0.2/32"), route(30, "192.168.20.0/24")}, ClientVrfIds: []uint32{30}}
	if got := states["rr"][Key{controlpb.Kind_KIND_PEER, "a"}].GetPeer().GetPeering(); !proto.Equal(got, ofA) {
		t.Errorf("the Peer a of the reflector has the peering %v, want %v", got, ofA)
	}
	ofRR := &controlpb.PeerPeering{Address: addr("10.1.0.1"), HoldTime: 9, VrfIds: []uint32{30},
		Accept: []*controlpb.Route{route(30, "10.30.0.1/32"), route(30, "192.168.10.0/24")}, ReflectorVrfIds: []uint32{30}}
	if got := states["b"][Key{controlpb.Kind_KIND_PEER, "rr"}].GetPeer().GetPeering(); !proto.Equal(got, ofRR) {
		t.Errorf("the Peer rr of client b has the peering %v, want %v", got, ofRR)
	}
	ofB := &controlpb.PeerPeering{Address: addr("10.1.0.3"), HoldTime: 9, VrfIds: []uint32{30},
		Accept: []*controlpb.Route{route(30, "10.30.0.3/32"), route(30, "192.168.30.0/24")}, ReflectedVrfIds: []uint32{30}}
	if got := states["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer().GetPeering(); !proto.Equal(got, ofB) {
		t.Errorf("the Peer b of client a has the peering %v, want %v", got, ofB)
	}
	// The LAN subnets of dc still go by BGP: no Peer has a route of them
	for _, k := range []struct{ node, peer string }{{"a", "b"}, {"b", "a"}, {"a", "rr"}, {"rr", "b"}} {
		if got := states[k.node][Key{controlpb.Kind_KIND_PEER, k.peer}].GetPeer().GetRoutes(); len(got) != 0 {
			t.Errorf("the Peer %s of %s has the routes %v, which go by BGP", k.peer, k.node, got)
		}
	}
}
