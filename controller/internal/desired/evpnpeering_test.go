package desired

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// evpnPeeringResources returns VRF dc of a link of kind vxlan with the peering peering, its L3 Network dc-net and its L2
// Network dc-l2, with the L2 VNI 5010 when the VRF peers by EVPN, and the Nodes a and b in dc, each with a LAN subnet there.
func evpnPeeringResources(peering string) []intent.Resource {
	l2 := `{"vrf": "dc", "mode": "L2"}`
	if peering != "" {
		peering = `, "peering": {"protocol": "` + peering + `", "holdTime": 9}`
		l2 = `{"vrf": "dc", "mode": "L2", "vni": 5010}`
	}
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"`+peering+`}`),
		res(intent.KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}`),
		res(intent.KindNetwork, "dc-l2", l2),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}, "addresses": {"dc-net": "10.30.0.1"}, "lanSubnets": {"dc": ["192.168.10.0/24"]}}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}, "addresses": {"dc-net": "10.30.0.2"}, "lanSubnets": {"dc": ["192.168.20.0/24"]}}`),
	}
}

// In a VRF whose Nodes peer by EVPN the Controller writes only the configuration of the peers (SDN-78): the Vrf object says
// evpn, with the VNI of the VRF as its L3 VNI; the L2 Network has its L2 VNI at every Node of the VRF, and the L3 Network none;
// each Node has the settings of its sidecar and announces its LAN subnet, and its Peer object has the address of the sidecar of
// the peer, the hold time, the VRF and what the peer may announce there. The VRF does not also use the form of the links of
// kind vxlan that the Controller fills (SDN-76): no Peer has a tunnel endpoint for it, the flood list of the VRF, or a route of
// the LAN subnet of the peer, as the same VRF without the peering has.
func TestCompileEVPNPeering(t *testing.T) {
	states := compile(t, evpnPeeringResources(intent.PeeringEVPN)...)
	addr := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

	for _, node := range []string{"a", "b"} {
		v := states[node][Key{controlpb.Kind_KIND_VRF, "dc"}].GetVrf()
		if v.GetPeering() != controlpb.Peering_PEERING_EVPN || v.GetLink() != controlpb.LinkKind_LINK_KIND_VXLAN || v.GetVni() != 30 {
			t.Errorf("the Vrf dc of %s is %v, want the peering evpn on the link vxlan with the L3 VNI 30", node, v)
		}
		if got := states[node][Key{controlpb.Kind_KIND_NETWORK, "dc-l2"}].GetNetwork().GetVni(); got != 5010 {
			t.Errorf("the L2 Network dc-l2 of %s has the VNI %d, want its L2 VNI 5010", node, got)
		}
		if got := states[node][Key{controlpb.Kind_KIND_NETWORK, "dc-net"}].GetNetwork().GetVni(); got != 0 {
			t.Errorf("the L3 Network dc-net of %s has the VNI %d, want none", node, got)
		}
		// The ports of its own tunnel endpoint, where the VTEP of its EVPN listens
		if got := states[node][Key{controlpb.Kind_KIND_NODE, node}].GetNode().GetVtep(); !proto.Equal(got, &controlpb.Vtep{VxlanPort: 4789, GenevePort: 6081}) {
			t.Errorf("the tunnel endpoint of %s in its NodeConfig is %v", node, got)
		}
	}

	own := &controlpb.NodePeering{Asn: intent.PeeringASN, RouterId: addr("10.1.0.1"), Address: addr("10.1.0.1"), Announce: []*controlpb.Route{route(30, "192.168.10.0/24")}}
	if got := states["a"][Key{controlpb.Kind_KIND_NODE, "a"}].GetNode().GetPeering(); !proto.Equal(got, own) {
		t.Errorf("the peering of a in its NodeConfig is %v, want %v", got, own)
	}
	ofB := &controlpb.PeerPeering{Address: addr("10.1.0.2"), HoldTime: 9, VrfIds: []uint32{30}, Accept: []*controlpb.Route{route(30, "10.30.0.2/32"), route(30, "192.168.20.0/24")}}
	peer := states["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer()
	if got := peer.GetPeering(); !proto.Equal(got, ofB) {
		t.Errorf("the Peer b of a has the peering %v, want %v", got, ofB)
	}
	if peer.GetVtep() != nil || len(peer.GetRoutes()) != 0 {
		t.Errorf("the Peer b of a has the tunnel endpoint %v and the routes %v, which the routes of the peers give in a VRF that peers by EVPN", peer.GetVtep(), peer.GetRoutes())
	}

	// The same VRF without the peering: the Controller fills the tunnel endpoint and the route of the LAN subnet of the peer
	plain := compile(t, evpnPeeringResources("")...)["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer()
	if !proto.Equal(plain.GetVtep(), &controlpb.Vtep{Address: addr("10.1.0.2"), VxlanPort: 4789, GenevePort: 6081}) || len(plain.GetRoutes()) != 1 || plain.GetPeering() != nil {
		t.Errorf("the Peer b of a in the VRF without the peering is %v, want its tunnel endpoint and its LAN subnet as its route, and no peering", plain)
	}

	// A VRF that peers by BGP keeps the tunnel endpoint of its peers, where its links carry its packets
	rs := evpnPeeringResources("")
	rs[0] = res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`)
	if got := compile(t, rs...)["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer(); got.GetVtep() == nil || got.GetPeering() == nil {
		t.Errorf("the Peer b of a in a VRF that peers by BGP is %v, want its tunnel endpoint and its peering", got)
	}
}
