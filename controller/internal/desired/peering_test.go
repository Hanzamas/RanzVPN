package desired

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// peeringResources returns VRF dc with the link vxlan, which peers by BGP with the hold time 9 unless
// dc is "", VRF lab with the link geneve, which peers with the hold time 30, and VRF corp of kind noise;
// the Network dc-net of dc; the Node gw in all three with its LAN subnets in each, db in dc and lab, and
// lab-1 in corp.
func peeringResources(dc string) []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"`+dc+`}`),
		res(intent.KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve", "peering": {"protocol": "bgp", "holdTime": 30}}`),
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc", "lab", "corp"], "vtep": {"address": "10.1.0.1"}, "addresses": {"dc-net": "10.30.0.1"},
			"lanSubnets": {"dc": ["192.168.10.0/24"], "lab": ["192.168.40.0/24"], "corp": ["192.168.99.0/24"]}}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.2"}, "addresses": {"dc-net": "10.30.0.2"}}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
	}
}

// route returns the Route of prefix in the VRF vrf.
func route(vrf uint32, p string) *controlpb.Route {
	return &controlpb.Route{VrfId: vrf, Prefix: prefix(netip.MustParsePrefix(p))}
}

// A VRF that peers by BGP carries its peering in its Vrf object. Each of its Nodes gets the settings
// of its sidecar in its NodeConfig, with the LAN subnets that it announces in the VRFs that peer, and
// each peer that shares such a VRF its address, the shortest hold time of those VRFs, their ids and
// what the peer may announce there: its addresses as host routes and its LAN subnets. A VRF that does
// not peer gives none of it.
func TestCompilePeering(t *testing.T) {
	states := compile(t, peeringResources(`, "peering": {"protocol": "bgp", "holdTime": 9}`)...)

	if got := states["gw"][Key{controlpb.Kind_KIND_VRF, "dc"}].GetVrf().GetPeering(); got != controlpb.Peering_PEERING_BGP {
		t.Errorf("the Vrf dc has the peering %v, want bgp", got)
	}
	if got := states["gw"][Key{controlpb.Kind_KIND_VRF, "corp"}].GetVrf().GetPeering(); got != controlpb.Peering_PEERING_UNSPECIFIED {
		t.Errorf("the Vrf corp, which does not peer, has the peering %v", got)
	}

	gw := netip.MustParseAddr("10.1.0.1").AsSlice()
	want := &controlpb.NodePeering{Asn: intent.PeeringASN, RouterId: gw, Address: gw,
		Announce: []*controlpb.Route{route(30, "192.168.10.0/24"), route(40, "192.168.40.0/24")}}
	if got := states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetPeering(); !proto.Equal(got, want) {
		t.Errorf("the NodeConfig of gw has the peering %v, want %v", got, want)
	}
	if got := states["lab-1"][Key{controlpb.Kind_KIND_NODE, "lab-1"}].GetNode().GetPeering(); got != nil {
		t.Errorf("the NodeConfig of lab-1, which peers in no VRF, has the peering %v", got)
	}

	ofGW := &controlpb.PeerPeering{Address: gw, HoldTime: 9, VrfIds: []uint32{30, 40},
		Accept: []*controlpb.Route{route(30, "10.30.0.1/32"), route(30, "192.168.10.0/24"), route(40, "192.168.40.0/24")}}
	if got := states["db"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetPeering(); !proto.Equal(got, ofGW) {
		t.Errorf("the Peer gw of db has the peering %v, want %v", got, ofGW)
	}
	db := netip.MustParseAddr("10.1.0.2").AsSlice()
	ofDB := &controlpb.PeerPeering{Address: db, HoldTime: 9, VrfIds: []uint32{30, 40}, Accept: []*controlpb.Route{route(30, "10.30.0.2/32")}}
	if got := states["gw"][Key{controlpb.Kind_KIND_PEER, "db"}].GetPeer().GetPeering(); !proto.Equal(got, ofDB) {
		t.Errorf("the Peer db of gw has the peering %v, want %v", got, ofDB)
	}
	if got := states["lab-1"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetPeering(); got != nil {
		t.Errorf("the Peer gw of lab-1, which shares only corp, has the peering %v", got)
	}

	// Without the peering of dc, the two peer in lab alone, with its hold time
	states = compile(t, peeringResources("")...)
	ofGW = &controlpb.PeerPeering{Address: gw, HoldTime: 30, VrfIds: []uint32{40}, Accept: []*controlpb.Route{route(40, "192.168.40.0/24")}}
	if got := states["db"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetPeering(); !proto.Equal(got, ofGW) {
		t.Errorf("without the peering of dc the Peer gw of db has the peering %v, want %v", got, ofGW)
	}
}

// The end of the peering of a VRF changes the state of its Nodes, and of no other: the Vrf object, the
// NodeConfig and the Peer objects. The delta of each changed Node is one Update, which takes the old
// state to the new one.
func TestCompilePeeringSwitch(t *testing.T) {
	bgp := compile(t, peeringResources(`, "peering": {"protocol": "bgp", "holdTime": 9}`)...)
	none := compile(t, peeringResources("")...)

	for _, name := range []string{"gw", "db"} {
		if Equal(bgp[name], none[name]) {
			t.Errorf("%s: the end of the peering of dc does not change its state", name)
			continue
		}
		u := Delta(bgp[name], 4, none[name], 5)
		got, err := Apply(bgp[name], 4, u)
		if err != nil || !Equal(got, none[name]) {
			t.Errorf("%s: the delta of the end of the peering does not take the old state to the new one: %v", name, err)
		}
		for _, o := range u.GetSet() {
			if k := KeyOf(o); k.Kind != controlpb.Kind_KIND_VRF && k.Kind != controlpb.Kind_KIND_NODE && k.Kind != controlpb.Kind_KIND_PEER {
				t.Errorf("%s: the delta of the end of the peering sets %v", name, k)
			}
		}
		if len(u.GetRemove()) != 0 {
			t.Errorf("%s: the delta of the end of the peering removes %v", name, u.GetRemove())
		}
	}
	if !Equal(bgp["lab-1"], none["lab-1"]) {
		t.Errorf("lab-1, outside dc, changes with the end of the peering of dc")
	}
}
