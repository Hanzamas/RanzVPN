package desired

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// linkResources returns the resources of a VRF dc with the link of kind, a VRF corp of kind noise, the Nodes gw
// and db in dc with their tunnel endpoints, and lab-1 in corp with gw.
func linkResources(kind string) []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "`+kind+`"}`),
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc", "corp"], "vtep": {"address": "10.1.0.1", "genevePort": 6100}}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "2001:db8::2"}}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
	}
}

// A VRF of kind vxlan or geneve carries its kind and its VNI in its Vrf object; each of its Nodes gets the ports of
// its own tunnel endpoint in its NodeConfig and the tunnel endpoint of each peer that shares it in the Peer object,
// which is the flood list of the VNI. A VRF of kind noise carries no kind, and a peer that shares only such a VRF
// carries no tunnel endpoint.
func TestCompileLinks(t *testing.T) {
	for _, c := range []struct {
		kind string
		want controlpb.LinkKind
	}{{intent.LinkVXLAN, controlpb.LinkKind_LINK_KIND_VXLAN}, {intent.LinkGeneve, controlpb.LinkKind_LINK_KIND_GENEVE}} {
		states := compile(t, linkResources(c.kind)...)

		dc := states["gw"][Key{controlpb.Kind_KIND_VRF, "dc"}].GetVrf()
		if dc.GetLink() != c.want || dc.GetVni() != 30 {
			t.Errorf("%s: the Vrf dc is %v", c.kind, dc)
		}
		corp := states["gw"][Key{controlpb.Kind_KIND_VRF, "corp"}].GetVrf()
		if corp.GetLink() != controlpb.LinkKind_LINK_KIND_UNSPECIFIED || corp.GetVni() != 0 {
			t.Errorf("%s: the Vrf corp, of kind noise, is %v", c.kind, corp)
		}

		if got, want := states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetVtep(), (&controlpb.Vtep{VxlanPort: 4789, GenevePort: 6100}); !proto.Equal(got, want) {
			t.Errorf("%s: the NodeConfig of gw has the vtep %v, want %v", c.kind, got, want)
		}
		if got := states["lab-1"][Key{controlpb.Kind_KIND_NODE, "lab-1"}].GetNode().GetVtep(); got != nil {
			t.Errorf("%s: the NodeConfig of lab-1, in no plain VRF, has the vtep %v", c.kind, got)
		}

		db := netip.MustParseAddr("2001:db8::2").AsSlice()
		if got, want := states["gw"][Key{controlpb.Kind_KIND_PEER, "db"}].GetPeer().GetVtep(), (&controlpb.Vtep{Address: db, VxlanPort: 4789, GenevePort: 6081}); !proto.Equal(got, want) {
			t.Errorf("%s: the Peer db of gw has the vtep %v, want %v", c.kind, got, want)
		}
		gw := netip.MustParseAddr("10.1.0.1").AsSlice()
		if got, want := states["db"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetVtep(), (&controlpb.Vtep{Address: gw, VxlanPort: 4789, GenevePort: 6100}); !proto.Equal(got, want) {
			t.Errorf("%s: the Peer gw of db has the vtep %v, want %v", c.kind, got, want)
		}
		if got := states["lab-1"][Key{controlpb.Kind_KIND_PEER, "gw"}].GetPeer().GetVtep(); got != nil {
			t.Errorf("%s: the Peer gw of lab-1, which shares only corp, has the vtep %v", c.kind, got)
		}
	}
}

// A switch of the kind of a link between noise and vxlan changes the state of the Nodes of the VRF, and of no other:
// the Vrf object, the NodeConfig and the Peer objects of the plain VRF. The delta of each changed Node is one Update,
// which takes the old state to the new one. A VRF of kind noise compiles as before the kinds existed.
func TestCompileLinkSwitch(t *testing.T) {
	noise := compile(t, linkResources(intent.LinkNoise)...)
	vxlan := compile(t, linkResources(intent.LinkVXLAN)...)
	plain := compile(t, linkResources("")...)

	for name := range noise {
		if !Equal(noise[name], plain[name]) {
			t.Errorf("%s: a VRF of kind noise compiles otherwise than one that names no kind", name)
		}
	}
	for _, name := range []string{"gw", "db"} {
		if Equal(noise[name], vxlan[name]) {
			t.Errorf("%s: the switch to vxlan does not change its state", name)
			continue
		}
		u := Delta(noise[name], 4, vxlan[name], 5)
		got, err := Apply(noise[name], 4, u)
		if err != nil || !Equal(got, vxlan[name]) {
			t.Errorf("%s: the delta of the switch does not take the old state to the new one: %v", name, err)
		}
		for _, o := range u.GetSet() {
			if k := KeyOf(o); k.Kind != controlpb.Kind_KIND_VRF && k.Kind != controlpb.Kind_KIND_NODE && k.Kind != controlpb.Kind_KIND_PEER {
				t.Errorf("%s: the delta of the switch sets %v", name, k)
			}
		}
		if len(u.GetRemove()) != 0 {
			t.Errorf("%s: the delta of the switch removes %v", name, u.GetRemove())
		}
	}
	if !Equal(noise["lab-1"], vxlan["lab-1"]) {
		t.Errorf("lab-1, outside dc, changes with the switch of the link of dc")
	}
}
