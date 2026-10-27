// The BGP peering of the standard mode in the controller conformance seam (SDN-77 #357): the Intent
// names the Nodes of a VRF that peer by BGP, and the controller turns it into the settings of the
// sidecar of each Node and nothing else: its own in its NodeConfig, and for each peer the address of
// the peer's sidecar, the hold time, the VRFs of the session and what the peer may announce there. The
// end of the peering is one Generation of the Nodes of the VRF. BGP is an Enterprise feature, which the
// licence in force must have.
package controller_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// hostRoute returns the Route of the prefix p in the VRF vrf.
func hostRoute(vrf uint32, p string) *controlpb.Route {
	pp := netip.MustParsePrefix(p)
	return &controlpb.Route{VrfId: vrf, Prefix: &controlpb.Prefix{Address: pp.Addr().AsSlice(), Length: uint32(pp.Bits())}}
}

// TestPeeringIsTheSettingsOfTheSidecars is the first criterion of SDN-77 at the controller: gw-1 and db,
// which the Intent names as peers in dc, get the settings of their sidecars, and lab-1, outside dc, gets
// none; without the peering each loses them in one Generation, and lab-1 keeps its own.
func TestPeeringIsTheSettingsOfTheSidecars(t *testing.T) {
	h := newHarness(t)

	// BGP is an Enterprise feature: without such a licence the peering is refused before the intent
	_, err := h.tryApply("peering.json")
	want := `VRF "dc": the BGP peering of its Nodes is part of EVPN and BGP, an Enterprise feature, and the licence in force is Personal`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("the peering under the Personal licence gave %v, want an error that says %q", err, want)
	}
	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	res := h.apply("peering.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 1}, {Name: "gw-1", Generation: 1}, {Name: "lab-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("peering.json changed %+v, want %+v", res.Nodes, want)
	}

	plain := proto.Clone(capsServer).(*controlpb.Capabilities)
	plain.PlainLinks = true
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = plain
	gw.start(h)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = plain
	db.start(h)

	m := gw.update(t)
	if v := vrfObject(m, "dc"); v.GetPeering() != controlpb.Peering_PEERING_BGP {
		t.Errorf("the update of gw-1 has the Vrf dc %v, want the peering bgp", v)
	}
	self := netip.MustParseAddr("10.1.0.1").AsSlice()
	wantNode := &controlpb.NodePeering{Asn: intent.PeeringASN, RouterId: self, Address: self, Announce: []*controlpb.Route{hostRoute(30, "192.168.10.0/24")}}
	if n := nodeObject(m); !proto.Equal(n.GetPeering(), wantNode) {
		t.Errorf("the update of gw-1 has the NodeConfig %v, want the peering %v", n, wantNode)
	}
	wantPeer := &controlpb.PeerPeering{Address: netip.MustParseAddr("10.1.0.2").AsSlice(), HoldTime: 9, VrfIds: []uint32{30},
		Accept: []*controlpb.Route{hostRoute(30, "10.30.0.2/32")}}
	if p := peerObject(m, "db"); !proto.Equal(p.GetPeering(), wantPeer) {
		t.Errorf("the update of gw-1 has the Peer db %v, want the peering %v", p, wantPeer)
	}
	if p := peerObject(db.update(t), "gw-1"); len(p.GetPeering().GetAccept()) != 2 {
		t.Errorf("the update of db has the Peer gw-1 %v, want the address and the LAN subnet of gw-1 to take from it", p)
	}
	h.waitNode("gw-1", 1, true)
	h.waitNode("db", 1, true)
	h.checkState(gw)
	h.checkState(db)

	// The end of the peering is one Generation of gw-1 and db, whose objects carry no peering any more
	res = h.apply("peering-off.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 2}, {Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("peering-off.json changed %+v, want %+v", res.Nodes, want)
	}
	m = gw.update(t)
	if p := peerObject(m, "db"); p == nil || p.GetPeering() != nil {
		t.Errorf("the update of gw-1 without the peering has the Peer db %v, want no peering", p)
	}
	if n := nodeObject(m); n == nil || n.GetPeering() != nil {
		t.Errorf("the update of gw-1 without the peering has the NodeConfig %v, want no peering", n)
	}
	if v := vrfObject(m, "dc"); v == nil || v.GetPeering() != controlpb.Peering_PEERING_UNSPECIFIED {
		t.Errorf("the update of gw-1 without the peering has the Vrf dc %v", v)
	}
	db.update(t)
	h.waitNode("gw-1", 2, true)
	h.waitNode("db", 2, true)
	h.checkState(gw)
	h.checkState(db)
}
