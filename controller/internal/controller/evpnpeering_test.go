// The EVPN peering of the standard mode in the controller conformance seam (SDN-78 #358): the Intent names the Nodes of a VRF that
// peer by EVPN, and the controller writes the configuration of the peers and nothing else: the settings of the sidecar of each Node
// in its NodeConfig, for each peer the address of its sidecar, the hold time, the VRF and what it may announce, and the L2 VNI of
// the L2 Network of the VRF. No Peer has a tunnel endpoint or a route for the VRF, which the Controller fills for a link of kind
// vxlan. EVPN is an Enterprise feature, which the licence in force must have, and a Node of the VRF needs the Capability
// evpnPeering.
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

// capsEVPNPeering is capsPeering with the Capability evpnPeering (SDN-78): a node that runs the EVPN peering of a VRF.
var capsEVPNPeering = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
	HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, PlainLinks: true, BgpPeering: true, EvpnPeering: true}

// networkObject returns the Network object named name among the objects that the update in m sets, nil for none.
func networkObject(m *controlpb.ControlMessage, name string) *controlpb.Network {
	for _, o := range m.GetUpdate().GetSet() {
		if nw := o.GetNetwork(); nw != nil && nw.GetName() == name {
			return nw
		}
	}
	return nil
}

// TestEVPNPeeringIsTheConfigurationOfThePeers is the fourth criterion of SDN-78 at the controller: gw-1 and db, which the Intent
// names as peers by EVPN in dc, get the settings of their sidecars, the L2 VNI of dc-l2 and the peering of each other, and neither
// the tunnel endpoint nor a route of the other in dc. Without an Enterprise licence the peering is refused before the intent. A
// node that does not report evpnPeering is refused as the capability package checks it (TestEVPNPeeringNeedsTheCapability).
func TestEVPNPeeringIsTheConfigurationOfThePeers(t *testing.T) {
	h := newHarness(t)

	_, err := h.tryApply("evpnpeering.json")
	want := `VRF "dc": the EVPN peering of its Nodes is part of EVPN and BGP, an Enterprise feature, and the licence in force is Personal`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("the EVPN peering under the Personal licence gave %v, want an error that says %q", err, want)
	}
	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	res := h.apply("evpnpeering.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 1}, {Name: "gw-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("evpnpeering.json changed %+v, want %+v", res.Nodes, want)
	}

	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsEVPNPeering
	gw.start(h)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = capsEVPNPeering
	db.start(h)

	m := gw.update(t)
	if v := vrfObject(m, "dc"); v.GetPeering() != controlpb.Peering_PEERING_EVPN || v.GetVni() != 30 {
		t.Errorf("the update of gw-1 has the Vrf dc %v, want the peering evpn with the L3 VNI 30", v)
	}
	if nw := networkObject(m, "dc-l2"); nw.GetVni() != 5010 {
		t.Errorf("the update of gw-1 has the Network dc-l2 %v, want the L2 VNI 5010", nw)
	}
	self := netip.MustParseAddr("10.1.0.1").AsSlice()
	wantNode := &controlpb.NodePeering{Asn: intent.PeeringASN, RouterId: self, Address: self, Announce: []*controlpb.Route{hostRoute(30, "192.168.10.0/24")}}
	if n := nodeObject(m); !proto.Equal(n.GetPeering(), wantNode) {
		t.Errorf("the update of gw-1 has the NodeConfig %v, want the peering %v", n, wantNode)
	}
	wantPeer := &controlpb.PeerPeering{Address: netip.MustParseAddr("10.1.0.2").AsSlice(), HoldTime: 9, VrfIds: []uint32{30},
		Accept: []*controlpb.Route{hostRoute(30, "10.30.0.2/32")}}
	if p := peerObject(m, "db"); !proto.Equal(p.GetPeering(), wantPeer) || p.GetVtep() != nil || len(p.GetRoutes()) != 0 {
		t.Errorf("the update of gw-1 has the Peer db %v, want the peering %v and no tunnel endpoint or route of the Controller", p, wantPeer)
	}
	if p := peerObject(db.update(t), "gw-1"); len(p.GetPeering().GetAccept()) != 2 || p.GetVtep() != nil || len(p.GetRoutes()) != 0 {
		t.Errorf("the update of db has the Peer gw-1 %v, want the address and the LAN subnet of gw-1 to take from it, and no tunnel endpoint or route", p)
	}
	h.waitNode("gw-1", 1, true)
	h.waitNode("db", 1, true)
	h.checkState(gw)
	h.checkState(db)
}
