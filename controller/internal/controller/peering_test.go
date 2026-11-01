// The BGP peering of the standard mode in the controller conformance seam (SDN-77 #357): the Intent
// names the Nodes of a VRF that peer by BGP, and the controller turns it into the settings of the
// sidecar of each Node and nothing else: its own in its NodeConfig, and for each peer the address of
// the peer's sidecar, the hold time, the VRFs of the session and what the peer may announce there. The
// end of the peering is one Generation of the Nodes of the VRF. BGP is an Enterprise feature, which the
// licence in force must have.
package controller_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

var (
	// capsPlain is a Windows Server gateway of the release of SDN-76: capsServer with the Capability plainLinks, which runs the
	// links of kind vxlan and geneve, and not the peering of the release after it.
	capsPlain = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
		HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, PlainLinks: true}
	// capsPeering is capsPlain with the Capability bgpPeering (SDN-77-R2): a node that runs the peering of a VRF.
	capsPeering = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
		HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, PlainLinks: true, BgpPeering: true}
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

	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsPeering
	gw.start(h)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = capsPeering
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

// TestPeeringNeedsTheCapability is the first criterion of SDN-77-R2 at the controller. gw-1 is a node of the
// release of SDN-76: it reports plainLinks and not bgpPeering, so it would ignore the settings of its sidecar
// and lose every LAN route of dc, which the Controller no longer gives it, and its own LAN subnets would be
// gone from the other nodes, all without an error. The peering of dc is refused before it applies, naming the
// Node, the VRF and the Capability, and nothing of it reaches any node; db, which reports it, is not named.
// Once gw-1 reports it in its next Hello the peering is one Generation of gw-1 and db, and a node that comes
// back without the Capability is refused at its Hello.
func TestPeeringNeedsTheCapability(t *testing.T) {
	h := newHarness(t)
	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	h.apply("links.json")
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsPlain
	gw.start(h)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = capsPeering
	db.start(h)
	gw.update(t)
	db.update(t)
	h.waitNode("gw-1", 1, true)
	h.waitNode("db", 1, true)
	before := h.resources()

	_, err := h.tryApply("peering.json")
	if err == nil {
		t.Fatal("the peering of dc was applied with gw-1, which does not report bgpPeering")
	}
	for _, want := range []string{`Node "gw-1" (Server, x64): BGP peering of VRF "dc" needs bgpPeering, which the node does not report`, capability.ErrMissing.Error()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal is %q, want it to say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `Node "db"`) {
		t.Errorf("the refusal names db, which reports bgpPeering: %v", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	h.waitNode("gw-1", 1, true)
	h.waitNode("db", 1, true)

	// gw-1 reports the Capability in its next Hello: the peering is one Generation of gw-1 and db, and not of lab-1. The
	// Controller shows the stream that just ended as connected until it reads its end, so the node is waited for to be gone
	// first, and the wait for it to be back is the one for the stream with the new Hello
	gw.halt()
	h.waitNode("gw-1", 1, false)
	gw.Capabilities = capsPeering
	gw.start(h)
	h.waitNode("gw-1", 1, true)
	res := h.apply("peering.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 2}, {Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("peering.json changed %+v, want %+v", res.Nodes, want)
	}
	if v := vrfObject(gw.update(t), "dc"); v.GetPeering() != controlpb.Peering_PEERING_BGP {
		t.Errorf("the update of gw-1 has the Vrf dc %v, want the peering bgp", v)
	}
	db.update(t)
	h.waitNode("gw-1", 2, true)
	h.waitNode("db", 2, true)
	h.checkState(gw)
	h.checkState(db)

	// A node that comes back without the Capability, as one that an older release replaced, is refused at its Hello
	db.halt()
	db.Capabilities = capsPlain
	db.start(h)
	refuse := db.refusal(t).GetRefuse()
	if want := `Node "db" (Server, x64): BGP peering of VRF "dc" needs bgpPeering, which the node does not report`; refuse.GetReason() != controlpb.RefuseReason_REFUSE_REASON_CAPABILITY || !strings.Contains(refuse.GetMessage(), want) {
		t.Errorf("the Hello of db without bgpPeering was refused with %v, want the reason capability and a message with %q", refuse, want)
	}
}

// TestPeeringReportReachesTheAPI is the last criterion of SDN-77 at the controller: what gw-1 reports of the peering of
// its sidecar, each peer with the state of its session and the prefixes learned from it and the sessions refused, is what
// the API answers for gw-1, which ranz explain gw-1 prints, with the Node of each peer named by its tunnel endpoint and
// the VRF of each prefix by its name. A peer that no Node has keeps its address alone, and a Node outside the peering
// has none.
func TestPeeringReportReachesTheAPI(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	h.apply("peering.json")
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsPeering
	gw.start(h)
	gw.update(t)
	h.waitNode("gw-1", 1, true)

	// Before a report: the peers that the intent names, and none of the sidecar
	st, err := h.api.Peering(ctx, "gw-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Node != "gw-1" || st.ASN != intent.PeeringASN || !slices.Equal(st.Expected, []string{"db"}) || !st.Reported.IsZero() || len(st.Peers) != 0 || st.Refused != 0 {
		t.Errorf("the peering of gw-1 before its report is %+v", st)
	}

	report := &controlpb.Telemetry{Peering: &controlpb.PeeringReport{Refused: 2, Peers: []*controlpb.PeeringPeer{
		{Address: netip.MustParseAddr("10.1.0.2").AsSlice(), State: "established", Learned: []*controlpb.Route{hostRoute(30, "10.30.0.2/32"), hostRoute(30, "192.168.20.0/24")}},
		{Address: netip.MustParseAddr("10.1.0.9").AsSlice(), State: "active"},
	}}}
	if err := gw.Telemetry(report); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for st.Reported.IsZero() {
		if time.Now().After(deadline) {
			t.Fatalf("the API has no report of the peering of gw-1 within %v", waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
		if st, err = h.api.Peering(ctx, "gw-1"); err != nil {
			t.Fatal(err)
		}
	}
	want := []controller.PeeringPeer{
		{Node: "db", Address: "10.1.0.2", State: "established", Learned: []controller.PeeringRoute{{VRF: "dc", Prefix: "10.30.0.2/32"}, {VRF: "dc", Prefix: "192.168.20.0/24"}}},
		{Address: "10.1.0.9", State: "active", Learned: []controller.PeeringRoute{}},
	}
	if !reflect.DeepEqual(st.Peers, want) || st.Refused != 2 {
		t.Errorf("the peering of gw-1 after its report is %+v, want the peers %+v and 2 sessions refused", st, want)
	}

	// A Node outside the peering, and one that the intent does not have
	if st, err := h.api.Peering(ctx, "lab-1"); err != nil || st.ASN != 0 || len(st.Expected) != 0 || len(st.Peers) != 0 {
		t.Errorf("the peering of lab-1 is %+v, %v, want none", st, err)
	}
	var refused *api.Error
	if _, err := h.api.Peering(ctx, "nowhere"); !errors.As(err, &refused) || refused.Status != http.StatusNotFound {
		t.Errorf("the peering of a Node that the intent does not have gave %v, want 404", err)
	}
}
