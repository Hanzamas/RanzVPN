// The links of kind vxlan and geneve in the controller conformance seam (SDN-76 #356): a switch of the kind of the
// link of a VRF between noise and vxlan is one Generation of each Node of the VRF and of no other, whose update
// carries the kind and the VNI of the VRF and the tunnel endpoint of the peer; and a Node that does not report the
// Capability plainLinks refuses the switch before apply, naming the Node, the link and the Capability.
package controller_test

import (
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// vrfObject returns the Vrf object named name among the objects that the update in m sets, nil for none.
func vrfObject(m *controlpb.ControlMessage, name string) *controlpb.Vrf {
	for _, o := range m.GetUpdate().GetSet() {
		if v := o.GetVrf(); v != nil && v.GetName() == name {
			return v
		}
	}
	return nil
}

// TestLinkSwitchIsOneGeneration is the fourth criterion of SDN-76 at the controller, and the Capability of the
// ticket: noise to vxlan and back are one Generation each of gw-1 and db, and lab-1, outside dc, keeps its own.
func TestLinkSwitchIsOneGeneration(t *testing.T) {
	h := newHarness(t)
	res := h.apply("links.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 1}, {Name: "gw-1", Generation: 1}, {Name: "lab-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("links.json changed %+v, want %+v", res.Nodes, want)
	}

	plain := proto.Clone(capsServer).(*controlpb.Capabilities)
	plain.PlainLinks = true
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = plain
	gw.start(h)
	db := h.sim("db", keyBranch2)
	gw.update(t)
	db.update(t)
	h.waitNode("gw-1", 1, true)
	h.waitNode("db", 1, true)

	// db runs no plain link: the switch is refused before apply, and no Generation moves
	_, err := h.tryApply("links-vxlan.json")
	if err == nil || !strings.Contains(err.Error(), `Node "db"`) || !strings.Contains(err.Error(), `vxlan link of VRF "dc" needs plainLinks`) {
		t.Fatalf("the switch to vxlan with db, which does not report plainLinks, gave %v", err)
	}
	if strings.Contains(err.Error(), `Node "gw-1"`) {
		t.Errorf("the refusal names gw-1, which reports plainLinks: %v", err)
	}
	if !strings.Contains(err.Error(), capability.ErrMissing.Error()) {
		t.Errorf("the refusal is not one of a missing Capability: %v", err)
	}

	// db reports it in its next Hello: the switch is one Generation of gw-1 and db, and not of lab-1. The Controller shows
	// the stream that just ended as connected until it reads its end, so the node is waited for to be gone first, and the
	// wait for it to be back is the one for the stream with the new Hello
	db.halt()
	h.waitNode("db", 1, false)
	db.Capabilities = plain
	db.start(h)
	h.waitNode("db", 1, true)
	res = h.apply("links-vxlan.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 2}, {Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("links-vxlan.json changed %+v, want %+v", res.Nodes, want)
	}
	m := gw.update(t)
	if v := vrfObject(m, "dc"); v.GetLink() != controlpb.LinkKind_LINK_KIND_VXLAN || v.GetVni() != 30 {
		t.Errorf("the update of gw-1 has the Vrf dc %v, want vxlan on VNI 30", v)
	}
	want := &controlpb.Vtep{Address: netip.MustParseAddr("10.1.0.2").AsSlice(), VxlanPort: 4789, GenevePort: 6081}
	if p := peerObject(m, "db"); p == nil || !proto.Equal(p.GetVtep(), want) {
		t.Errorf("the update of gw-1 has the Peer db %v, want the vtep %v", p, want)
	}
	if n := nodeObject(m); n == nil || !proto.Equal(n.GetVtep(), &controlpb.Vtep{VxlanPort: 4789, GenevePort: 6081}) {
		t.Errorf("the update of gw-1 has the NodeConfig %v, want the ports of its vtep", n)
	}
	if m := db.update(t); vrfObject(m, "dc").GetLink() != controlpb.LinkKind_LINK_KIND_VXLAN {
		t.Errorf("the update of db is %v", m)
	}
	h.waitNode("gw-1", 2, true)
	h.waitNode("db", 2, true)
	h.checkState(gw)
	h.checkState(db)

	// Back to noise is one Generation again, whose Vrf object carries no kind and whose peer no tunnel endpoint
	res = h.apply("links.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 3}, {Name: "gw-1", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("links.json again changed %+v, want %+v", res.Nodes, want)
	}
	m = gw.update(t)
	if v := vrfObject(m, "dc"); v == nil || v.GetLink() != controlpb.LinkKind_LINK_KIND_UNSPECIFIED || v.GetVni() != 0 {
		t.Errorf("the update of gw-1 back to noise has the Vrf dc %v", v)
	}
	if p := peerObject(m, "db"); p == nil || p.GetVtep() != nil {
		t.Errorf("the update of gw-1 back to noise has the Peer db %v, want no vtep", p)
	}
	h.waitNode("gw-1", 3, true)
}
