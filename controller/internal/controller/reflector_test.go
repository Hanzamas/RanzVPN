// The route reflectors of the BGP peering of the standard mode in the controller conformance seam (SDN-79 #359): the
// Intent names the route reflectors of a VRF, and the controller gives each Node the role of each of its peers there,
// for the sidecar of the Node, and nothing else. Each Node of such a VRF must run the reflectors, and the peers that the
// API names for a client are the reflectors alone, the only Nodes that it has a session with.
package controller_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// capsReflection is capsPeering with the Capability bgpReflection (SDN-79): a node that runs the route reflectors of the
// peering, as a reflector and as a client.
var capsReflection = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
	HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, PlainLinks: true, BgpPeering: true,
	BgpReflection: true}

// TestReflectorsAreTheRolesOfThePeers is SDN-79 at the controller. gw-1, db and files peer by BGP in dc in a full mesh,
// and then the Intent names gw-1 the route reflector of dc. files, of the release of SDN-77, reports bgpPeering and not
// bgpReflection: it would peer in a full mesh that db refuses, so the reflector is refused before it applies, naming
// files, the VRF and the Capability, and nothing of it reaches any node. Once files reports it in its next Hello the
// reflector is one Generation of the three: gw-1 gets db and files as its clients in dc, and db gets gw-1 as the
// reflector of dc and files as reflected there, with what files may announce, to check the routes of the reflector. The
// API names gw-1 alone as the peer of each client, and both clients as the peers of gw-1.
func TestReflectorsAreTheRolesOfThePeers(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	h.apply("reflector.json")
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsReflection
	gw.start(h)
	db := h.newSim("db", keyBranch2)
	db.Capabilities = capsReflection
	db.start(h)
	files := h.newSim("files", keyLab1)
	files.Capabilities = capsPeering
	files.start(h)
	h.connect(t, gw, db, files)
	before := h.resources()

	// files runs the peering and not its route reflectors
	_, err := h.tryApply("reflector-on.json")
	if err == nil {
		t.Fatal("the route reflector of dc was applied with files, which does not report bgpReflection")
	}
	for _, want := range []string{`Node "files" (Server, x64): route reflection of VRF "dc" needs bgpReflection, which the node does not report`, capability.ErrMissing.Error()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal is %q, want it to say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `Node "db"`) || strings.Contains(err.Error(), `Node "gw-1"`) {
		t.Errorf("the refusal names a node that reports bgpReflection: %v", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	for _, s := range []*sim{gw, db, files} {
		noUpdate(t, s)
	}

	// files reports the Capability in its next Hello: the reflector is one Generation of the three
	files.halt()
	files.Capabilities = capsReflection
	files.start(h)
	// The controller checks an apply against the Capabilities of the last Hello, so the apply waits for the new one
	deadline := time.Now().Add(waitTimeout)
	for n := h.node("files"); !n.Connected || n.Capabilities == nil || !n.Capabilities.BGPReflection; n = h.node("files") {
		if time.Now().After(deadline) {
			t.Fatalf("the API reports files as %+v after %v, want it connected with bgpReflection", n, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.waitNode("files", 1, true)
	res := h.apply("reflector-on.json")
	if want := []controller.NodeGeneration{{Name: "db", Generation: 2}, {Name: "files", Generation: 2}, {Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("reflector-on.json changed %+v, want %+v", res.Nodes, want)
	}
	m := gw.update(t)
	if v := vrfObject(m, "dc"); !slices.Equal(v.GetReflectors(), []string{"gw-1"}) {
		t.Errorf("the update of gw-1 has the Vrf dc %v, want the reflector gw-1", v)
	}
	for _, client := range []string{"db", "files"} {
		if p := peerObject(m, client).GetPeering(); !slices.Equal(p.GetClientVrfIds(), []uint32{30}) || len(p.GetReflectorVrfIds()) != 0 || len(p.GetReflectedVrfIds()) != 0 {
			t.Errorf("the update of gw-1 has the Peer %s with the peering %v, want a client in dc", client, p)
		}
	}
	m = db.update(t)
	if p := peerObject(m, "gw-1").GetPeering(); !slices.Equal(p.GetReflectorVrfIds(), []uint32{30}) || len(p.GetClientVrfIds()) != 0 || len(p.GetReflectedVrfIds()) != 0 {
		t.Errorf("the update of db has the Peer gw-1 with the peering %v, want the reflector of dc", p)
	}
	if p := peerObject(m, "files").GetPeering(); !slices.Equal(p.GetReflectedVrfIds(), []uint32{30}) || len(p.GetAccept()) != 2 {
		t.Errorf("the update of db has the Peer files with the peering %v, want it reflected in dc, with its address and its LAN subnet", p)
	}
	files.update(t)
	for _, s := range []*sim{gw, db, files} {
		h.waitNode(s.name, 2, true)
		h.checkState(s)
	}

	// The peers that the API names: the reflector for each client, and the clients for the reflector
	for node, want := range map[string][]string{"db": {"gw-1"}, "files": {"gw-1"}, "gw-1": {"db", "files"}} {
		if st, err := h.api.Peering(ctx, node); err != nil || !slices.Equal(st.Expected, want) {
			t.Errorf("the peering of %s is %+v, %v, want the peers %v", node, st, err, want)
		}
	}
}
