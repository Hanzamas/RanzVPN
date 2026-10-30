// Capability reporting and intent validation in the controller conformance seam (ADR-0033,
// SDN-9 #185): simulated nodes report different Capabilities in their Hello, the API lists them,
// and the controller refuses an intent that a node cannot honour, naming the node and the
// Capability, before any of it reaches a node. Every core feature applies on a node that reports
// no Capability at all.
package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

var (
	// capsServer is a Windows Server gateway with every Capability. Every simulated node reports
	// it unless its test sets others.
	capsServer = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
		HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT}
	// capsArmHome is an arm64 laptop with Windows 11 Home: L3 only (ADR-0022), egress through the
	// proxy, and on 5555 because something else holds 443.
	capsArmHome = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_HOME, Architecture: controlpb.Architecture_ARCHITECTURE_ARM64,
		EgressTier: controlpb.EgressTier_EGRESS_TIER_PROXY, TlsPortFallback: true}
)

// laptopMissesL2 is the problem of the node laptop (capsArmHome) with the L2 Network corp-dmz.
const laptopMissesL2 = `Node "laptop" (Home, arm64): L2 Network "corp-dmz" needs XDP or SeLow, which the node does not report`

// TestAPIListsCapabilities is the first criterion of #185: the API lists the Capabilities that
// each node reported, none before a node's first Hello, and keeps them across a restart of the
// controller and of rqlite.
func TestAPIListsCapabilities(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	h := newHarness(t)
	h.apply("caps-apply1.json")
	for _, n := range h.nodes() {
		if n.Capabilities != nil {
			t.Errorf("%s: the API lists the Capabilities %+v before the node reported any", n.Name, n.Capabilities)
		}
	}
	gw := h.sim("gw", keyBranch1)
	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = capsArmHome
	laptop.start(h)
	h.waitNode("gw", 1, true)
	h.waitNode("laptop", 1, true)
	before := h.nodes()
	goldenJSON(t, "caps-nodes", api.NodeList{Nodes: before})

	h.stop()
	for _, s := range []*sim{gw, laptop} {
		if err := s.end(t); err == nil {
			t.Errorf("the stream of %s ended without an error when the controller stopped", s.name)
		}
	}
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	after := h.nodes()
	if len(after) != len(before) {
		t.Fatalf("the nodes after the restart are %+v, before %+v", after, before)
	}
	for i := range after {
		if a, b := after[i].Capabilities, before[i].Capabilities; a == nil || b == nil || *a != *b {
			t.Errorf("%s: the Capabilities after the restart are %+v, before %+v", after[i].Name, a, b)
		}
	}
}

// TestApplyRefusesMissingCapability is the second criterion of #185: an intent that needs a
// Capability a node does not report is refused before it applies, and the answer names the node
// and the Capability. Nothing of it reaches any node, and the same feature applies on a node that
// has the Capability.
func TestApplyRefusesMissingCapability(t *testing.T) {
	h := newHarness(t)
	h.apply("caps-apply1.json")
	gw := h.sim("gw", keyBranch1)
	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = capsArmHome
	laptop.start(h)
	if u := gw.update(t).GetUpdate(); u.GetGeneration() != 1 {
		t.Fatalf("gw received generation %d first, not 1", u.GetGeneration())
	}
	h.waitNode("gw", 1, true)
	h.waitNode("laptop", 1, true)
	before := h.resources()

	// An L2 Network in corp: laptop, an arm64 Home node, has no L2 backend.
	_, err := h.tryApply("caps-l2-corp.json")
	if err == nil {
		t.Fatal("an L2 Network in a VRF of an arm64 node with neither XDP nor SeLow was applied")
	}
	if !strings.Contains(err.Error(), laptopMissesL2) {
		t.Errorf("the error %q does not name %q", err, laptopMissesL2)
	}
	if strings.Contains(err.Error(), `Node "gw"`) {
		t.Errorf("the error %q names gw, which reports XDP and SeLow", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	h.waitNode("gw", 1, true)
	h.waitNode("laptop", 1, true)

	// An L2 Network in lab, a VRF of gw alone: gw has XDP, so it applies, and it is the next
	// update gw receives.
	res := h.apply("caps-l2-lab.json")
	if want := []controller.NodeGeneration{{Name: "gw", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("caps-l2-lab.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "caps-l2-lab-gw", gw.update(t))
	h.waitNode("gw", 2, true)
	h.waitNode("laptop", 1, true)
	h.checkState(gw)
	h.checkState(laptop)
}

// TestCoreFeaturesNeedNoCapability is the third criterion of #185: a node that reports no
// Capability at all receives every core feature of the intent.
func TestCoreFeaturesNeedNoCapability(t *testing.T) {
	h := newHarness(t)
	h.apply("caps-core1.json")
	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = &controlpb.Capabilities{}
	laptop.start(h)
	if u := laptop.update(t).GetUpdate(); u.GetGeneration() != 1 {
		t.Fatalf("laptop received generation %d first, not 1", u.GetGeneration())
	}
	h.waitNode("laptop", 1, true)

	res := h.apply("caps-core2.json")
	if want := []controller.NodeGeneration{{Name: "gw", Generation: 1}, {Name: "laptop", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("caps-core2.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "caps-core2-laptop", laptop.update(t))
	h.waitNode("laptop", 2, true)
	h.checkState(laptop)
}

// TestHelloRefusesMissingCapability covers a node that had not reported its Capabilities when
// an intent it cannot honour was applied: its Hello reports them, and the controller refuses the
// stream, naming the node and the Capability, so none of that intent reaches the node. Its
// Capabilities are known from then on: an apply that changes the node is refused, a delete that
// makes its state one it can honour is not, and the node then receives that state.
func TestHelloRefusesMissingCapability(t *testing.T) {
	h := newHarness(t)
	h.apply("caps-apply1.json")
	h.apply("caps-l2-corp.json")

	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = capsArmHome
	laptop.start(h)
	golden(t, "refuse-capability", laptop.refusal(t))
	n := h.node("laptop")
	if n.Connected || n.AckedGeneration != 0 || n.Capabilities == nil || n.Capabilities.Architecture != "arm64" {
		t.Errorf("after the refusal the API reports laptop as %+v (Capabilities %+v), want it unconnected at no acknowledged generation, with the arm64 it reported",
			n, n.Capabilities)
	}

	tag := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindNode, Name: "laptop", Spec: json.RawMessage(`{"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"], "tags": ["laptop"]}`)},
	}}
	if _, err := h.api.Apply(context.Background(), tag); err == nil || !strings.Contains(err.Error(), laptopMissesL2) {
		t.Errorf("a change of laptop, which cannot honour its state, gave %v, want a refusal that names %q", err, laptopMissesL2)
	}

	res, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-dmz")
	if err != nil {
		t.Fatal(err)
	}
	gen := uint64(0)
	for _, ng := range res.Nodes {
		if ng.Name == "laptop" {
			gen = ng.Generation
		}
	}
	laptop.start(h)
	if u := laptop.update(t).GetUpdate(); u.GetGeneration() != gen || u.GetBaseGeneration() != 0 {
		t.Errorf("laptop received generation %d from %d, want its full state at generation %d", u.GetGeneration(), u.GetBaseGeneration(), gen)
	}
	h.waitNode("laptop", gen, true)
	h.checkState(laptop)
}

// TestRollbackRefusesMissingCapability checks a rollback against the Capabilities like an apply
// (SDN-13 #189 with ADR-0033): a rollback to a revision that a node cannot honour, applied before
// the node reported its Capabilities, is refused with 409 Conflict, naming the node and the
// Capability, and makes no revision.
func TestRollbackRefusesMissingCapability(t *testing.T) {
	h := newHarness(t)
	h.apply("caps-apply1.json")
	h.apply("caps-l2-corp.json")
	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = capsArmHome
	laptop.start(h)
	golden(t, "refuse-capability", laptop.refusal(t))
	if _, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-dmz"); err != nil {
		t.Fatal(err)
	}
	before := h.resources()

	_, err := h.api.Rollback(context.Background(), 2)
	if httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), laptopMissesL2) {
		t.Errorf("the rollback to revision 2, which laptop cannot honour, gave %v, want a 409 that names %q", err, laptopMissesL2)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused rollback changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if got, want := h.revisionLog(), "1 apply\n2 apply\n3 delete\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
}

// nodes returns the status of every node as the API reports it.
func (h *harness) nodes() []controller.NodeStatus {
	h.t.Helper()
	nodes, err := h.api.Nodes(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return nodes
}

// node returns the status of node name as the API reports it.
func (h *harness) node(name string) controller.NodeStatus {
	h.t.Helper()
	for _, n := range h.nodes() {
		if n.Name == name {
			return n
		}
	}
	h.t.Fatalf("the API reports no node %s", name)
	return controller.NodeStatus{}
}

// goldenJSON compares v as JSON with testdata/<name>.json, or writes it there under -update.
func goldenJSON(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join("testdata", name+".json")
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if *rewrite {
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want, have any
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if err := json.Unmarshal(got, &have); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("%s: the answer differs from the golden file\n--- got\n%s\n--- want\n%s", path, got, b)
	}
}
