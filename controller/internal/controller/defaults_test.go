// The first start and VRF default (ADR-0034, SDN-3 #179) in the controller conformance seam: a
// fresh controller reports VRF default and the starter rule through the API, as revision 1 that
// no later start makes again, and two nodes that name no VRF join VRF default, get their
// addresses from its automatic pool and acknowledge their generation, which the API shows. The
// real nodes of the vpntest harness then forward over it (vpntest sdntrace,
// .github/scripts/sdn-tracer.ps1).
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newFirstStartHarness returns a harness whose controller makes the intent of a first install
// at its first start, with the ULA fd12:3456:789a::/48 for VRF default.
func newFirstStartHarness(t *testing.T) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), defaults: true, random: bytes.NewReader([]byte{0x12, 0x34, 0x56, 0x78, 0x9a})}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

// TestFirstStartCreatesDefaultVRF is the first criterion of #179: a fresh controller reports VRF
// default with overlay DNS on, its Network with the automatic pool, and the starter rule, through
// the API (golden output), as the revision of its first start. A restart makes no second one.
func TestFirstStartCreatesDefaultVRF(t *testing.T) {
	h := newFirstStartHarness(t)
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	goldenJSON(t, "first-start-resources", api.ResourceList{Resources: rs})
	if got, want := h.revisionLog(), "1 first-start\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
	before := h.resources()

	h.stop()
	h.start()
	if after := h.resources(); after != before {
		t.Errorf("the intent after the restart is\n%s\nwant\n%s", after, before)
	}
	if got, want := h.revisionLog(), "1 first-start\n"; got != want {
		t.Errorf("after the restart the revisions are\n%s\nwant\n%s", got, want)
	}
}

// TestDefaultVRFNodes is the controller's side of the second, third and fourth criteria of #179:
// two nodes that name no VRF join VRF default and receive, as generation 1, the first addresses
// of its pool, each with the other as its peer at its address (golden control messages); the API
// shows the generation each acknowledged; and once the controller stops, each keeps the state it
// applied.
func TestDefaultVRFNodes(t *testing.T) {
	h := newFirstStartHarness(t)
	res := h.apply("apply-default.json")
	if want := []controller.NodeGeneration{{Name: "node-a", Generation: 1}, {Name: "node-b", Generation: 1}}; res.Revision != 2 || !equalGenerations(res.Nodes, want) {
		t.Errorf("apply-default.json made revision %d and changed %+v, want revision 2 and %+v", res.Revision, res.Nodes, want)
	}
	a := h.sim("node-a", keyBranch1)
	b := h.sim("node-b", keyBranch2)
	golden(t, "default-node-a", a.update(t))
	golden(t, "default-node-b", b.update(t))
	h.waitNode("node-a", 1, true)
	h.waitNode("node-b", 1, true)
	goldenJSON(t, "default-nodes", api.NodeList{Nodes: h.nodes()})
	h.checkState(a)
	h.checkState(b)

	before := map[string]desired.State{}
	for _, s := range []*sim{a, b} {
		_, before[s.name] = s.State()
	}
	h.stop()
	for _, s := range []*sim{a, b} {
		if err := s.end(t); err == nil {
			t.Errorf("the stream of %s ended without an error when the controller stopped", s.name)
		}
		if gen, st := s.State(); gen != 1 || !desired.Equal(st, before[s.name]) {
			t.Errorf("%s: without the controller the node is at generation %d with another state, want generation 1 as it applied it", s.name, gen)
		}
	}
}
