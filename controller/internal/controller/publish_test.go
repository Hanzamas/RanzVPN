package controller_test

import (
	"context"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// TestPublishedEndpointReachesTheNodes is the controller side of SDN-24 (#200). The Endpoint of tests/explain/endpoint.json (corp
// publishes the HTTPS port of corp-app into vendor, which uses the same range) reaches the four Nodes as the rule of each VRF, the
// name in the zone of vendor and the routes of the one consumer, and as nothing else: of the Nodes of the two VRFs only corp-app and
// vendor-1, the Node of vendor that has the tag, are Peers, though they share no VRF. Deleting the Endpoint takes all of it away from
// the four Nodes, and a rollback brings the state of the first revision back.
func TestPublishedEndpointReachesTheNodes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sc, err := explain.LoadScenario("../../../tests/explain/endpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sc.Document()
	if err != nil {
		t.Fatal(err)
	}
	gens := func(n uint64) []controller.NodeGeneration {
		var out []controller.NodeGeneration
		for _, name := range []string{"corp-app", "corp-db", "vendor-1", "vendor-2"} {
			out = append(out, controller.NodeGeneration{Name: name, Generation: n})
		}
		return out
	}
	res, err := h.api.Apply(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 1 || !equalGenerations(res.Nodes, gens(1)) {
		t.Errorf("the apply made revision %d and changed %+v, want revision 1 and %+v", res.Revision, res.Nodes, gens(1))
	}
	sims := []*sim{h.sim("corp-app", keyBranch1), h.sim("corp-db", keyBranch2), h.sim("vendor-1", keyLab1), h.sim("vendor-2", keyRelay1)}
	by := map[string]*sim{}
	for _, s := range sims {
		by[s.name] = s
	}

	// holds says whether the state of a Node holds the rule or the Peer; with and without say whether it does with the Endpoint
	// and without it
	holds := func(node string, kind controlpb.Kind, name string) bool {
		_, st := by[node].State()
		_, ok := st[desired.Key{Kind: kind, Name: name}]
		return ok
	}
	rule, peer := controlpb.Kind_KIND_RULE, controlpb.Kind_KIND_PEER
	objects := []struct {
		node          string
		kind          controlpb.Kind
		name          string
		with, without bool
	}{
		// The rule of the source VRF is held by its Nodes, and the rule of the consumer VRF by its Nodes
		{"corp-app", rule, "billing.source", true, false},
		{"corp-db", rule, "billing.source", true, false},
		{"vendor-1", rule, "billing.source", false, false},
		{"vendor-2", rule, "billing.source", false, false},
		{"vendor-1", rule, "billing.consumer", true, false},
		{"vendor-2", rule, "billing.consumer", true, false},
		{"corp-app", rule, "billing.consumer", false, false},
		{"corp-db", rule, "billing.consumer", false, false},
		// The Nodes of one VRF are Peers; of the two VRFs, only the Node that serves the Endpoint and its one consumer are
		{"corp-app", peer, "corp-db", true, true},
		{"corp-db", peer, "corp-app", true, true},
		{"vendor-1", peer, "vendor-2", true, true},
		{"vendor-2", peer, "vendor-1", true, true},
		{"corp-app", peer, "vendor-1", true, false},
		{"vendor-1", peer, "corp-app", true, false},
		{"corp-app", peer, "vendor-2", false, false},
		{"vendor-2", peer, "corp-app", false, false},
		{"corp-db", peer, "vendor-1", false, false},
		{"corp-db", peer, "vendor-2", false, false},
		{"vendor-1", peer, "corp-db", false, false},
		{"vendor-2", peer, "corp-db", false, false},
	}
	check := func(endpoint bool) {
		t.Helper()
		for _, c := range objects {
			want := c.without
			if endpoint {
				want = c.with
			}
			if got := holds(c.node, c.kind, c.name); got != want {
				t.Errorf("%s holds %s %s: %v, want %v (the Endpoint is there: %v)", c.node, c.kind, c.name, got, want, endpoint)
			}
		}
	}

	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	check(true)

	res, err = h.api.Delete(ctx, intent.KindEndpoint, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 2 || !equalGenerations(res.Nodes, gens(2)) {
		t.Errorf("deleting the Endpoint made revision %d and changed %+v, want revision 2 and %+v", res.Revision, res.Nodes, gens(2))
	}
	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 2, true)
		h.checkState(s)
	}
	check(false)

	res, err = h.api.Rollback(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 3 || !equalGenerations(res.Nodes, gens(3)) {
		t.Errorf("the rollback made revision %d and changed %+v, want revision 3 and %+v", res.Revision, res.Nodes, gens(3))
	}
	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 3, true)
		h.checkRevisionState(s, 1)
	}
	check(true)
}
