package controller_test

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// TestPolicyReachesTheNodes is the controller side of SDN-8 (#184): the tag rules of policy.json
// arrive at the nodes as compiled rules. branch-1 (tag web) gets the rules of corp whose from or to
// end can be it, with the conntrack quota and the timeouts of corp and the tags of its peers (the
// golden file policy-branch-1); lab-1, which has no tag, gets no-guests, whose to end is any, and
// the rule of lab, not web-to-db (policy-lab-1). A change of web-to-db reaches branch-1 and branch-2
// as a delta of that rule alone, and lab-1 not at all (policy2-branch-1).
func TestPolicyReachesTheNodes(t *testing.T) {
	h := newHarness(t)
	h.apply("policy.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	lab := h.sim("lab-1", keyLab1)
	golden(t, "policy-branch-1", b1.update(t))
	b2.update(t)
	golden(t, "policy-lab-1", lab.update(t))
	for _, s := range []*sim{b1, b2, lab} {
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}

	res := h.apply("policy2.json")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "branch-2", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("policy2.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "policy2-branch-1", b1.update(t))
	b2.update(t)
	for _, s := range []*sim{b1, b2} {
		h.waitNode(s.name, 2, true)
		h.checkState(s)
	}
	h.waitNode("lab-1", 1, true)
	h.checkState(lab)
}
