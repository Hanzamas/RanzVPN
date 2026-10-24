package controller_test

import "testing"

// TestNATAndFourViaSix is the controller side of SDN-6 (#182): a NAT resource and the 4via6 that
// the controller makes reach the nodes. branch-1, in red and blue, which both use 10.0.0.0/24,
// applies the 4via6 of both VRFs and routes the outside prefix of the rule of branch-2 to that
// peer; branch-2 applies its own rule (the golden files nat-branch-1 and nat-branch-2).
func TestNATAndFourViaSix(t *testing.T) {
	h := newHarness(t)
	h.apply("nat.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	lab := h.sim("lab-1", keyLab1)
	golden(t, "nat-branch-1", b1.update(t))
	golden(t, "nat-branch-2", b2.update(t))
	lab.update(t)
	for _, s := range []*sim{b1, b2, lab} {
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
}
