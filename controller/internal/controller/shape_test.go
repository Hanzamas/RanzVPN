package controller_test

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// TestLimitsReachTheNode checks the MTU and the rate limits of SDN-20 (#196): the MTU that the
// VRF of limits.json raises above the default, its rate limit and the rate limit of the Node
// resource reach the node in its state, which the C node gets in the same fields (the nanopb
// round trip of CI reads the frames of this test too).
func TestLimitsReachTheNode(t *testing.T) {
	h := newHarness(t)
	res := h.apply("limits.json")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("limits.json changed %+v, want %+v", res.Nodes, want)
	}
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "limits-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	h.checkState(b1)
}
