package capability

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The internet exit of a VRF needs a node that reports an Egress tier (SDN-12): the problem names the
// node, the VRF by its id and the Capability, and a node that reports any of the three tiers is the
// exit. The other Nodes of the VRF, which only route to the exit, need nothing.
func TestEgressNeedsAnEgressTier(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "gw"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48", "egress": "gw"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	)
	old := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_PRO, Architecture: controlpb.Architecture_ARCHITECTURE_X64}
	want := `Node "gw" (Pro, x64): the internet exit of the VRFs of ids 10, 20 needs egressTier, which the node does not report`
	if problems := Check("gw", old, states["gw"]); len(problems) != 1 || problems[0].Error() != want {
		t.Errorf("the problems are %v, want [%s]", problems, want)
	}
	for _, tier := range []controlpb.EgressTier{controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, controlpb.EgressTier_EGRESS_TIER_WINNAT, controlpb.EgressTier_EGRESS_TIER_PROXY} {
		caps := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_HOME, Architecture: controlpb.Architecture_ARCHITECTURE_ARM64, EgressTier: tier}
		if problems := Check("gw", caps, states["gw"]); len(problems) > 0 {
			t.Errorf("tier %v: the exit was refused: %v", tier, problems)
		}
	}
	if problems := Check("laptop", nil, states["laptop"]); len(problems) > 0 {
		t.Errorf("a Node that routes to the exit was refused: %v", problems)
	}

	one := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "egress": "gw"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	)
	want = `Node "gw": the internet exit of the VRF of id 10 needs egressTier, which the node does not report`
	if problems := Check("gw", nil, one["gw"]); len(problems) != 1 || problems[0].Error() != want {
		t.Errorf("a node that reports nothing: the problems are %v, want [%s]", problems, want)
	}
}
