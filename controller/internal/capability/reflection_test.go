package capability

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A VRF whose Intent names route reflectors needs bgpReflection on each of its nodes, the reflector and the
// clients (SDN-79): a node of the release of SDN-77, which reports bgpPeering and no more, would skip the roles
// of its peers and peer in a full mesh that they refuse. The problem names the node, the VRF and the
// Capability, once for the VRF. A node that reports it is not refused, and neither is a VRF of a full mesh.
func TestReflectionNeedsTheCapability(t *testing.T) {
	states := compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp", "reflectors": ["gw"]}}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	)
	previous := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true, BgpPeering: true}
	runs := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true, BgpPeering: true, BgpReflection: true}

	for _, node := range []string{"gw", "db"} {
		want := `Node "` + node + `" (Server, x64): route reflection of VRF "dc" needs bgpReflection, which the node does not report`
		if problems := Check(node, previous, states[node]); len(problems) != 1 || problems[0].Error() != want {
			t.Errorf("%s: a node that reports bgpPeering alone has the problems %v, want [%s]", node, problems, want)
		}
		if problems := Check(node, runs, states[node]); len(problems) > 0 {
			t.Errorf("%s: a node that reports bgpReflection was refused: %v", node, problems)
		}
	}

	// A VRF whose Nodes peer in a full mesh needs no more than bgpPeering
	states = compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	)
	for _, node := range []string{"gw", "db"} {
		if problems := Check(node, previous, states[node]); len(problems) > 0 {
			t.Errorf("%s: a node of a full mesh that reports bgpPeering was refused: %v", node, problems)
		}
	}

	// The API form of the Capabilities carries it both ways
	c := FromProto(runs)
	if !c.BGPReflection {
		t.Errorf("the API form of the Capabilities %v has no bgpReflection", runs)
	}
	if p, err := c.Proto(); err != nil || !p.GetBgpReflection() {
		t.Errorf("the Capabilities %+v in the form of a Hello are %v, %v, want bgpReflection", c, p, err)
	}
}
