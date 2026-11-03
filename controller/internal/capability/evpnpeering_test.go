package capability

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A VRF whose Nodes peer by EVPN needs evpnPeering on each of its nodes (SDN-78): a node of the release of SDN-77, which reports
// bgpPeering, would read the peering as none, start no EVPN and reach no other node of the VRF. The problem names the node, the
// VRF and the Capability, once for the VRF. A node that reports it is not refused, and a VRF that peers by BGP needs no more than
// bgpPeering.
func TestEVPNPeeringNeedsTheCapability(t *testing.T) {
	states := compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "evpn"}}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	)
	previous := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true, BgpPeering: true, BgpReflection: true}
	runs := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true, BgpPeering: true, BgpReflection: true, EvpnPeering: true}

	for _, node := range []string{"gw", "db"} {
		want := `Node "` + node + `" (Server, x64): EVPN peering of VRF "dc" needs evpnPeering, which the node does not report`
		if problems := Check(node, previous, states[node]); len(problems) != 1 || problems[0].Error() != want {
			t.Errorf("%s: a node that reports bgpPeering alone has the problems %v, want [%s]", node, problems, want)
		}
		if problems := Check(node, runs, states[node]); len(problems) > 0 {
			t.Errorf("%s: a node that reports evpnPeering was refused: %v", node, problems)
		}
	}

	// A VRF whose Nodes peer by BGP needs no more than bgpPeering
	states = compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	)
	for _, node := range []string{"gw", "db"} {
		if problems := Check(node, previous, states[node]); len(problems) > 0 {
			t.Errorf("%s: a node of a VRF that peers by BGP and reports bgpPeering was refused: %v", node, problems)
		}
	}

	// The API form of the Capabilities carries it both ways
	c := FromProto(runs)
	if !c.EVPNPeering {
		t.Errorf("the API form of the Capabilities %v has no evpnPeering", runs)
	}
	if p, err := c.Proto(); err != nil || !p.GetEvpnPeering() {
		t.Errorf("the Capabilities %+v in the form of a Hello are %v, %v, want evpnPeering", c, p, err)
	}
}
