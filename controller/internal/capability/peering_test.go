package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A VRF whose Nodes peer by BGP needs bgpPeering on each of its nodes (SDN-77-R2): a node of the release of
// SDN-76, which reports plainLinks and no more, is refused, and the problem names the node, the VRF and the
// Capability, as it does for a node that reports neither. A node that reports both is not, and neither is
// a VRF of a plain link that does not peer, which needs plainLinks alone.
func TestBGPPeeringNeedsTheCapability(t *testing.T) {
	states := compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	)
	previous := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true}
	runs := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PlainLinks: true, BgpPeering: true}

	for _, node := range []string{"gw", "db"} {
		want := `Node "` + node + `" (Server, x64): BGP peering of VRF "dc" needs bgpPeering, which the node does not report`
		if problems := Check(node, previous, states[node]); len(problems) != 1 || problems[0].Error() != want {
			t.Errorf("%s: a node that reports plainLinks alone has the problems %v, want [%s]", node, problems, want)
		}
		if problems := Check(node, runs, states[node]); len(problems) > 0 {
			t.Errorf("%s: a node that reports bgpPeering was refused: %v", node, problems)
		}
		// A node that reports no Capability at all lacks the link as well
		problems := Check(node, nil, states[node])
		if len(problems) != 2 || !strings.Contains(problems[0].Error(), "needs plainLinks") || !strings.Contains(problems[1].Error(), `BGP peering of VRF "dc" needs bgpPeering`) {
			t.Errorf("%s: a node that reports nothing has the problems %v, want plainLinks and bgpPeering", node, problems)
		}
	}

	// A VRF whose link is plain and whose Nodes do not peer by BGP needs no more than plainLinks
	states = compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
	)
	if problems := Check("gw", previous, states["gw"]); len(problems) > 0 {
		t.Errorf("a VRF that does not peer by BGP was refused for a node of plainLinks: %v", problems)
	}
}

// A node that is no member of the VRF that peers by BGP is not asked for the Capability: its state holds the Vrf
// objects of its own VRFs alone.
func TestBGPPeeringIsAskedOfItsMembersOnly(t *testing.T) {
	states := compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res("VRF", "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
		res("Node", "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	)
	if problems := Check("laptop", armHome, states["laptop"]); len(problems) > 0 {
		t.Errorf("a node outside the VRF that peers was refused: %v", problems)
	}
}

// The Capability reads from the Hello into the API form and back, under the name bgpPeering; a node that reports
// nothing reports no bgpPeering.
func TestAPIFormBGPPeering(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{BgpPeering: true})
	if !c.BGPPeering {
		t.Errorf("the API form of a Hello with bgp_peering is %+v", c)
	}
	p, err := c.Proto()
	if err != nil || !p.GetBgpPeering() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
	if b, err := json.Marshal(c); err != nil || !strings.Contains(string(b), `"bgpPeering":true`) {
		t.Errorf("the JSON of the API form is %s, %v, want bgpPeering", b, err)
	}
	if b, err := json.Marshal(FromProto(&controlpb.Capabilities{})); err != nil || strings.Contains(string(b), "bgpPeering") {
		t.Errorf("the JSON of a node that reports nothing is %s, %v, want no bgpPeering", b, err)
	}
}
