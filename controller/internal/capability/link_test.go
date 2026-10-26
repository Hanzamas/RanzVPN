package capability

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A VRF with a link of kind vxlan or geneve needs plainLinks on each of its nodes (SDN-76): the problem
// names the node, the kind of the link, the VRF and the Capability, and a node that reports it runs the
// link. A VRF of kind noise needs nothing.
func TestPlainLinkNeedsTheCapability(t *testing.T) {
	for _, kind := range []string{"vxlan", "geneve"} {
		states := compile(t,
			res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "`+kind+`"}`),
			res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
			res("Node", "db", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
		)
		s := states["gw"]
		want := `Node "gw" (Server, x64): ` + kind + ` link of VRF "dc" needs plainLinks, which the node does not report`
		if problems := Check("gw", server, s); len(problems) != 1 || problems[0].Error() != want {
			t.Errorf("%s: the problems are %v, want [%s]", kind, problems, want)
		}
		runs := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_PRO, Architecture: controlpb.Architecture_ARCHITECTURE_ARM64, PlainLinks: true}
		if problems := Check("gw", runs, s); len(problems) > 0 {
			t.Errorf("%s: a node that runs the links was refused: %v", kind, problems)
		}
	}

	states := compile(t,
		res("VRF", "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "noise"}`),
		res("Node", "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
	)
	if problems := Check("gw", armHome, states["gw"]); len(problems) > 0 {
		t.Errorf("a VRF of kind noise was refused: %v", problems)
	}
}

// The Capability reads from the Hello into the API form and back.
func TestAPIFormPlainLinks(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{PlainLinks: true})
	if !c.PlainLinks {
		t.Errorf("the API form of a Hello with plain_links is %+v", c)
	}
	p, err := c.Proto()
	if err != nil || !p.GetPlainLinks() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
}
