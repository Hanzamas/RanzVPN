package capability

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A Stretch needs evpn at its gateway (SDN-63): the problem names the node, the Network and the Capability, a node that reports it
// takes the Stretch, and a node that is no gateway of one needs nothing, whatever it reports.
func TestStretchNeedsEVPN(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd30:1:2::/48"}`),
		res(intent.KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["dc"]}`),
		res(intent.KindStretch, "s", `{"gateway": "gw", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`),
	)

	// A Windows Server with every other Capability, and a node that reports none at all, lack evpn
	for _, c := range []struct {
		caps *controlpb.Capabilities
		want string
	}{
		{server, `Node "gw" (Server, x64): Stretch of Network "dc-l2" needs evpn, which the node does not report`},
		{nil, `Node "gw": Stretch of Network "dc-l2" needs evpn, which the node does not report`},
		{&controlpb.Capabilities{}, `Node "gw": Stretch of Network "dc-l2" needs evpn, which the node does not report`},
	} {
		if problems := Check("gw", c.caps, states["gw"]); len(problems) != 1 || problems[0].Error() != c.want {
			t.Errorf("the problems of gw with the Capabilities %v are %v, want [%s]", c.caps, problems, c.want)
		}
	}

	// A node that reports evpn takes the Stretch
	evpn := proto.Clone(server).(*controlpb.Capabilities)
	evpn.Evpn = true
	if problems := Check("gw", evpn, states["gw"]); len(problems) > 0 {
		t.Errorf("a node that reports evpn was refused: %v", problems)
	}

	// The other node of the VRF gets no Stretch, so it needs nothing
	for _, caps := range []*controlpb.Capabilities{nil, {}, armHome, server} {
		if problems := Check("host", caps, states["host"]); len(problems) > 0 {
			t.Errorf("host, which is no gateway, with the Capabilities %v was refused: %v", caps, problems)
		}
	}

	// An L2 Network that no Stretch binds needs no evpn
	plain := compile(t,
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd30:1:2::/48"}`),
		res(intent.KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
	)
	if problems := Check("gw", server, plain["gw"]); len(problems) > 0 {
		t.Errorf("an L2 Network without a Stretch was refused: %v", problems)
	}
}

// The Capability evpn reads from the Hello into the API form and back, and a node that reports nothing reports no evpn.
func TestAPIFormEVPN(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{Evpn: true})
	if !c.EVPN {
		t.Errorf("the API form of a Hello with evpn is %+v", c)
	}
	p, err := c.Proto()
	if err != nil || !p.GetEvpn() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
	if FromProto(&controlpb.Capabilities{}).EVPN {
		t.Error("a node that reports no Capability reports evpn")
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil || fields["evpn"] != true {
		t.Errorf("the API form is %s, want the field evpn", b)
	}
	b, err = json.Marshal(FromProto(&controlpb.Capabilities{}))
	if err != nil {
		t.Fatal(err)
	}
	var none map[string]any
	if err := json.Unmarshal(b, &none); err != nil {
		t.Fatal(err)
	}
	if _, ok := none["evpn"]; ok {
		t.Errorf("the API form of a node that does not report evpn is %s, want no field evpn", b)
	}
}
