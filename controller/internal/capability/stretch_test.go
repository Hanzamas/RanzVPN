package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// problemsAbout returns the problems that name the Capability evpn, the ones of the Stretch.
func problemsAbout(problems []error) []string {
	var out []string
	for _, p := range problems {
		if strings.Contains(p.Error(), "needs evpn") {
			out = append(out, p.Error())
		}
	}
	return out
}

// A Stretch needs evpn at its gateway (SDN-63): the problem names the node, the Network and the Capability, a node that reports it
// takes the Stretch, and a node that is no gateway of one needs nothing for it, whatever it reports. The L2 Network of the Stretch
// needs an L2 backend as any L2 Network does, which is the problem of another row.
func TestStretchNeedsEVPN(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd30:1:2::/48"}`),
		res(intent.KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["dc"]}`),
		res(intent.KindStretch, "s", `{"gateway": "gw", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`),
	)

	// A Windows Server with every other Capability has the L2 backend, so evpn is the one that it lacks
	want := `Node "gw" (Server, x64): Stretch of Network "dc-l2" needs evpn, which the node does not report`
	if problems := Check("gw", server, states["gw"]); len(problems) != 1 || problems[0].Error() != want {
		t.Errorf("the problems of gw with the Capabilities of a Server are %v, want [%s]", problems, want)
	}
	// A node that reports no Capability at all lacks it as well, besides the L2 backend
	for _, caps := range []*controlpb.Capabilities{nil, {}} {
		want := `Node "gw": Stretch of Network "dc-l2" needs evpn, which the node does not report`
		if got := problemsAbout(Check("gw", caps, states["gw"])); len(got) != 1 || got[0] != want {
			t.Errorf("the problems of gw about evpn with the Capabilities %v are %v, want [%s]", caps, got, want)
		}
	}

	// A node that reports evpn takes the Stretch
	evpn := proto.Clone(server).(*controlpb.Capabilities)
	evpn.Evpn = true
	if problems := Check("gw", evpn, states["gw"]); len(problems) > 0 {
		t.Errorf("a node that reports evpn was refused: %v", problems)
	}

	// The other node of the VRF gets no Stretch, so it needs no evpn, and a Server needs nothing at all
	for _, caps := range []*controlpb.Capabilities{nil, {}, armHome, server} {
		if got := problemsAbout(Check("host", caps, states["host"])); len(got) > 0 {
			t.Errorf("host, which is no gateway, with the Capabilities %v needs evpn: %v", caps, got)
		}
	}
	if problems := Check("host", server, states["host"]); len(problems) > 0 {
		t.Errorf("host, which is no gateway, was refused by a Server: %v", problems)
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
