package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// An L3 Network that splits TCP needs tcpSplit on every node of its VRF (CORE-P2-3): a node of an older release, which reports
// every other Capability, is refused, and the problem names the node, the Network and the Capability. A node that reports it is
// not, a Network of the VRF that does not split TCP needs nothing, and a node outside the VRF is not asked for it.
func TestTCPSplitNeedsTheCapability(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-fast", `{"vrf": "corp", "ipv4Pool": "10.11.0.0/24", "tcpSplit": true}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	)

	want := `Node "gw" (Server, x64): TCP splitting of Network "corp-fast" needs tcpSplit, which the node does not report`
	if problems := Check("gw", server, states["gw"]); len(problems) != 1 || problems[0].Error() != want {
		t.Errorf("the problems of gw with the Capabilities of a Server of an older release are %v, want [%s]", problems, want)
	}
	for _, caps := range []*controlpb.Capabilities{nil, {}} {
		want := `Node "gw": TCP splitting of Network "corp-fast" needs tcpSplit, which the node does not report`
		if problems := Check("gw", caps, states["gw"]); len(problems) != 1 || problems[0].Error() != want {
			t.Errorf("the problems of gw with the Capabilities %v are %v, want [%s]", caps, problems, want)
		}
	}

	split := proto.Clone(armHome).(*controlpb.Capabilities)
	split.TcpSplit = true
	if problems := Check("gw", split, states["gw"]); len(problems) > 0 {
		t.Errorf("a node that reports tcpSplit was refused: %v", problems)
	}

	// laptop is no member of corp: its state holds no Network of corp
	for _, caps := range []*controlpb.Capabilities{nil, {}, armHome} {
		if problems := Check("laptop", caps, states["laptop"]); len(problems) > 0 {
			t.Errorf("laptop, outside the VRF of the Network that splits TCP, with the Capabilities %v was refused: %v", caps, problems)
		}
	}

	// Splitting is off by default: the same VRF without tcpSplit needs nothing
	plain := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "corp-fast", `{"vrf": "corp", "ipv4Pool": "10.11.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	)
	if problems := Check("gw", armHome, plain["gw"]); len(problems) > 0 {
		t.Errorf("a Network that does not split TCP was refused: %v", problems)
	}
}

// The Capability reads from the Hello into the API form and back, under the name tcpSplit; a node that reports nothing reports
// no tcpSplit.
func TestAPIFormTCPSplit(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{TcpSplit: true})
	if !c.TCPSplit {
		t.Errorf("the API form of a Hello with tcp_split is %+v", c)
	}
	p, err := c.Proto()
	if err != nil || !p.GetTcpSplit() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
	if b, err := json.Marshal(c); err != nil || !strings.Contains(string(b), `"tcpSplit":true`) {
		t.Errorf("the JSON of the API form is %s, %v, want tcpSplit", b, err)
	}
	if b, err := json.Marshal(FromProto(&controlpb.Capabilities{})); err != nil || strings.Contains(string(b), "tcpSplit") {
		t.Errorf("the JSON of a node that reports nothing is %s, %v, want no tcpSplit", b, err)
	}
}
