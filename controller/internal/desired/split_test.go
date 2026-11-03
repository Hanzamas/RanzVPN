package desired

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// Every node of the VRF of an L3 Network that splits TCP gets tcp_split in the Network object of its
// state; a Network that leaves tcpSplit out, the default, sends it off.
func TestCompileSplit(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "fast", `{"vrf": "corp", "ipv4Pool": "10.21.0.0/24", "tcpSplit": true}`),
		res(intent.KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	}
	states := compile(t, rs...)
	fast := Key{controlpb.Kind_KIND_NETWORK, "fast"}
	lan := Key{controlpb.Kind_KIND_NETWORK, "lan"}
	for _, node := range []string{"a", "b"} {
		if n := states[node][fast].GetNetwork(); n == nil || !n.GetTcpSplit() {
			t.Errorf("the Network fast of %s is %v, want it with tcp_split", node, n)
		}
		if n := states[node][lan].GetNetwork(); n == nil || n.GetTcpSplit() {
			t.Errorf("the Network lan of %s is %v, want it without tcp_split: splitting is off by default", node, n)
		}
	}
}
