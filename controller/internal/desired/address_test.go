package desired

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A node gets its own addresses in the L3 Networks of its VRFs, and each peer comes with its
// addresses in the Networks of the VRFs the two share, and with none of another VRF (SDN-3).
func TestCompileAddresses(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.30.0.0/24"}`),
		res(intent.KindNetwork, "lab-l2", `{"vrf": "lab", "mode": "L2", "ipv4Pool": "10.40.0.0/24"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	)
	self := states["a"][Key{controlpb.Kind_KIND_NODE, "a"}].GetNode()
	if got := addressText(self.GetAddresses()); got != "corp-lan 10 10.10.0.1/24, lab-lan 20 10.30.0.1/24" {
		t.Errorf("a holds the addresses %q", got)
	}
	peer := states["b"][Key{controlpb.Kind_KIND_PEER, "a"}].GetPeer()
	if got := addressText(peer.GetAddresses()); got != "lab-lan 20 10.30.0.1/24" {
		t.Errorf("the peer a of b comes with the addresses %q, want its address in lab alone", got)
	}
	peer = states["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer()
	if got := addressText(peer.GetAddresses()); got != "lab-lan 20 10.30.0.2/24" {
		t.Errorf("the peer b of a comes with the addresses %q", got)
	}
}

// addressText writes addresses as "network vrf prefix", comma-separated.
func addressText(addresses []*controlpb.Address) string {
	var out []string
	for _, a := range addresses {
		ip, _ := netip.AddrFromSlice(a.GetPrefix().GetAddress())
		out = append(out, fmt.Sprintf("%s %d %s", a.GetNetwork(), a.GetVrfId(), netip.PrefixFrom(ip, int(a.GetPrefix().GetLength()))))
	}
	return strings.Join(out, ", ")
}
