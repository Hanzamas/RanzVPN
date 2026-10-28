package desired

import (
	"slices"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// Every node of the VRF of an L2 Network gets its security in the Network object of its state: the
// protections that are on, the limits of the checks and the gateways, the node that answers DHCP
// for the Network among them. A Network without a security, and one whose security turns nothing
// on, get none; a check that is off sends no limit.
func TestCompileSecurity(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24",
			"security": {"checkMac": true, "checkIp": true, "maxIps": 4, "arpDhcpOnly": true, "dhcpGuard": true, "raGuard": true, "gateways": ["b"]},
			"dhcp": {"mode": "pool", "node": "a"}}`),
		res(intent.KindNetwork, "plain", `{"vrf": "corp", "mode": "L2"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	}
	states := compile(t, rs...)
	dmz := Key{controlpb.Kind_KIND_NETWORK, "dmz"}
	plain := Key{controlpb.Kind_KIND_NETWORK, "plain"}
	for _, node := range []string{"a", "b"} {
		s := states[node][dmz].GetNetwork().GetSecurity()
		if !s.GetCheckMac() || !s.GetCheckIp() || s.GetMaxMacs() != intent.DefaultSecurityMACs || s.GetMaxIps() != 4 || !s.GetArpDhcpOnly() || !s.GetDhcpGuard() ||
			!s.GetRaGuard() || !slices.Equal(s.GetGateways(), []string{"a", "b"}) {
			t.Errorf("the Network dmz of %s has the security %v, want every protection, the limits %d and 4, and the gateways a, which answers DHCP, and b",
				node, s, intent.DefaultSecurityMACs)
		}
		if s := states[node][plain].GetNetwork().GetSecurity(); s != nil {
			t.Errorf("the Network plain of %s has the security %v, want none", node, s)
		}
	}

	rs[1] = res(intent.KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "security": {"gateways": ["b"]}}`)
	if s := compile(t, rs...)["a"][dmz].GetNetwork().GetSecurity(); s != nil {
		t.Errorf("a security that turns no protection on compiles to %v, want none", s)
	}
	rs[1] = res(intent.KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "security": {"raGuard": true}}`)
	s := compile(t, rs...)["b"][dmz].GetNetwork().GetSecurity()
	if !s.GetRaGuard() || s.GetCheckMac() || s.GetMaxMacs() != 0 || s.GetMaxIps() != 0 || len(s.GetGateways()) != 0 {
		t.Errorf("the RA guard alone compiles to %v, want it without limits or gateways", s)
	}
}
