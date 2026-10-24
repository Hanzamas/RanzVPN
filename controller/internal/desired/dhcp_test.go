package desired

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// dhcpLine writes the DHCP responder d of a Network object as one line, "none" for no responder.
func dhcpLine(d *controlpb.Dhcp) string {
	if d == nil {
		return "none"
	}
	addr := func(b []byte) string {
		a, ok := netip.AddrFromSlice(b)
		if !ok {
			return "-"
		}
		return a.String()
	}
	var dns, reserved []string
	for _, b := range d.GetDns() {
		dns = append(dns, addr(b))
	}
	for _, p := range d.GetReserved() {
		reserved = append(reserved, prefixText(p))
	}
	return fmt.Sprintf("mode=%s address=%s gateway=%s dns=%s lease=%d reserved=%s", d.GetMode(), addr(d.GetAddress()), addr(d.GetGateway()),
		strings.Join(dns, ","), d.GetLeaseTime(), strings.Join(reserved, ","))
}

// The node that answers DHCP for an L2 Network gets the responder in the Network object of its
// state, with its own address, the gateway, the DNS servers, the lease time and the reservations
// of the pool; the other node of the VRF gets the Network without one, and no node gets one while
// the responder is off.
func TestCompileDHCP(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "reserved": ["10.20.0.0/29"],
			"dhcp": {"mode": "pool", "node": "a", "gateway": "10.20.0.1", "dns": ["10.20.0.1", "9.9.9.9"], "leaseTime": 3600}}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	}
	states := compile(t, rs...)
	dmz := Key{controlpb.Kind_KIND_NETWORK, "dmz"}
	want := "mode=DHCP_MODE_POOL address=10.20.0.8 gateway=10.20.0.1 dns=10.20.0.1,9.9.9.9 lease=3600 reserved=10.20.0.0/29"
	if got := dhcpLine(states["a"][dmz].GetNetwork().GetDhcp()); got != want {
		t.Errorf("the Network dmz of a, which answers DHCP for it, has the responder\n%s\nwant\n%s", got, want)
	}
	if got := dhcpLine(states["b"][dmz].GetNetwork().GetDhcp()); got != "none" {
		t.Errorf("the Network dmz of b has the responder %s, want none: a answers DHCP for it", got)
	}
	if got, want := states["b"][dmz].GetNetwork().GetMode(), controlpb.NetworkMode_NETWORK_MODE_L2; got != want {
		t.Errorf("the Network dmz of b is of mode %s, want %s", got, want)
	}

	rs[1] = res(intent.KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "dhcp": {"mode": "off", "node": "a"}}`)
	off := compile(t, rs...)
	for _, node := range []string{"a", "b"} {
		if got := dhcpLine(off[node][dmz].GetNetwork().GetDhcp()); got != "none" {
			t.Errorf("with the responder off the Network dmz of %s has the responder %s, want none", node, got)
		}
	}
}
