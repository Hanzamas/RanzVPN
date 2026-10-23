package desired

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="

// prefixText returns p as text, "-" for none.
func prefixText(p *controlpb.Prefix) string {
	a, ok := netip.AddrFromSlice(p.GetAddress())
	if !ok {
		return "-"
	}
	return netip.PrefixFrom(a, int(p.GetLength())).String()
}

// A node gets the 1:1 NAT rules that it applies, the 4via6 of its two VRFs on one range among
// them, and each peer the outside prefixes of that peer's rules of one family in the VRFs they
// share as its routes; the 4via6 of a peer is no route.
func TestCompileNAT(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48"}`),
		res(intent.KindVRF, "blue", `{"id": 202, "ula": "fd00:202::/48"}`),
		res(intent.KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.0.0.0/24"}`),
		res(intent.KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.0.0.0/24"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["red", "blue"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["blue"]}`),
		res(intent.KindNAT, "b-lan", `{"vrf": "red", "node": "b", "inside": "192.168.7.0/24", "outside": "10.99.7.0/24"}`),
		res(intent.KindNAT, "a-lab", `{"vrf": "blue", "node": "a", "inside": "172.16.0.0/16", "outside": "10.98.0.0/16"}`),
	)
	for _, c := range []struct {
		node string
		want string
	}{
		{"a", "101 fd00:101:0:ffff::/96 > 0.0.0.0/0; 202 172.16.0.0/16 > 10.98.0.0/16; 202 fd00:202:0:ffff::/96 > 0.0.0.0/0"},
		{"b", "101 192.168.7.0/24 > 10.99.7.0/24"},
		{"c", ""},
	} {
		var got []string
		for _, r := range states[c.node][Key{controlpb.Kind_KIND_NODE, c.node}].GetNode().GetNat() {
			got = append(got, fmt.Sprintf("%d %s > %s", r.GetVrfId(), prefixText(r.GetInside()), prefixText(r.GetOutside())))
		}
		if strings.Join(got, "; ") != c.want {
			t.Errorf("%s applies %q, want %q", c.node, strings.Join(got, "; "), c.want)
		}
	}
	for _, c := range []struct {
		node, peer string
		want       string
	}{
		{"a", "b", "101 10.99.7.0/24"},
		{"a", "c", ""},
		{"b", "a", ""},
		{"c", "a", "202 10.98.0.0/16"},
	} {
		var got []string
		for _, r := range states[c.node][Key{controlpb.Kind_KIND_PEER, c.peer}].GetPeer().GetRoutes() {
			got = append(got, fmt.Sprintf("%d %s", r.GetVrfId(), prefixText(r.GetPrefix())))
		}
		if strings.Join(got, "; ") != c.want {
			t.Errorf("the routes of the peer %s of %s are %q, want %q", c.peer, c.node, strings.Join(got, "; "), c.want)
		}
	}
}
