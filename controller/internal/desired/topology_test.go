package desired

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// routeText writes routes as "vrf prefix" items joined by "; ".
func routeText(routes []*controlpb.Route) string {
	var out []string
	for _, r := range routes {
		out = append(out, fmt.Sprintf("%d %s", r.GetVrfId(), prefixText(r.GetPrefix())))
	}
	return strings.Join(out, "; ")
}

// peerText returns the Peer peer of the state of node as the VRFs that the two share and the routes
// of the peer, "none" when the state has no such Peer.
func peerText(states map[string]State, node, peer string) string {
	o, ok := states[node][Key{controlpb.Kind_KIND_PEER, peer}]
	if !ok {
		return "none"
	}
	return strings.TrimSuffix(fmt.Sprint(o.GetPeer().GetVrfIds())+"; "+routeText(o.GetPeer().GetRoutes()), "; ")
}

// Two gateways advertise one LAN subnet in VRF corp, which spreads its flows over them (ECMP): the
// NodeConfig of each holds its LAN subnets, every other Node gets them as routes of the Peer of each,
// with the outside prefix of a 1:1 NAT rule, and a gateway gets no route of the other for a subnet that
// it advertises itself. The Vrf object says ECMP and names no hub.
func TestCompileGateways(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48", "ecmp": true}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "gw-1", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}}`),
		res(intent.KindNode, "gw-2", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "lanSubnets": {"corp": ["fd99::/64", "192.168.1.0/24"]}}`),
		res(intent.KindNAT, "gw-2-host", `{"vrf": "corp", "node": "gw-2", "inside": "172.16.0.0/24", "outside": "10.99.0.0/24"}`),
	)
	for _, node := range []string{"a", "gw-1", "gw-2"} {
		if v := states[node][Key{controlpb.Kind_KIND_VRF, "corp"}].GetVrf(); !v.GetEcmp() || v.GetHub() != "" {
			t.Errorf("the VRF corp of %s is %v, want ECMP and no hub", node, v)
		}
	}
	for _, c := range []struct{ node, want string }{
		{"a", ""},
		{"gw-1", "10 192.168.1.0/24"},
		{"gw-2", "10 192.168.1.0/24; 10 fd99::/64"},
	} {
		if got := routeText(states[c.node][Key{controlpb.Kind_KIND_NODE, c.node}].GetNode().GetLanSubnets()); got != c.want {
			t.Errorf("the LAN subnets of %s are %q, want %q", c.node, got, c.want)
		}
	}
	for _, c := range []struct{ node, peer, want string }{
		{"a", "gw-1", "[10]; 10 192.168.1.0/24"},
		{"a", "gw-2", "[10]; 10 10.99.0.0/24; 10 192.168.1.0/24; 10 fd99::/64"},
		{"gw-1", "gw-2", "[10]; 10 10.99.0.0/24; 10 fd99::/64"},
		{"gw-2", "gw-1", "[10]"},
		{"gw-1", "a", "[10]"},
	} {
		if got := peerText(states, c.node, c.peer); got != c.want {
			t.Errorf("the Peer %s of %s is %q, want %q", c.peer, c.node, got, c.want)
		}
	}
}

// VRF branch is of topology hub-and-spoke with the hub hub: the Vrf object of each member names the
// hub, the hub has every spoke as its Peer, and a spoke has the hub as its only Peer in the VRF, with
// the pool of its L3 Network and the LAN subnets of the other spokes as routes of the hub. Two spokes
// that share the full mesh corp too are peers there only, with their addresses of corp.
func TestCompileHubAndSpoke(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "branch", `{"id": 20, "ula": "fd00:20::/48", "topology": "hub-and-spoke", "hub": "hub"}`),
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`),
		res(intent.KindNetwork, "branch-lan", `{"vrf": "branch", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNode, "hub", `{"publicKey": "`+key1+`", "vrfs": ["branch"]}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key2+`", "vrfs": ["branch", "corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key3+`", "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.9.0/24"]}}`),
		res(intent.KindNode, "c", `{"publicKey": "`+key4+`", "vrfs": ["branch", "corp"]}`),
	)
	for _, node := range []string{"hub", "a", "b", "c"} {
		if v := states[node][Key{controlpb.Kind_KIND_VRF, "branch"}].GetVrf(); v.GetHub() != "hub" || v.GetEcmp() {
			t.Errorf("the VRF branch of %s is %v, want the hub hub", node, v)
		}
	}
	if v := states["a"][Key{controlpb.Kind_KIND_VRF, "corp"}].GetVrf(); v.GetHub() != "" {
		t.Errorf("the VRF corp of a names the hub %q, a full mesh none", v.GetHub())
	}
	for _, c := range []struct{ node, peer, want string }{
		{"hub", "a", "[20]"},
		{"hub", "b", "[20]; 20 192.168.9.0/24"},
		{"hub", "c", "[20]"},
		{"a", "hub", "[20]; 20 10.20.0.0/24; 20 192.168.9.0/24"},
		{"b", "hub", "[20]; 20 10.20.0.0/24"},
		{"c", "hub", "[20]; 20 10.20.0.0/24; 20 192.168.9.0/24"},
		{"a", "c", "[10]"},
		{"c", "a", "[10]"},
		{"a", "b", "none"},
		{"b", "a", "none"},
		{"b", "c", "none"},
	} {
		if got := peerText(states, c.node, c.peer); got != c.want {
			t.Errorf("the Peer %s of %s is %q, want %q", c.peer, c.node, got, c.want)
		}
	}
	for _, a := range states["a"][Key{controlpb.Kind_KIND_PEER, "c"}].GetPeer().GetAddresses() {
		if a.GetNetwork() != "corp-lan" {
			t.Errorf("the Peer c of a has the address %s of %s, a Network of the VRF in which both are spokes", prefixText(a.GetPrefix()), a.GetNetwork())
		}
	}
}
