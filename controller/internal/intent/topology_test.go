package intent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// gatewayLines writes each route as a line: its VRF, its prefix and the Node that it leads to.
func gatewayLines(routes []Route) string {
	var lines []string
	for _, r := range routes {
		lines = append(lines, r.VRF+" "+r.Prefix.String()+" via "+r.Via)
	}
	return strings.Join(lines, "\n")
}

// hubAndSpoke is VRF branch of topology hub-and-spoke, written in capitals, with the hub hub and the
// spokes a, b and c, an L3 and an L2 Network: a and b both advertise the LAN 192.168.1.0/24, b also
// 192.168.2.0/24 and the hub 192.168.100.0/24, and c presents a host LAN with a 1:1 NAT rule.
func hubAndSpoke(extra ...Resource) Document {
	return doc(append([]Resource{
		res(KindVRF, "branch", `{"id": 20, "ula": "fd00:20::/48", "topology": "Hub-And-Spoke", "hub": "hub"}`),
		res(KindNetwork, "branch-lan", `{"vrf": "branch", "ipv4Pool": "10.20.0.0/24", "ipv6Pool": "fd00:20:0:1::/64"}`),
		res(KindNetwork, "branch-l2", `{"vrf": "branch", "mode": "L2", "ipv4Pool": "10.21.0.0/24"}`),
		res(KindNode, "hub", `{"publicKey": "`+key1+`", "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.100.0/24"]}}`),
		res(KindNode, "a", `{"publicKey": "`+key2+`", "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.1.0/24"]}}`),
		res(KindNode, "b", `{"publicKey": "`+key3+`", "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.1.0/24", "192.168.2.0/24"]}}`),
		res(KindNode, "c", `{"publicKey": "`+key4+`", "vrfs": ["branch"]}`),
		nat("c-host", "branch", "c", "172.16.0.0/24", "10.99.3.0/24"),
	}, extra...)...)
}

// The hub of a VRF of topology hub-and-spoke is a peer of each spoke, and two spokes are no peers in
// it. A spoke reaches the prefixes of the VRF through the hub: the LAN subnets of the hub, the pools of
// the L3 Networks of the VRF, and the LAN subnets and the outside prefixes of 1:1 NAT of the other
// spokes, but not a LAN subnet that it advertises itself. The hub reaches the LAN subnets of each spoke
// through that spoke.
func TestHubAndSpokeRoutes(t *testing.T) {
	in, err := Apply(New(), hubAndSpoke(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := in.VRFs["branch"]; v.Topology != TopologyHubAndSpoke || v.Hub != "hub" || !v.HubAndSpoke() {
		t.Errorf("VRF branch is %+v, want the topology %s with the hub hub", v, TopologyHubAndSpoke)
	}
	for _, c := range []struct {
		a, b   string
		spokes bool
	}{{"a", "b", true}, {"b", "c", true}, {"a", "hub", false}, {"hub", "c", false}} {
		if got := in.Spokes("branch", c.a, c.b); got != c.spokes {
			t.Errorf("Spokes(branch, %s, %s) is %v, want %v", c.a, c.b, got, c.spokes)
		}
	}
	for _, c := range []struct{ node, peer, want string }{
		{"a", "hub", "branch 10.20.0.0/24 via hub\nbranch 10.99.3.0/24 via hub\nbranch 192.168.2.0/24 via hub\nbranch 192.168.100.0/24 via hub\nbranch fd00:20:0:1::/64 via hub"},
		{"c", "hub", "branch 10.20.0.0/24 via hub\nbranch 192.168.1.0/24 via hub\nbranch 192.168.2.0/24 via hub\nbranch 192.168.100.0/24 via hub\nbranch fd00:20:0:1::/64 via hub"},
		{"hub", "a", "branch 192.168.1.0/24 via a"},
		{"hub", "b", "branch 192.168.1.0/24 via b\nbranch 192.168.2.0/24 via b"},
		{"hub", "c", ""},
		{"a", "b", ""},
		{"b", "c", ""},
		{"a", "a", ""},
	} {
		if got := gatewayLines(in.GatewayRoutes(c.node, c.peer)); got != c.want {
			t.Errorf("the routes of %s to %s are\n%s\nwant\n%s", c.node, c.peer, got, c.want)
		}
	}
}

// Two gateways advertise one LAN subnet in a full mesh: every other Node of the VRF gets it as a route
// of each, and a gateway gets none of the other for the subnet that it advertises itself. ECMP is a
// setting of the VRF.
func TestGatewayRoutes(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48", "ecmp": true}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "gw-1", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}}`),
		res(KindNode, "gw-2", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.9.0/24", "192.168.1.0/24"]}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := in.VRFs["corp"]; !v.ECMP || v.Topology != "" || v.HubAndSpoke() || in.Spokes("corp", "a", "gw-1") {
		t.Errorf("VRF corp is %+v, want a full mesh with ECMP", v)
	}
	for _, c := range []struct{ node, peer, want string }{
		{"a", "gw-1", "corp 192.168.1.0/24 via gw-1"},
		{"a", "gw-2", "corp 192.168.1.0/24 via gw-2\ncorp 192.168.9.0/24 via gw-2"},
		{"gw-1", "gw-2", "corp 192.168.9.0/24 via gw-2"},
		{"gw-2", "gw-1", ""},
		{"gw-1", "a", ""},
	} {
		if got := gatewayLines(in.GatewayRoutes(c.node, c.peer)); got != c.want {
			t.Errorf("the routes of %s to %s are\n%s\nwant\n%s", c.node, c.peer, got, c.want)
		}
	}
}

// A VRF of topology hub-and-spoke names its hub, a Node that is a member of it, and only such a VRF
// names one; no other topology is known; a Node advertises MaxLANSubnets LAN subnets at most; and a
// Node that is the hub of a VRF cannot be deleted.
func TestTopologyRejects(t *testing.T) {
	member := res(KindNode, "x", `{"publicKey": "`+key1+`", "vrfs": ["branch"]}`)
	outside := res(KindNode, "y", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`)
	corp := res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`)
	for _, c := range []struct{ spec, want string }{
		{`{"topology": "hub-and-spoke"}`, `VRF "branch": the topology hub-and-spoke needs a hub: name the Node that the spokes reach each other through`},
		{`{"topology": "hub-and-spoke", "hub": "nobody"}`, `VRF "branch": the hub, Node "nobody", does not exist`},
		{`{"topology": "hub-and-spoke", "hub": "y"}`, `VRF "branch": the hub, Node "y", is not a member of the VRF`},
		{`{"hub": "x"}`, `VRF "branch": the hub "x" needs the topology hub-and-spoke, and the topology is full-mesh`},
		{`{"topology": "full-mesh", "hub": "x"}`, `VRF "branch": the hub "x" needs the topology hub-and-spoke, and the topology is full-mesh`},
		{`{"topology": "star"}`, `VRF "branch": the topology must be full-mesh or hub-and-spoke, not "star"`},
	} {
		if _, err := Apply(New(), doc(corp, res(KindVRF, "branch", c.spec), member, outside), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.spec, err, c.want)
		}
	}
	if _, err := Apply(New(), doc(corp, res(KindVRF, "branch", `{"topology": "full-mesh"}`), member, outside), nil); err != nil {
		t.Errorf("a VRF of topology full-mesh: %v", err)
	}

	var lans []string
	for k := range MaxLANSubnets + 1 {
		lans = append(lans, fmt.Sprintf("%q", fmt.Sprintf("192.168.%d.0/24", k)))
	}
	many := res(KindNode, "gw", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "lanSubnets": {"corp": [`+strings.Join(lans, ", ")+`]}}`)
	if _, err := Apply(New(), doc(corp, many), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "gw": it advertises 17 LAN subnets, and the control protocol carries at most 16`) {
		t.Errorf("17 LAN subnets: %v", err)
	}

	in, err := Apply(New(), hubAndSpoke(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindNode, "hub"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "hub" is the hub of VRF "branch"`) {
		t.Errorf("deleting the hub: %v", err)
	}
	if _, err := Delete(in, KindNode, "a"); err != nil {
		t.Errorf("deleting a spoke: %v", err)
	}
}

// The LAN subnets of a gateway count among the routes that lead a Node to it, which the control
// protocol carries MaxPeerRoutes of: here the 16 LAN subnets of gw and the outside prefix of its 1:1
// NAT rule.
func TestGatewayRoutesAreBounded(t *testing.T) {
	var lans []string
	for k := range MaxLANSubnets {
		lans = append(lans, fmt.Sprintf("%q", fmt.Sprintf("192.168.%d.0/24", k)))
	}
	rs := []Resource{
		res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "gw", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "lanSubnets": {"corp": [`+strings.Join(lans, ", ")+`]}}`),
	}
	if _, err := Apply(New(), doc(rs...), nil); err != nil {
		t.Errorf("16 LAN subnets of one peer: %v", err)
	}
	rs = append(rs, nat("gw-host", "corp", "gw", "172.16.0.0/24", "10.99.0.0/24"))
	if _, err := Apply(New(), doc(rs...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "a": 17 routes lead to its peer "gw"`) {
		t.Errorf("16 LAN subnets and a NAT rule of one peer: %v", err)
	}
}
