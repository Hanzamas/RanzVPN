package intent

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A VRF of a link of kind vxlan peers by EVPN with the protocol evpn, in any case, with its hold time, and each of its L2
// Networks has its L2 VNI (SDN-78). Its Nodes peer with the sidecar of the peering, as for bgp, and the intent reads back from
// its resources and applies again unchanged.
func TestApplyEVPNPeering(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "EVPN", "holdTime": 9}}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve"}`),
		res(KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}`),
		res(KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2", "vni": 5010}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.1"}, "lanSubnets": {"dc": ["192.168.10.0/24"]}}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := in.VRFs["dc"].Peering; !reflect.DeepEqual(p, Peering{Protocol: PeeringEVPN, HoldTime: 9}) || !p.Peers() {
		t.Errorf("VRF dc has the peering %+v, want evpn with the hold time 9", p)
	}
	if got := in.PeeringVRFs(in.Nodes["a"]); !slices.Equal(got, []string{"dc"}) {
		t.Errorf("the VRFs of Node a that peer are %v, want dc", got)
	}
	if got := in.EVPNVRFs(in.Nodes["a"]); !slices.Equal(got, []string{"dc"}) {
		t.Errorf("the VRFs of Node a that peer by EVPN are %v, want dc", got)
	}
	if got := in.Networks["dc-l2"].VNI; got != 5010 {
		t.Errorf("the L2 Network dc-l2 has the VNI %d, want 5010", got)
	}
	// The LAN subnet of a goes by EVPN: no route of the Controller, and none of the routes of b at a peer
	if got := in.GatewayRoutes("b", "a"); len(got) != 0 {
		t.Errorf("Node b has the routes %v of the Controller to the LAN subnet of a", got)
	}
	if got := in.peeringRoutes("b", "a"); len(got) != 0 {
		t.Errorf("Node b counts %v among the routes of its peer a, which it learns by EVPN", got)
	}

	again, err := Apply(in, doc(in.Resources()...), nil)
	if err != nil || !reflect.DeepEqual(again.VRFs["dc"].Peering, in.VRFs["dc"].Peering) || again.Networks["dc-l2"].VNI != 5010 {
		t.Errorf("the resources applied again: %v, VRF dc %+v, Network dc-l2 %+v", err, again.VRFs["dc"], again.Networks["dc-l2"])
	}
}

// An EVPN peering is refused with the VRF, the Network or the Node and the reason: a link of another kind than vxlan, route
// reflectors, hub-and-spoke, ecmp, an L2 Network without its VNI, a VNI on another Network, out of range or twice, two VXLAN
// ports, another VRF of a link of kind vxlan at a Node, and what only the Controller routes: a 1:1 NAT rule, a leak and an exit.
func TestApplyEVPNPeeringRejects(t *testing.T) {
	const evpn = `"peering": {"protocol": "evpn"}`
	for _, c := range []struct {
		dc, l2, b string
		extra     []Resource
		want      string
	}{
		{`"link": "geneve", ` + evpn, `"vni": 5010`, ``, nil, `VRF "dc": EVPN peering needs a link of kind vxlan, and the link is geneve`},
		{evpn, `"vni": 5010`, ``, nil, `VRF "dc": EVPN peering needs a link of kind vxlan, and the link is noise`},
		{`"link": "vxlan", "peering": {"protocol": "evpn", "reflectors": ["a"]}`, `"vni": 5010`, ``, nil, `VRF "dc": the peering reflectors need the peering protocol bgp`},
		{`"link": "vxlan", "topology": "hub-and-spoke", "hub": "a", ` + evpn, `"vni": 5010`, ``, nil, `VRF "dc": EVPN peering is a full mesh, and the topology is hub-and-spoke`},
		{`"link": "vxlan", "ecmp": true, ` + evpn, `"vni": 5010`, ``, nil, `VRF "dc": ecmp spreads the flows to a LAN subnet over the gateways that advertise it, and with the peering evpn each Node learns one best path`},
		{`"link": "vxlan", ` + evpn, ``, ``, nil, `Network "dc-l2": an L2 Network of VRF "dc", which peers by EVPN, needs a vni`},
		{`"link": "vxlan", ` + evpn, `"vni": 30`, ``, nil, `Network "dc-l2": vni 30 is already the vni of VRF "dc"`},
		{`"link": "vxlan", ` + evpn, `"vni": 16777216`, ``, nil, `Network "dc-l2": vni 16777216 is not from 1 to 16777215`},
		{`"link": "vxlan", ` + evpn, `"vni": 5010`, ``, []Resource{res(KindNetwork, "dc-l2b", `{"vrf": "dc", "mode": "L2", "vni": 5010}`)}, `Network "dc-l2b": vni 5010 is already the vni of Network "dc-l2"`},
		{`"link": "vxlan", ` + evpn, `"vni": 5010`, ``, []Resource{res(KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24", "vni": 7}`)}, `Network "dc-net": vni 7 needs an L2 Network of a VRF that peers by EVPN`},
		{`"link": "vxlan", "peering": {"protocol": "bgp"}`, `"vni": 5010`, ``, nil, `Network "dc-l2": vni 5010 needs an L2 Network of a VRF that peers by EVPN`},
		{`"link": "vxlan", ` + evpn, `"vni": 5010`, `, "vxlanPort": 4800`, nil, `Node "b": VRF "dc" peers by EVPN, and the vtep vxlanPort 4800 is not the 4789 of Node "a"`},
		{`"link": "vxlan", ` + evpn, `"vni": 5010`, ``, []Resource{res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan"}`), res(KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.3"}}`)},
			`Node "c": VRF "dc" peers by EVPN and VRF "lab" has a link of kind vxlan without it`},
		{`"link": "vxlan", ` + evpn, `"vni": 5010`, ``, []Resource{nat("n", "dc", "a", "172.16.0.0/24", "10.200.0.0/24")}, `NAT "n": VRF "dc" peers by EVPN, and a 1:1 NAT rule needs the routes that the Controller gives`},
		{`"link": "vxlan", "importTargets": ["65000:1"], ` + evpn, `"vni": 5010`, ``, nil, `VRF "dc": it peers by EVPN, and a leak needs the routes that the Controller gives`},
		{`"link": "vxlan", "egress": "a", ` + evpn, `"vni": 5010`, ``, nil, `VRF "dc": it peers by EVPN, and its internet exit "a" needs the default route that the Controller gives`},
	} {
		rs := []Resource{
			res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", `+c.dc+`}`),
			res(KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"`+prefixed(c.l2)+`}`),
			res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}}`),
			res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"`+c.b+`}}`),
		}
		// A Resource of the case takes the place of the one of its kind and name
		for _, e := range c.extra {
			if i := slices.IndexFunc(rs, func(r Resource) bool { return r.Kind == e.Kind && r.Name == e.Name }); i >= 0 {
				rs[i] = e
			} else {
				rs = append(rs, e)
			}
		}
		_, err := Apply(New(), doc(rs...), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("VRF dc {%s}, Network dc-l2 {%s}: the error is %v, want one with %q", c.dc, c.l2, err, c.want)
		}
	}
}

// prefixed returns the members s of a JSON object after a comma, "" for none.
func prefixed(s string) string {
	if s == "" {
		return ""
	}
	return ", " + s
}

// What only the Controller routes in a VRF has no place in a VRF that peers by EVPN: a WireGuard Device, an Endpoint of it or into
// it, and a Stretch of one of its Networks, a Node running one EVPN. The problems name the resource and the VRF.
func TestEVPNPeeringRefusesControllerRoutes(t *testing.T) {
	in := Intent{
		VRFs: map[string]VRF{
			"dc":   {ID: 30, Link: LinkVXLAN, VNI: 30, Peering: Peering{Protocol: PeeringEVPN}},
			"corp": {ID: 10},
		},
		Networks: map[string]Network{
			"dc-net":  {VRF: "dc", Mode: ModeL3},
			"dc-l2":   {VRF: "dc", Mode: ModeL2, VNI: 5010},
			"corp-l3": {VRF: "corp", Mode: ModeL3},
		},
		Devices:   map[string]Device{"phone": {Network: "dc-net"}, "laptop": {Network: "corp-l3"}},
		Endpoints: map[string]PublishedEndpoint{"web": {VRF: "dc", Consumer: "corp"}, "db": {VRF: "corp", Consumer: "dc"}, "mail": {VRF: "corp", Consumer: "corp"}},
		Stretches: map[string]Stretch{"dc-stretch": {Network: "dc-l2"}},
	}
	var got []string
	for _, p := range in.validateEVPNPeering() {
		got = append(got, p.Error())
	}
	want := []string{
		`Device "phone": VRF "dc" of its Network peers by EVPN, and a WireGuard Device needs the routes that the Controller gives`,
		`Endpoint "db": VRF "dc" peers by EVPN, and an Endpoint needs the routes that the Controller gives`,
		`Endpoint "web": VRF "dc" peers by EVPN, and an Endpoint needs the routes that the Controller gives`,
		`Stretch "dc-stretch": VRF "dc" of its Network peers by EVPN, and a Node runs one EVPN, of the peering or toward a fabric`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("the problems are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
