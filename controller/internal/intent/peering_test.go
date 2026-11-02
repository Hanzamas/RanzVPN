package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// A VRF whose link is vxlan or geneve peers by BGP with the protocol bgp, in any case, and its hold
// time; the peering reads back from the resources and applies again unchanged, and a VRF that names
// none has none in its resource. The router id of a Node with an IPv4 tunnel endpoint is that
// address, and of one with an IPv6 tunnel endpoint 4 bytes of its hash.
func TestApplyPeering(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "BGP", "holdTime": 9}}`),
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc", "corp"], "vtep": {"address": "10.1.0.1"}, "lanSubnets": {"dc": ["192.168.10.0/24"]}}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`),
		res(KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := in.VRFs["dc"].Peering; !reflect.DeepEqual(p, Peering{Protocol: PeeringBGP, HoldTime: 9}) {
		t.Errorf("VRF dc has the peering %+v, want bgp with the hold time 9", p)
	}
	if got := in.PeeringVRFs(in.Nodes["a"]); strings.Join(got, ",") != "dc" {
		t.Errorf("the VRFs of Node a that peer by BGP are %v, want dc", got)
	}
	if got := in.PeeringVRFs(in.Nodes["c"]); len(got) != 0 {
		t.Errorf("the VRFs of Node c that peer by BGP are %v, want none", got)
	}

	v4 := netip.MustParseAddr("10.1.0.1")
	if got := RouterID(v4); got != v4 {
		t.Errorf("the router id of the vtep address %s is %s", v4, got)
	}
	a6, b6 := RouterID(netip.MustParseAddr("2001:db8::2")), RouterID(netip.MustParseAddr("2001:db8::3"))
	if !a6.Is4() || a6 == b6 {
		t.Errorf("the router ids of the vtep addresses 2001:db8::2 and 2001:db8::3 are %s and %s", a6, b6)
	}

	rs := in.Resources()
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || !reflect.DeepEqual(again.VRFs["dc"].Peering, in.VRFs["dc"].Peering) {
		t.Errorf("the resources applied again: %v, VRF dc %+v", err, again.VRFs["dc"])
	}
	for _, r := range rs {
		if r.Kind == KindVRF && r.Name == "corp" && strings.Contains(string(r.Spec), "peering") {
			t.Errorf("the resource of VRF corp, which names no peering, is %s", r.Spec)
		}
	}
}

// A peering is refused with the VRF or the Node and the reason: an unknown protocol, a VRF whose link
// is noise, a VRF of topology hub-and-spoke, ecmp, a hold time without the protocol or out of range, tunnel
// endpoints of two families in one VRF that peers, more LAN subnets than a Node announces, and two
// Nodes of one router id.
func TestApplyPeeringRejects(t *testing.T) {
	var lans []string
	for i := range MaxPeeringAnnounce + 1 {
		lans = append(lans, fmt.Sprintf(`"192.168.%d.0/24"`, i))
	}
	many := `, "lanSubnets": {"dc": [` + strings.Join(lans, ", ") + `]}`
	for _, c := range []struct {
		dc, a, b string
		want     string
	}{
		{`"link": "vxlan", "peering": {"protocol": "ospf"}`, ``, `10.1.0.2`, `VRF "dc": the peering protocol must be bgp, not "ospf"`},
		{`"link": "noise", "peering": {"protocol": "bgp"}`, ``, `10.1.0.2`, `VRF "dc": BGP peering needs a link of kind vxlan or geneve, and the link is noise`},
		{`"peering": {"protocol": "bgp"}`, ``, `10.1.0.2`, `VRF "dc": BGP peering needs a link of kind vxlan or geneve, and the link is noise`},
		{`"link": "vxlan", "topology": "hub-and-spoke", "hub": "a", "peering": {"protocol": "bgp"}`, ``, `10.1.0.2`, `VRF "dc": BGP peering is a full mesh, and the topology is hub-and-spoke`},
		{`"link": "vxlan", "ecmp": true, "peering": {"protocol": "bgp"}`, ``, `10.1.0.2`,
			`VRF "dc": ecmp spreads the flows to a LAN subnet over the gateways that advertise it, and with the peering bgp each Node learns one best path for each prefix, so the flows would never spread: leave out ecmp or the peering`},
		{`"link": "vxlan", "peering": {"holdTime": 9}`, ``, `10.1.0.2`, `VRF "dc": the peering holdTime 9 needs the peering protocol bgp`},
		{`"link": "vxlan", "peering": {"protocol": "bgp", "holdTime": 2}`, ``, `10.1.0.2`, `VRF "dc": the peering holdTime 2 is not from 3 to 65535`},
		{`"link": "vxlan", "peering": {"protocol": "bgp", "holdTime": 70000}`, ``, `10.1.0.2`, `VRF "dc": the peering holdTime 70000 is not from 3 to 65535`},
		{`"link": "geneve", "peering": {"protocol": "bgp"}`, ``, `2001:db8::2`, `Node "b": VRF "dc" peers by BGP, and the vtep address 2001:db8::2 is not of the family of the one of Node "a"`},
		{`"link": "vxlan", "peering": {"protocol": "bgp"}`, many, `10.1.0.2`, `Node "a": it advertises 17 LAN subnets, and the control protocol carries at most 16`},
	} {
		_, err := Apply(New(), doc(
			res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", `+c.dc+`}`),
			res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "10.1.0.1"}`+c.a+`}`),
			res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "`+c.b+`"}}`),
		), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("VRF dc {%s}, Node b at %s: the error is %v, want one with %q", c.dc, c.b, err, c.want)
		}
	}

	// The router id of a Node with an IPv6 tunnel endpoint in one VRF is the IPv4 tunnel endpoint of a
	// Node in another: an IPv6 address whose router id can be a tunnel endpoint
	v6 := netip.MustParseAddr("2001:db8::2")
	for {
		if _, err := ParseVTEPAddress(RouterID(v6).String()); err == nil {
			break
		}
		v6 = v6.Next()
	}
	id := RouterID(v6)
	_, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "vxlan", "peering": {"protocol": "bgp"}}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "vtep": {"address": "`+v6.String()+`"}}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"], "vtep": {"address": "`+id.String()+`"}}`),
	), nil)
	if want := fmt.Sprintf(`Node "b": its BGP router id %s, from its vtep address, is already the one of Node "a"`, id); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("two Nodes of the router id %s: the error is %v, want one with %q", id, err, want)
	}
}

// ecmp and the peering exclude each other on one VRF (SDN-77-R2): a Node takes one best path for each prefix from BGP, so the
// groups of gateways of the Controller, which spread the flows to a LAN subnet over its gateways, would never apply there. The
// Intent refuses both on one VRF, naming it and saying why, and takes each of them alone, and the two on two VRFs.
func TestPeeringExcludesECMP(t *testing.T) {
	const bgp = `"peering": {"protocol": "bgp"}`
	for _, c := range []struct {
		dc, corp string
		ok       bool
	}{
		{`"link": "vxlan", "ecmp": true, ` + bgp, `"ecmp": true`, false},
		{`"link": "geneve", "ecmp": true, ` + bgp, ``, false},
		{`"link": "vxlan", ` + bgp, `"ecmp": true`, true},
		{`"link": "vxlan", "ecmp": true`, ``, true},
		{`"link": "vxlan", "ecmp": false, ` + bgp, ``, true},
	} {
		corp := `{"id": 10, "ula": "fd12:3456:789a::/48"`
		if c.corp != "" {
			corp += ", " + c.corp
		}
		_, err := Apply(New(), doc(
			res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", `+c.dc+`}`),
			res(KindVRF, "corp", corp+`}`),
			res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc", "corp"], "vtep": {"address": "10.1.0.1"}}`),
			res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc", "corp"], "vtep": {"address": "10.1.0.2"}}`),
		), nil)
		switch {
		case c.ok && err != nil:
			t.Errorf("VRF dc {%s}, VRF corp {%s}: %v", c.dc, c.corp, err)
		case !c.ok && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `VRF "dc": ecmp spreads the flows to a LAN subnet over the gateways that advertise it, and with the peering bgp each Node learns one best path for each prefix`)):
			t.Errorf("VRF dc {%s}, VRF corp {%s}: %v, want a refusal that names VRF dc and says why", c.dc, c.corp, err)
		case !c.ok && strings.Contains(err.Error(), `VRF "corp"`):
			t.Errorf("VRF dc {%s}, VRF corp {%s}: the refusal names VRF corp, which does not peer: %v", c.dc, c.corp, err)
		}
	}
}

// The LAN subnets that a Node learns from a peer by BGP take the slots of the routes to that peer like the routes of the
// Controller do (SDN-77-R2): peer x of VRF red, which peers by BGP, has 12 LAN subnets and some 1:1 NAT rules, and Node a, to
// which 17 or 18 routes lead, is refused with the message of the routes of the Controller, the one that the same LAN subnets get
// in a VRF that does not peer, while 16 are none too many. A Node that advertises the LAN subnets itself learns none of them.
func TestPeeringRoutesAreBounded(t *testing.T) {
	var lans []string
	for i := range 12 {
		lans = append(lans, fmt.Sprintf(`"192.168.%d.0/24"`, i))
	}
	subnets := `, "lanSubnets": {"red": [` + strings.Join(lans, ", ") + `]}`
	// VRF red with the peering, Node a with the spec a, and Node x with the 12 LAN subnets and nats 1:1 NAT rules
	build := func(peering, a string, nats int) []Resource {
		rs := []Resource{
			res(KindVRF, "red", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"`+peering+`}`),
			res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["red"], "vtep": {"address": "10.1.0.1"}`+a+`}`),
			res(KindNode, "x", `{"publicKey": "`+key2+`", "vrfs": ["red"], "vtep": {"address": "10.1.0.2"}`+subnets+`}`),
		}
		for i := range nats {
			rs = append(rs, nat(fmt.Sprintf("x-%d", i), "red", "x", fmt.Sprintf("172.16.%d.0/24", i), fmt.Sprintf("10.200.%d.0/24", i)))
		}
		return rs
	}
	const bgp = `, "peering": {"protocol": "bgp"}`

	// 12 LAN subnets and 4 NAT rules are the 16 routes that a Peer carries
	if _, err := Apply(New(), doc(build(bgp, "", 4)...), nil); err != nil {
		t.Errorf("12 LAN subnets and 4 NAT rules of one peer in a VRF that peers by BGP: %v", err)
	}
	for _, c := range []struct{ nats, routes int }{{5, 17}, {6, 18}} {
		_, err := Apply(New(), doc(build(bgp, "", c.nats)...), nil)
		// The head and the tail of the message of the routes of the Controller (TestPeerRoutesAreBounded pins the whole of it)
		want := fmt.Sprintf(`Node "a": %d routes lead to its peer "x", `, c.routes)
		const tail = `and the control protocol carries at most 16`
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), tail) {
			t.Errorf("12 LAN subnets and %d NAT rules of one peer in a VRF that peers by BGP: %v, want an error with %q and %q", c.nats, err, want, tail)
			continue
		}
		// The same LAN subnets as routes of the Controller, in a VRF that does not peer, are refused with the same message
		if _, own := Apply(New(), doc(build("", "", c.nats)...), nil); own == nil || own.Error() != err.Error() {
			t.Errorf("%d routes of the Controller are refused with %v, and the same ones by BGP with %v: want one message", c.routes, own, err)
		}
	}

	// Node a advertises the 12 LAN subnets of x too, as a gateway of the same group: its own path is the best one, so it learns none
	// of them and has the 6 routes of the NAT rules only. Node c does not advertise them, and has 18 routes to x
	rs := append(build(bgp, subnets, 6), res(KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["red"], "vtep": {"address": "10.1.0.3"}}`))
	_, err := Apply(New(), doc(rs...), nil)
	if want := `Node "c": 18 routes lead to its peer "x"`; err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), `Node "a"`) {
		t.Errorf("Node c, which advertises none of the LAN subnets of x, and Node a, which advertises them: %v, want an error with %q that does not name Node a", err, want)
	}
}
