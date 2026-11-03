package sidecar

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The symmetric IRB of the tests (SDN-67 #294): the stretch of VNI 5010 routes in VRF 101 of testEVPN, whose L3 VNI is 10101,
// with a gateway IP of each family; the stretch of VNI 5030 has no irb; and the stretch of VNI 5040 routes in VRF 102, whose L3
// VNI is 10102, on the same Network addresses as the one of VNI 5010
const (
	testPlainVNI      = 5030
	testPlainTarget   = "65000:5030"
	testOverlapVNI    = 5040
	testOverlapTarget = "65000:5040"
)

func testIRBEVPN() *EVPN {
	e := testEVPN()
	e.Stretches = []EVPNStretch{
		{VNI: testStretchVNI, RouteTargets: []string{testStretchTarget}, IRB: true, VRF: 101, GatewayIPs: []string{"10.50.0.1/24", "fd50::1/64"}},
		{VNI: testPlainVNI, RouteTargets: []string{testPlainTarget}},
	}
	return e
}

// The IRB of a stretch is checked before BGP starts: the VRF and the gateway IPs of a stretch with irb, a stretch without irb
// names neither, and each thing that they may not hold.
func TestParseIRB(t *testing.T) {
	routerID := netip.MustParseAddr("192.0.2.1")
	st, err := parseEVPN(testIRBEVPN(), routerID)
	if err != nil {
		t.Fatal(err)
	}
	v, plain := st.stretch.byVNI[testStretchVNI], st.stretch.byVNI[testPlainVNI]
	if v == nil || v.irb == nil || v.irb.vrf != st.byID[101] || len(v.irb.gateways) != 2 || v.irb.gateways[0].String() != "10.50.0.1/24" ||
		v.irb.gateways[1].String() != "fd50::1/64" {
		t.Fatalf("the stretch with irb: %+v", v)
	}
	if plain == nil || plain.irb != nil {
		t.Fatalf("the stretch without irb: %+v", plain)
	}

	// Both addresses of an IPv4 /31 and of an IPv6 /127 are hosts
	e := testIRBEVPN()
	e.Stretches[0].GatewayIPs = []string{"10.50.0.0/31", "fd50::1/127"}
	if _, err := parseEVPN(e, routerID); err != nil {
		t.Errorf("gateway IPs of a /31 and a /127: %v", err)
	}

	cases := []struct {
		name string
		edit func(s *EVPNStretch)
		want string
	}{
		{"irb without a vrf", func(s *EVPNStretch) { s.VRF = 0 }, "vrf 0 is no EVPN VRF"},
		{"irb with a vrf of no EVPN VRF", func(s *EVPNStretch) { s.VRF = 103 }, "vrf 103 is no EVPN VRF"},
		{"irb without gateway IPs", func(s *EVPNStretch) { s.GatewayIPs = nil }, "gateway_ips holds 1 to 2"},
		{"three gateway IPs", func(s *EVPNStretch) { s.GatewayIPs = append(s.GatewayIPs, "10.51.0.1/24") }, "gateway_ips holds 1 to 2"},
		{"two IPv4 gateway IPs", func(s *EVPNStretch) { s.GatewayIPs = []string{"10.50.0.1/24", "10.51.0.1/24"} }, "two addresses"},
		{"a gateway IP without its prefix length", func(s *EVPNStretch) { s.GatewayIPs = []string{"10.50.0.1"} }, "prefix length"},
		{"the first address of an IPv4 subnet", func(s *EVPNStretch) { s.GatewayIPs = []string{"10.50.0.0/24"} }, "first address"},
		{"the first address of an IPv6 subnet", func(s *EVPNStretch) { s.GatewayIPs = []string{"fd50::/64"} }, "first address"},
		{"the broadcast address", func(s *EVPNStretch) { s.GatewayIPs = []string{"10.50.0.255/24"} }, "broadcast address"},
		{"an address without a subnet", func(s *EVPNStretch) { s.GatewayIPs = []string{"10.50.0.1/32"} }, "one host in a subnet"},
		{"a multicast address", func(s *EVPNStretch) { s.GatewayIPs = []string{"224.0.0.1/24"} }, "one host in a subnet"},
		{"a link-local address", func(s *EVPNStretch) { s.GatewayIPs = []string{"fe80::1/64"} }, "one host in a subnet"},
		{"a vrf without irb", func(s *EVPNStretch) { s.IRB = false; s.GatewayIPs = nil }, "without irb"},
		{"gateway IPs without irb", func(s *EVPNStretch) { s.IRB = false; s.VRF = 0 }, "without irb"},
	}
	for _, c := range cases {
		e := testIRBEVPN()
		c.edit(&e.Stretches[0])
		if st, err := parseEVPN(e, routerID); err == nil || st != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %+v, %v; want an error that says %q", c.name, st, err, c.want)
		}
	}
}

// irbRoute is a type-2 route of the gateway as the fabric router has it, with what irb adds to it: its labels, its route targets
// in order, its router MAC and whether it has the default gateway extended community
type irbRoute struct {
	labels  []uint32
	targets []string
	mac     string
	gateway bool
	nextHop string
}

// irbRoutes are the type-2 routes that the fabric router has from the gateway, "<first label> <mac> <ip>" by their text
func (f *testFabric) irbRoutes() map[string]irbRoute {
	f.t.Helper()
	out := make(map[string]irbRoute)
	err := f.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_EVPN}, func(n bgp.NLRI, paths []*apiutil.Path) {
		e, ok := n.(*bgp.EVPNNLRI)
		if !ok {
			return
		}
		r, ok := e.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok || len(r.Labels) == 0 {
			return
		}
		ip := ""
		if r.IPAddressLength != 0 {
			ip = r.IPAddress.String()
		}
		for _, p := range paths {
			if !p.PeerAddress.IsValid() {
				continue
			}
			out[fmt.Sprintf("%d %s %s", r.Labels[0], r.MacAddress, ip)] = irbRoute{labels: slices.Clone(r.Labels), targets: slices.Sorted(slices.Values(routeTargets(p.Attrs))),
				mac: routerMACOf(p.Attrs), gateway: hasDefaultGateway(p.Attrs), nextHop: pathNextHop(p).String()}
		}
	})
	if err != nil {
		f.t.Fatalf("fabric RIB: %v", err)
	}
	return out
}

// announceIRB announces the type-2 route of mac and ip behind the VTEP of the fabric with labels under the route distinguisher
// rd, with the route targets, the VXLAN encapsulation, the router MAC rmac ("" for none) and, with gateway, the default gateway
// extended community: the form of a leaf with symmetric IRB, or another one
func (f *testFabric) announceIRB(rd string, labels []uint32, mac, ip, rmac string, gateway bool, targets ...string) uuid.UUID {
	f.t.Helper()
	d, err := bgp.ParseRouteDistinguisher(rd)
	if err != nil {
		f.t.Fatal(err)
	}
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(d, bgp.EthernetSegmentIdentifier{}, 0, mac, netip.MustParseAddr(ip), labels)
	if err != nil {
		f.t.Fatal(err)
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(testFabricVTEP))
	if err != nil {
		f.t.Fatal(err)
	}
	var ecs []bgp.ExtendedCommunityInterface
	for _, rt := range targets {
		ec, err := bgp.ParseRouteTarget(rt)
		if err != nil {
			f.t.Fatal(err)
		}
		ecs = append(ecs, ec)
	}
	ecs = append(ecs, bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN))
	if rmac != "" {
		ecs = append(ecs, bgp.NewRoutersMacExtended(rmac))
	}
	if gateway {
		ecs = append(ecs, bgp.NewDefaultGatewayExtended())
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), reach, bgp.NewPathAttributeExtendedCommunities(ecs)}
	return f.add(&apiutil.Path{Family: bgp.RF_EVPN, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix()})
}

// The IRB of a gateway against a fabric router. Into the fabric: each gateway IP of the stretch with irb is a type-2 route of the
// router MAC with both labels, the route targets of the stretch and of the VRF, the router MAC and the default gateway extended
// community; a type-2 route of the node of the MAC plus IP form on that stretch carries the L3 VNI and the router MAC, and its
// MAC only form does not. The stretch without irb announces no gateway IP or MAC of its Network: only the routes of the node,
// each with one label and no router MAC, default gateway community or route target of a VRF. Out of the fabric: a type-2 route
// of the form of a leaf with symmetric IRB in a gateway IP prefix is a host route of the VRF, with the second label as its VNI,
// the router MAC and the VTEP of the fabric, IPv4 and IPv6, and goes with its route; a route without a second label, outside
// the gateway IP prefixes, of a default gateway, without the route target of the VRF, without a router MAC, or of the stretch
// without irb gives none, and each still reaches the node as a route of its stretch.
func TestIRB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	node := startNode(t, ctx)
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      int32(port),
		ListenAddresses: []string{"127.0.0.1"},
		Peers:           []Peer{{Address: "127.0.0.3", ASN: 65010, Passive: true}},
		EVPN:            testIRBEVPN(),
	})
	node.wait("ready", false, isType(TypeReady))
	fabric := startFabric(t, 65010, "192.0.2.10", "127.0.0.3", port)
	node.wait("the fabric established", true, isPeer("127.0.0.3", StateEstablished))

	// The gateway IPs of the stretch with irb
	gateways := []string{"5010 " + DefaultRouterMAC + " 10.50.0.1", "5010 " + DefaultRouterMAC + " fd50::1"}
	waitUntil(t, "the fabric has the gateway IPs of the stretch with irb", func() bool {
		r := fabric.irbRoutes()
		_, a := r[gateways[0]]
		_, b := r[gateways[1]]
		return a && b
	})
	both := []string{"65000:10101", testStretchTarget}
	for _, k := range gateways {
		g := fabric.irbRoutes()[k]
		if !slices.Equal(g.labels, []uint32{testStretchVNI, 10101}) || !slices.Equal(g.targets, both) || g.mac != DefaultRouterMAC || !g.gateway || g.nextHop != testVTEP {
			t.Errorf("the gateway IP %s at the fabric: %+v", k, g)
		}
	}

	// The routes of the node on both stretches
	node.resync([]StretchRoute{
		{VNI: testStretchVNI, MAC: testMAC(false, 1)},
		{VNI: testStretchVNI, MAC: testMAC(false, 1), IP: "10.50.0.5"},
		{VNI: testPlainVNI, MAC: testMAC(false, 2)},
		{VNI: testPlainVNI, MAC: testMAC(false, 2), IP: "10.53.0.5"},
	})
	waitUntil(t, "the fabric has the routes of the node", func() bool { return len(fabric.irbRoutes()) == len(gateways)+4 })
	routes := fabric.irbRoutes()
	if r := routes["5010 "+testMAC(false, 1)+" 10.50.0.5"]; !slices.Equal(r.labels, []uint32{testStretchVNI, 10101}) || !slices.Equal(r.targets, both) ||
		r.mac != DefaultRouterMAC || r.gateway {
		t.Errorf("the MAC plus IP form on the stretch with irb at the fabric: %+v", r)
	}
	if r := routes["5010 "+testMAC(false, 1)+" "]; !slices.Equal(r.labels, []uint32{testStretchVNI}) || !slices.Equal(r.targets, []string{testStretchTarget}) ||
		r.mac != "" || r.gateway {
		t.Errorf("the MAC only form on the stretch with irb at the fabric: %+v", r)
	}

	// With irb off, no gateway IP or MAC of the Network: the routes of the node alone, each without what irb adds
	plain := []string{"5030 " + testMAC(false, 2) + " ", "5030 " + testMAC(false, 2) + " 10.53.0.5"}
	for k, r := range routes {
		if !strings.HasPrefix(k, "5030 ") {
			continue
		}
		if !slices.Contains(plain, k) || !slices.Equal(r.labels, []uint32{testPlainVNI}) || !slices.Equal(r.targets, []string{testPlainTarget}) || r.mac != "" || r.gateway {
			t.Errorf("a route on the stretch without irb at the fabric: %s %+v", k, r)
		}
	}
	for k := range routes {
		if strings.Contains(k, " "+DefaultRouterMAC+" ") && !slices.Contains(gateways, k) {
			t.Errorf("the router MAC at the fabric in a route that is no gateway IP of the stretch with irb: %s", k)
		}
	}

	// The fabric: a host of each family in the form of a leaf with symmetric IRB, and the routes that give no host route
	irb := []string{testStretchTarget, "65000:10101"}
	in := fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 1), "10.50.0.10", testFabricMAC, false, irb...)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 2), "fd50::10", testFabricMAC, false, irb...)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI}, testMAC(true, 3), "10.50.0.13", "", false, testStretchTarget)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 4), "10.99.0.14", testFabricMAC, false, irb...)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 5), "10.50.0.254", testFabricMAC, true, irb...)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 6), "10.50.0.16", testFabricMAC, false, testStretchTarget)
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 7), "10.50.0.17", "", false, irb...)
	fabric.announceIRB("192.0.2.10:5030", []uint32{testPlainVNI, 10101}, testMAC(true, 8), "10.53.0.18", testFabricMAC, false, testPlainTarget, "65000:10101")

	for _, prefix := range []string{"10.50.0.10/32", "fd50::10/128"} {
		r := node.wait("the host route "+prefix+" in VRF 101", true, isEVPNRoute(TypeLearned, 101, prefix))
		if r.NextHop != testFabricVTEP || r.VNI != 10101 || r.RouterMAC != testFabricMAC || r.Peer != "127.0.0.3" || !slices.Equal(r.VTEPs, []string{testFabricVTEP}) {
			t.Errorf("the host route %s in VRF 101: %+v", prefix, r)
		}
	}
	waitUntil(t, "the node learns the type-2 routes of the fabric on both stretches", func() bool {
		l := node.learnedStretch()
		return len(l) == 8
	})
	time.Sleep(settleTime)
	node.drain()
	for _, m := range node.seen {
		if m.Type == TypeLearned && m.VNI != 0 && m.Prefix != "10.50.0.10/32" && m.Prefix != "fd50::10/128" {
			t.Errorf("a host route that the gateway may not take: %+v", m)
		}
	}

	// The route goes, and its host route with it
	fabric.withdraw(in)
	if r := node.wait("the host route 10.50.0.10/32 withdrawn", false, isEVPNRoute(TypeWithdrawn, 101, "10.50.0.10/32")); r.VNI != 10101 {
		t.Errorf("the withdrawn host route: %+v", r)
	}
}

// Overlapping VRFs stay apart (SDN-67 #294): two stretches with irb on the same Network addresses, each in its own EVPN VRF. The
// gateway IP of each goes to the fabric with the L3 VNI and the route targets of its own VRF alone. A host of the fabric with the
// same address on each stretch is a host route of the VRF of its own stretch alone, with the VNI and the router MAC of its route;
// a type-2 route of one stretch with the route target of the VRF of the other gives no host route in either; and when one host
// goes, its host route goes and the one of the other VRF stays.
func TestIRBOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)

	e := testEVPN()
	e.Stretches = []EVPNStretch{
		{VNI: testStretchVNI, RouteTargets: []string{testStretchTarget}, IRB: true, VRF: 101, GatewayIPs: []string{"10.50.0.1/24"}},
		{VNI: testOverlapVNI, RouteTargets: []string{testOverlapTarget}, IRB: true, VRF: 102, GatewayIPs: []string{"10.50.0.1/24"}},
	}
	node := startNode(t, ctx)
	node.send(Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      int32(port),
		ListenAddresses: []string{"127.0.0.1"},
		Peers:           []Peer{{Address: "127.0.0.3", ASN: 65010, Passive: true}},
		EVPN:            e,
	})
	node.wait("ready", false, isType(TypeReady))
	fabric := startFabric(t, 65010, "192.0.2.10", "127.0.0.3", port)
	node.wait("the fabric established", true, isPeer("127.0.0.3", StateEstablished))

	// The gateway IP of each stretch, with the L3 VNI and the export route targets of its own VRF besides its own route target
	gateways := map[string]irbRoute{
		fmt.Sprintf("%d %s 10.50.0.1", testStretchVNI, DefaultRouterMAC): {labels: []uint32{testStretchVNI, 10101}, targets: []string{"65000:10101", testStretchTarget}},
		fmt.Sprintf("%d %s 10.50.0.1", testOverlapVNI, DefaultRouterMAC): {labels: []uint32{testOverlapVNI, 10102}, targets: []string{"192.0.2.1:102", "65000:10102", testOverlapTarget}},
	}
	waitUntil(t, "the fabric has the gateway IP of both stretches", func() bool { return len(fabric.irbRoutes()) == len(gateways) })
	for k, r := range fabric.irbRoutes() {
		want, ok := gateways[k]
		if !ok || !slices.Equal(r.labels, want.labels) || !slices.Equal(r.targets, want.targets) || r.mac != DefaultRouterMAC || !r.gateway {
			t.Errorf("a gateway IP at the fabric: %s %+v, want %+v", k, r, want)
		}
	}

	// A host of the fabric with the same address on each stretch, with the L3 VNI, the route target and the router MAC of the VRF
	// of its stretch; and a host on the stretch of VRF 101 whose route carries the route target of VRF 102
	red := fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10101}, testMAC(true, 1), "10.50.0.10", testFabricMAC, false, testStretchTarget, "65000:10101")
	fabric.announceIRB("192.0.2.10:5040", []uint32{testOverlapVNI, 10102}, testMAC(true, 2), "10.50.0.10", testFabricMAC2, false, testOverlapTarget, "65000:10102")
	fabric.announceIRB("192.0.2.10:5010", []uint32{testStretchVNI, 10102}, testMAC(true, 3), "10.50.0.30", testFabricMAC2, false, testStretchTarget, "65000:10102")

	for _, want := range []struct {
		vrf, vni uint32
		mac      string
	}{{101, 10101, testFabricMAC}, {102, 10102, testFabricMAC2}} {
		r := node.wait(fmt.Sprintf("the host route 10.50.0.10/32 in VRF %d", want.vrf), true, isEVPNRoute(TypeLearned, want.vrf, "10.50.0.10/32"))
		if r.NextHop != testFabricVTEP || r.VNI != want.vni || r.RouterMAC != want.mac || r.Peer != "127.0.0.3" {
			t.Errorf("the host route 10.50.0.10/32 in VRF %d: %+v", want.vrf, r)
		}
	}
	waitUntil(t, "the node learns the type-2 routes of the fabric on both stretches", func() bool { return len(node.learnedStretch()) == 3 })
	time.Sleep(settleTime)
	node.drain()
	for _, m := range node.seen {
		if m.Type != TypeLearned || m.VNI == 0 {
			continue
		}
		if m.Prefix != "10.50.0.10/32" || (m.VRF == 101 && (m.VNI != 10101 || m.RouterMAC != testFabricMAC)) || (m.VRF == 102 && (m.VNI != 10102 || m.RouterMAC != testFabricMAC2)) {
			t.Errorf("a host route that crosses from one VRF into the other: %+v", m)
		}
	}

	// The host of VRF 101 goes, and its host route with it; the one of VRF 102 stays
	seen := len(node.seen)
	fabric.withdraw(red)
	node.wait("the host route 10.50.0.10/32 of VRF 101 withdrawn", false, isEVPNRoute(TypeWithdrawn, 101, "10.50.0.10/32"))
	time.Sleep(settleTime)
	node.drain()
	if n := node.countFrom(seen, isEVPNRoute(TypeWithdrawn, 102, "10.50.0.10/32")); n != 0 {
		t.Errorf("the host route 10.50.0.10/32 of VRF 102 went %d times with the host of VRF 101", n)
	}
}
