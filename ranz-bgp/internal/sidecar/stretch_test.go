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

// The stretch of the tests (SDN-64 #291): the L2 VNI 5010 of one Network, whose route target the fabric router uses as well
const (
	testStretchVNI    = 5010
	testStretchTarget = "65000:5010"
	testFabricVTEP2   = "192.0.2.11"
)

func testStretchEVPN() *EVPN {
	return &EVPN{VTEP: testVTEP, Stretches: []EVPNStretch{{VNI: testStretchVNI, RouteTargets: []string{testStretchTarget}}}}
}

// The stretches of an evpn object are checked before BGP starts: their defaults, and each thing that they may not hold.
func TestParseStretches(t *testing.T) {
	routerID := netip.MustParseAddr("192.0.2.1")
	st, err := parseEVPN(testStretchEVPN(), routerID)
	if err != nil || len(st.vrfs) != 0 || st.stretch == nil {
		t.Fatalf("an evpn with a stretch and no VRF: %+v, %v", st, err)
	}
	v := st.stretch.byVNI[testStretchVNI]
	if v == nil || v.rd.String() != "192.0.2.1:5010" || !v.imports[testStretchTarget] || len(v.targets) != 1 {
		t.Fatalf("the stretch of VNI 5010: %+v", v)
	}
	if st, err := parseEVPN(testEVPN(), routerID); err != nil || st.stretch != nil {
		t.Errorf("an evpn without stretches: %+v, %v", st, err)
	}

	cases := []struct {
		name string
		edit func(e *EVPN)
		want string
	}{
		{"no vrfs and no stretches", func(e *EVPN) { e.Stretches = nil }, "no vrfs and no stretches"},
		{"a stretch without a VNI", func(e *EVPN) { e.Stretches[0].VNI = 0 }, "vni 0"},
		{"a VNI of 25 bits", func(e *EVPN) { e.Stretches[0].VNI = 0x1000000 }, "vni 16777216"},
		{"two stretches of one VNI", func(e *EVPN) { e.Stretches = append(e.Stretches, e.Stretches[0]) }, "comes twice"},
		{"the L3 VNI of a VRF", func(e *EVPN) { e.VRFs = testEVPN().VRFs; e.Stretches[0].VNI = 10101 }, "L3 VNI of vrf 101"},
		{"no route distinguisher for a large VNI", func(e *EVPN) { e.Stretches[0].VNI = 100000 }, "rd is missing"},
		{"a route distinguisher that is none", func(e *EVPN) { e.Stretches[0].RD = "rd-of-5010" }, "rd"},
		{"no route target", func(e *EVPN) { e.Stretches[0].RouteTargets = nil }, "route targets"},
		{"nine route targets", func(e *EVPN) {
			for i := range 8 {
				e.Stretches[0].RouteTargets = append(e.Stretches[0].RouteTargets, fmt.Sprintf("65000:%d", i))
			}
		}, "route targets"},
		{"a route target that is none", func(e *EVPN) { e.Stretches[0].RouteTargets = []string{"rt"} }, "route target"},
	}
	for _, c := range cases {
		e := testStretchEVPN()
		c.edit(e)
		if st, err := parseEVPN(e, routerID); err == nil || st != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %+v, %v; want an error that says %q", c.name, st, err, c.want)
		}
	}
}

// path is a path of the fabric router: its NLRI, its next hop, its route targets, the VXLAN encapsulation, and the
// attributes extra
func (f *testFabric) path(nlri bgp.NLRI, nextHop string, targets []string, extra ...bgp.PathAttributeInterface) *apiutil.Path {
	f.t.Helper()
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nextHop))
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
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), reach, bgp.NewPathAttributeExtendedCommunities(ecs)}
	return &apiutil.Path{Family: bgp.RF_EVPN, Nlri: nlri, Attrs: append(attrs, extra...), Age: time.Now().Unix()}
}

// add announces a path of the fabric router, and returns its UUID for withdraw
func (f *testFabric) add(p *apiutil.Path) uuid.UUID {
	f.t.Helper()
	resp, err := f.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{p}})
	if err != nil {
		f.t.Fatalf("fabric announces %s: %v", p.Nlri, err)
	}
	return resp[0].UUID
}

// announceMAC announces the type-2 route of mac, and of ip in the MAC plus IP form ("" for MAC only), on vni behind the VTEP
// vtep, under the route distinguisher rd
func (f *testFabric) announceMAC(rd string, vni uint32, mac, ip, vtep string, targets ...string) uuid.UUID {
	f.t.Helper()
	d, err := bgp.ParseRouteDistinguisher(rd)
	if err != nil {
		f.t.Fatal(err)
	}
	var addr netip.Addr
	if ip != "" {
		addr = netip.MustParseAddr(ip)
	}
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(d, bgp.EthernetSegmentIdentifier{}, 0, mac, addr, []uint32{vni})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.add(f.path(nlri, vtep, targets))
}

// announceIMET announces the type-3 route of the VTEP vtep on vni under the route distinguisher rd, with a PMSI tunnel of
// ingress replication whose label is vni, or with none
func (f *testFabric) announceIMET(rd string, vni uint32, vtep string, pmsi bool, targets ...string) uuid.UUID {
	f.t.Helper()
	d, err := bgp.ParseRouteDistinguisher(rd)
	if err != nil {
		f.t.Fatal(err)
	}
	nlri, err := bgp.NewEVPNMulticastEthernetTagRoute(d, 0, netip.MustParseAddr(vtep))
	if err != nil {
		f.t.Fatal(err)
	}
	var extra []bgp.PathAttributeInterface
	if pmsi {
		id, err := bgp.NewIngressReplTunnelID(netip.MustParseAddr(vtep))
		if err != nil {
			f.t.Fatal(err)
		}
		extra = append(extra, bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, vni, id))
	}
	return f.add(f.path(nlri, vtep, targets, extra...))
}

// gatewayStretchRoute is a type-2 or type-3 route of the gateway as the fabric router has it
type gatewayStretchRoute struct {
	rd, nextHop, tunnel string
	label               uint32
	targets             []string
	vxlan               bool
}

// stretchRoutes are the type-2 and type-3 routes that the fabric router has from the gateway: "mac <mac> <ip>" and "imet
// <vtep>", by their text
func (f *testFabric) stretchRoutes() map[string]gatewayStretchRoute {
	f.t.Helper()
	out := make(map[string]gatewayStretchRoute)
	err := f.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_EVPN}, func(n bgp.NLRI, paths []*apiutil.Path) {
		e, ok := n.(*bgp.EVPNNLRI)
		if !ok {
			return
		}
		for _, p := range paths {
			if !p.PeerAddress.IsValid() {
				continue
			}
			targets, encap, pmsi := targetsOf(p)
			g := gatewayStretchRoute{nextHop: pathNextHop(p).String(), targets: slices.Sorted(slices.Values(targets)), vxlan: encap == bgp.TUNNEL_TYPE_VXLAN}
			switch r := e.RouteTypeData.(type) {
			case *bgp.EVPNMacIPAdvertisementRoute:
				g.rd = r.RD.String()
				if len(r.Labels) != 0 {
					g.label = r.Labels[0]
				}
				ip := ""
				if r.IPAddressLength != 0 {
					ip = r.IPAddress.String()
				}
				out["mac "+r.MacAddress.String()+" "+ip] = g
			case *bgp.EVPNMulticastEthernetTagRoute:
				g.rd = r.RD.String()
				if pmsi != nil {
					g.label, g.tunnel = pmsi.Label, pmsi.TunnelID.String()
				}
				out["imet "+r.IPAddress.String()] = g
			}
		}
	})
	if err != nil {
		f.t.Fatalf("fabric RIB: %v", err)
	}
	return out
}

// learnedStretch applies the stretch messages of the sidecar seen so far, in order: the routes of the fabric that the node
// holds, "<vni> <mac> <ip>" for a type-2 route and "<vni> vtep <vtep>" for a type-3 route, with their VTEP. It fails the test
// for a stretch message of more than MaxStretchRoutes routes.
func (n *testNode) learnedStretch() map[string]string {
	n.t.Helper()
	n.drain()
	out := make(map[string]string)
	for _, m := range n.seen {
		if m.Type != TypeStretch {
			continue
		}
		if len(m.Routes) == 0 || len(m.Routes) > MaxStretchRoutes {
			n.t.Fatalf("a stretch message of %d routes", len(m.Routes))
		}
		for _, r := range m.Routes {
			k := fmt.Sprintf("%d %s %s", r.VNI, r.MAC, r.IP)
			if r.MAC == "" {
				k = fmt.Sprintf("%d vtep %s", r.VNI, r.NextHop)
			}
			if r.Withdraw {
				delete(out, k)
			} else {
				out[k] = r.NextHop
			}
		}
	}
	return out
}

// testMAC is the MAC address i of a host of the tests, behind the gateway (02:52:5a:..) or in the fabric (02:00:5e:..)
func testMAC(fabric bool, i int) string {
	if fabric {
		return fmt.Sprintf("02:00:5e:50:%02x:%02x", i>>8&0xFF, i&0xFF)
	}
	return fmt.Sprintf("02:52:5a:64:%02x:%02x", i>>8&0xFF, i&0xFF)
}

// resync sends the routes in the stretch messages of a full resync, MaxStretchRoutes routes in each; their number
func (n *testNode) resync(routes []StretchRoute) int {
	n.t.Helper()
	num := 0
	for first := true; first || len(routes) != 0; first = false {
		c := min(len(routes), MaxStretchRoutes)
		n.send(Message{Type: TypeStretch, Full: first, More: c < len(routes), Routes: routes[:c]})
		routes = routes[c:]
		num++
	}
	return num
}

// The stretch of a gateway against a fabric router: the type-3 route of the gateway reaches the fabric with a PMSI tunnel of
// ingress replication to its VTEP, labelled with the L2 VNI; the type-2 routes of a full resync of 1,200 routes in three
// messages reach it, MAC only and MAC plus IP, each with the route distinguisher, the route target and the VNI of the
// stretch and the VTEP of the gateway as next hop; a delta withdraws one and adds one, and a second full resync withdraws
// what it does not name. The type-3 routes of two VTEPs of the fabric and its type-2 routes come to the node with their
// VTEP, 1,200 of them in messages of 500 routes at most; a MAC that moves to the other VTEP is one learned route; and the
// routes that the gateway leaves out do not come. What cannot be applied is answered with an error, and the session goes on.
func TestStretch(t *testing.T) {
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
		EVPN:            testStretchEVPN(),
	})
	node.wait("ready", false, isType(TypeReady))
	fabric := startFabric(t, 65010, "192.0.2.10", "127.0.0.3", port)
	node.wait("the fabric established", true, isPeer("127.0.0.3", StateEstablished))

	// The type-3 route of the gateway
	waitUntil(t, "the fabric has the type-3 route of the gateway", func() bool { _, ok := fabric.stretchRoutes()["imet "+testVTEP]; return ok })
	imet := fabric.stretchRoutes()["imet "+testVTEP]
	if imet.rd != "192.0.2.1:5010" || imet.label != testStretchVNI || imet.tunnel != testVTEP || imet.nextHop != testVTEP || !imet.vxlan ||
		!slices.Equal(imet.targets, []string{testStretchTarget}) {
		t.Errorf("the type-3 route of the gateway at the fabric: %+v", imet)
	}

	// A full resync of 600 MAC addresses, each MAC only and with an IPv4 address: 1,200 routes in three messages
	var routes []StretchRoute
	for i := range 600 {
		routes = append(routes, StretchRoute{VNI: testStretchVNI, MAC: testMAC(false, i)},
			StretchRoute{VNI: testStretchVNI, MAC: testMAC(false, i), IP: fmt.Sprintf("10.50.%d.%d", i/250, i%250+1)})
	}
	if c := node.resync(routes); c != 3 {
		t.Fatalf("a full resync of 1,200 routes went in %d messages", c)
	}
	waitUntil(t, "the fabric has the 1,200 type-2 routes of the gateway", func() bool { return len(fabric.stretchRoutes()) == 1+1200 })
	got := fabric.stretchRoutes()
	only, both := got["mac "+testMAC(false, 0)+" "], got["mac "+testMAC(false, 599)+" 10.50.2.100"]
	for _, r := range []gatewayStretchRoute{only, both} {
		if r.rd != "192.0.2.1:5010" || r.label != testStretchVNI || r.nextHop != testVTEP || !r.vxlan || !slices.Equal(r.targets, []string{testStretchTarget}) {
			t.Errorf("a type-2 route of the gateway at the fabric: %+v", r)
		}
	}

	// A delta: one MAC plus IP goes, one MAC with an IPv6 address comes
	node.send(Message{Type: TypeStretch, Routes: []StretchRoute{
		{VNI: testStretchVNI, MAC: testMAC(false, 0), IP: "10.50.0.1", Withdraw: true},
		{VNI: testStretchVNI, MAC: testMAC(false, 1000), IP: "fd50::1000"},
	}})
	waitUntil(t, "the fabric loses one route and gets another", func() bool {
		r := fabric.stretchRoutes()
		_, gone := r["mac "+testMAC(false, 0)+" 10.50.0.1"]
		_, came := r["mac "+testMAC(false, 1000)+" fd50::1000"]
		return !gone && came && len(r) == 1+1200
	})

	// A second full resync of the first 100 routes of the first resync: the fabric keeps them and loses every other
	node.resync(routes[:100])
	waitUntil(t, "the fabric has the 100 routes of the second resync", func() bool { return len(fabric.stretchRoutes()) == 1+100 })
	got = fabric.stretchRoutes()
	if _, ok := got["mac "+testMAC(false, 0)+" 10.50.0.1"]; !ok {
		t.Error("the second resync names the route that the delta withdrew, and the fabric does not have it again")
	}
	if _, ok := got["imet "+testVTEP]; !ok {
		t.Error("a full resync of the type-2 routes withdrew the type-3 route of the gateway")
	}

	// The fabric: the type-3 routes of two VTEPs, a MAC only and a MAC plus IP route, and the routes that the gateway leaves
	// out: a route target of no stretch, another VNI, a type-3 route without a PMSI tunnel
	fabric.announceIMET("192.0.2.10:5010", testStretchVNI, testFabricVTEP, true, testStretchTarget)
	fabric.announceIMET("192.0.2.11:5010", testStretchVNI, testFabricVTEP2, true, testStretchTarget)
	inA := fabric.announceMAC("192.0.2.10:5010", testStretchVNI, testMAC(true, 1), "", testFabricVTEP, testStretchTarget)
	fabric.announceMAC("192.0.2.10:5010", testStretchVNI, testMAC(true, 1), "10.50.9.1", testFabricVTEP, testStretchTarget)
	fabric.announceMAC("192.0.2.10:6010", 6010, testMAC(true, 2), "", testFabricVTEP, "65000:6010")
	fabric.announceMAC("192.0.2.10:5010", 6010, testMAC(true, 3), "", testFabricVTEP, testStretchTarget)
	fabric.announceIMET("192.0.2.12:5010", testStretchVNI, "192.0.2.12", false, testStretchTarget)
	want := map[string]string{
		"5010 vtep " + testFabricVTEP:             testFabricVTEP,
		"5010 vtep " + testFabricVTEP2:            testFabricVTEP2,
		"5010 " + testMAC(true, 1) + " ":          testFabricVTEP,
		"5010 " + testMAC(true, 1) + " 10.50.9.1": testFabricVTEP,
	}
	waitUntil(t, "the node learns the type-3 routes of two VTEPs and two type-2 routes", func() bool { return len(node.learnedStretch()) >= len(want) })
	time.Sleep(settleTime)
	if l := node.learnedStretch(); !sameRoutes(l, want) {
		t.Errorf("the routes of the fabric at the node: %v, want %v", l, want)
	}

	// A MAC that moves to the other VTEP is one learned route, without a withdraw between
	fabric.announceMAC("192.0.2.11:5010", testStretchVNI, testMAC(true, 1), "", testFabricVTEP2, testStretchTarget)
	waitUntil(t, "the sidecar has the route of the second VTEP", func() bool { return node.hasEVPN(8) })
	before := len(node.seen)
	fabric.withdraw(inA)
	waitUntil(t, "the MAC moves to the second VTEP", func() bool { return node.learnedStretch()["5010 "+testMAC(true, 1)+" "] == testFabricVTEP2 })
	for _, m := range node.seen[before:] {
		for _, r := range m.Routes {
			if r.Withdraw && r.MAC == testMAC(true, 1) && r.IP == "" {
				t.Errorf("the MAC moved with a withdraw between: %+v", r)
			}
		}
	}

	// 1,200 more MAC addresses of the fabric come in messages of 500 routes at most
	for i := range 1200 {
		fabric.announceMAC("192.0.2.10:5010", testStretchVNI, testMAC(true, 100+i), "", testFabricVTEP, testStretchTarget)
	}
	waitUntil(t, "the node learns the 1,200 MAC addresses", func() bool { return len(node.learnedStretch()) == len(want)+1200 })

	// What cannot be applied is answered with an error; the session goes on
	big := make([]StretchRoute, MaxStretchRoutes+1)
	for i := range big {
		big[i] = StretchRoute{VNI: testStretchVNI, MAC: testMAC(false, 2000+i)}
	}
	refused := [][]StretchRoute{
		{{VNI: 6010, MAC: testMAC(false, 1)}},
		{{VNI: testStretchVNI, MAC: "01:00:5e:00:00:01"}},
		{{VNI: testStretchVNI, MAC: testMAC(false, 1), NextHop: testVTEP}},
		{{VNI: testStretchVNI, MAC: testMAC(false, 1), IP: "224.0.0.1"}},
		{{VNI: testStretchVNI}},
		big,
	}
	for _, r := range refused {
		node.send(Message{Type: TypeStretch, Routes: r})
		if e := node.wait("an error for a stretch message", false, isType(TypeError)); !strings.Contains(e.Error, "stretch") {
			t.Errorf("error for %+v: %+v", r[0], e)
		}
	}
	time.Sleep(settleTime)
	if n := len(fabric.stretchRoutes()); n != 1+100 {
		t.Errorf("the fabric has %d routes of the gateway after the refused messages, not 101", n)
	}
}

// sameRoutes reports whether two sets of routes of learnedStretch hold the same
func sameRoutes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// After the pipe to the sidecar closed, a new session learns the same routes of the fabric again, and the full resync of the
// node gives the fabric the same routes of the gateway again: the node resyncs fully, and the MAC addresses match.
func TestStretchResync(t *testing.T) {
	port := freePort(t)
	start := Message{
		Type:            TypeStart,
		ASN:             65001,
		RouterID:        "192.0.2.1",
		ListenPort:      int32(port),
		ListenAddresses: []string{"127.0.0.1"},
		Peers:           []Peer{{Address: "127.0.0.3", ASN: 65010, Passive: true}},
		EVPN:            testStretchEVPN(),
	}
	var routes []StretchRoute
	for i := range 700 {
		routes = append(routes, StretchRoute{VNI: testStretchVNI, MAC: testMAC(false, i), IP: fmt.Sprintf("fd50::%x", i+1)})
	}

	// The first session: the fabric announces its routes, and the node its own
	ctx, cancel := context.WithCancel(context.Background())
	node := startNode(t, ctx)
	node.send(start)
	node.wait("ready", false, isType(TypeReady))
	fabric := startFabric(t, 65010, "192.0.2.10", "127.0.0.3", port)
	node.wait("the fabric established", true, isPeer("127.0.0.3", StateEstablished))
	fabric.announceIMET("192.0.2.10:5010", testStretchVNI, testFabricVTEP, true, testStretchTarget)
	for i := range 600 {
		fabric.announceMAC("192.0.2.10:5010", testStretchVNI, testMAC(true, i), fmt.Sprintf("10.50.%d.%d", i/250, i%250+1), testFabricVTEP, testStretchTarget)
	}
	node.resync(routes)
	waitUntil(t, "the node learns the routes of the fabric", func() bool { return len(node.learnedStretch()) == 1+600 })
	waitUntil(t, "the fabric has the routes of the gateway", func() bool { return len(fabric.stretchRoutes()) == 1+700 })
	learned, announced := node.learnedStretch(), fabric.stretchRoutes()

	// The pipe closes: the session ends, and BGP with it
	node.conn.Close()
	select {
	case <-node.done:
	case <-time.After(waitTimeout):
		t.Fatal("the session did not end when the pipe closed")
	}
	cancel()
	waitUntil(t, "the fabric loses the routes of the gateway", func() bool { return len(fabric.stretchRoutes()) == 0 })

	// The next session: the same start and a full resync of the node
	again := startNode(t, context.Background())
	again.send(start)
	again.wait("ready", false, isType(TypeReady))
	again.wait("the fabric established again", true, isPeer("127.0.0.3", StateEstablished))
	if c := again.resync(routes); c != 2 {
		t.Errorf("a full resync of 700 routes went in %d messages", c)
	}
	waitUntil(t, "the node learns the routes of the fabric again", func() bool { return len(again.learnedStretch()) == len(learned) })
	waitUntil(t, "the fabric has the routes of the gateway again", func() bool { return len(fabric.stretchRoutes()) == len(announced) })
	if l := again.learnedStretch(); !sameRoutes(l, learned) {
		t.Errorf("the MAC addresses that the node learned again do not match: %d, before %d", len(l), len(learned))
	}
	now := fabric.stretchRoutes()
	for k, r := range announced {
		if n, ok := now[k]; !ok || n.nextHop != r.nextHop || n.label != r.label || n.rd != r.rd {
			t.Errorf("the route %s of the gateway at the fabric after the resync: %+v, before %+v", k, n, r)
		}
	}
}
