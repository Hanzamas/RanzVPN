package sidecar

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// The EVPN of a gateway in the tests: VRFs 101 and 102 hand over the same prefixes, each on its own L3 VNI and route
// target, which the fabric router uses as well
const (
	testVTEP       = "192.0.2.1"
	testFabricVTEP = "192.0.2.10"
	testFabricMAC  = "02:00:5e:10:00:01"
	testFabricMAC2 = "02:00:5e:10:00:02"
)

func testEVPN() *EVPN {
	return &EVPN{
		VTEP: testVTEP,
		VRFs: []EVPNVRF{
			{VRF: 101, VNI: 10101, Import: []string{"65000:10101"}, Export: []string{"65000:10101"}, Accept: []string{"172.16.0.0/12", "2001:db8:16::/48"}},
			{VRF: 102, VNI: 10102, RD: "65000:102", Import: []string{"65000:10102"}, Export: []string{"65000:10102", "192.0.2.1:102"}, Accept: []string{"172.16.0.0/12"}},
		},
	}
}

// An evpn object is checked before BGP starts: its defaults, and each thing that it may not hold.
func TestParseEVPN(t *testing.T) {
	routerID := netip.MustParseAddr("192.0.2.1")
	if st, err := parseEVPN(nil, routerID); st != nil || err != nil {
		t.Fatalf("a start without evpn: %+v, %v", st, err)
	}

	st, err := parseEVPN(testEVPN(), routerID)
	if err != nil {
		t.Fatal(err)
	}
	if st.vtep.String() != testVTEP || st.mac != DefaultRouterMAC || len(st.vrfs) != 2 || !st.has(101) || !st.has(102) || st.has(103) || st.has(0) {
		t.Fatalf("the evpn of the tests: %+v", st)
	}
	if a, b := st.byID[101], st.byID[102]; a.rd.String() != "192.0.2.1:101" || b.rd.String() != "65000:102" || a.vni != 10101 || !a.imports["65000:10101"] ||
		len(b.exports) != 2 || b.exports[1].String() != "192.0.2.1:102" || len(a.accept) != 2 {
		t.Errorf("the VRFs: %+v, %+v", a, b)
	}
	var none *evpnState
	if none.has(101) {
		t.Error("a session without EVPN has an EVPN VRF")
	}

	// An IPv6 VTEP, a router MAC of its own, a route distinguisher of a 32-bit ASN and route targets of each form
	six := &EVPN{VTEP: "2001:db8::1", RouterMAC: "02-52-5A-00-00-09", VRFs: []EVPNVRF{
		{VRF: 70000, VNI: 0xFFFFFF, RD: "1.2:7", Import: []string{"1.2:7", "192.0.2.9:7"}, Export: []string{"64086.59904:7"}},
	}}
	if st, err := parseEVPN(six, routerID); err != nil || st.vtep.String() != "2001:db8::1" || st.mac != "02:52:5a:00:00:09" || !st.byID[70000].imports["192.0.2.9:7"] {
		t.Errorf("an IPv6 VTEP with a router MAC of its own: %+v, %v", st, err)
	}

	cases := []struct {
		name string
		edit func(e *EVPN)
		want string
	}{
		{"no vtep", func(e *EVPN) { e.VTEP = "" }, "vtep"},
		{"a vtep that is no address", func(e *EVPN) { e.VTEP = "gateway" }, "vtep"},
		{"the unspecified vtep", func(e *EVPN) { e.VTEP = "0.0.0.0" }, "vtep"},
		{"a vtep with a zone", func(e *EVPN) { e.VTEP = "fe80::1%eth0" }, "vtep"},
		{"a multicast router MAC", func(e *EVPN) { e.RouterMAC = "01:00:5e:00:00:01" }, "router_mac"},
		{"a router MAC that is none", func(e *EVPN) { e.RouterMAC = "02:52:5a" }, "router_mac"},
		{"a router MAC of 8 bytes", func(e *EVPN) { e.RouterMAC = "02:52:5a:00:00:05:00:01" }, "router_mac"},
		{"no vrfs", func(e *EVPN) { e.VRFs = nil }, "no vrfs"},
		{"a VRF without an id", func(e *EVPN) { e.VRFs[0].VRF = 0 }, "VRF id is missing"},
		{"a VRF without a VNI", func(e *EVPN) { e.VRFs[0].VNI = 0 }, "vni 0"},
		{"a VNI of 25 bits", func(e *EVPN) { e.VRFs[0].VNI = 0x1000000 }, "vni 16777216"},
		{"two VRFs of one id", func(e *EVPN) { e.VRFs[1].VRF = 101 }, "vrf 101 comes twice"},
		{"two VRFs of one VNI", func(e *EVPN) { e.VRFs[1].VNI = 10101 }, "is the VNI of vrf 101"},
		{"a route distinguisher that is none", func(e *EVPN) { e.VRFs[0].RD = "rd-of-101" }, "rd"},
		{"a route distinguisher that does not fit", func(e *EVPN) { e.VRFs[0].RD = "192.0.2.1:70000" }, "rd"},
		{"no route distinguisher for a large VRF id", func(e *EVPN) { e.VRFs[0].VRF = 70000 }, "rd is missing"},
		{"no import route target", func(e *EVPN) { e.VRFs[0].Import = nil }, "import and export"},
		{"no export route target", func(e *EVPN) { e.VRFs[0].Export = nil }, "import and export"},
		{"an import route target that is none", func(e *EVPN) { e.VRFs[0].Import = []string{"rt"} }, "import"},
		{"an export route target that does not fit", func(e *EVPN) { e.VRFs[0].Export = []string{"65000:4294967296"} }, "export"},
		{"an accept that is no prefix", func(e *EVPN) { e.VRFs[0].Accept = []string{"172.16.0.1/12"} }, "accept"},
	}
	for _, c := range cases {
		e := testEVPN()
		c.edit(e)
		if st, err := parseEVPN(e, routerID); err == nil || st != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %+v, %v; want an error that says %q", c.name, st, err, c.want)
		}
	}
}

// testFabric is a router of a data-centre fabric: GoBGP in the test, with IPv4 unicast and L2VPN EVPN, which connects to
// the sidecar
type testFabric struct {
	t   *testing.T
	bgp *server.BgpServer
}

// startFabric starts the fabric router AS asn, which connects from the address local to the sidecar's AS 65001 on
// 127.0.0.1:port.
func startFabric(t *testing.T, asn uint32, routerID, local string, port int) *testFabric {
	t.Helper()
	b := server.NewBgpServer(server.LoggerOption(testLogger(), nil))
	go b.Serve()
	ctx := context.Background()
	if err := b.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: asn, RouterId: routerID, ListenPort: -1}}); err != nil {
		t.Fatalf("fabric %s: %v", routerID, err)
	}
	t.Cleanup(b.Stop)
	err := b.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{LocalAddress: local, RemotePort: uint32(port)},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis:  []*api.AfiSafi{unicast(api.Family_AFI_IP), {Config: &api.AfiSafiConfig{Family: evpnFamily(), Enabled: true}}},
	}})
	if err != nil {
		t.Fatalf("fabric %s: peer: %v", routerID, err)
	}
	return &testFabric{t: t, bgp: b}
}

// fabricRoute is an IP prefix route that the fabric router announces
type fabricRoute struct {
	rd, prefix, nextHop, mac, gateway string
	label                             uint32
	targets                           []string
	encap                             bgp.TunnelType // VXLAN when 0
}

// announce announces r, and returns its UUID for withdraw
func (f *testFabric) announce(r fabricRoute) uuid.UUID {
	f.t.Helper()
	rd, err := bgp.ParseRouteDistinguisher(r.rd)
	if err != nil {
		f.t.Fatal(err)
	}
	p := netip.MustParsePrefix(r.prefix)
	gw := netip.IPv4Unspecified()
	if r.gateway != "" {
		gw = netip.MustParseAddr(r.gateway)
	}
	nlri, err := bgp.NewEVPNIPPrefixRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, uint8(p.Bits()), p.Addr(), gw, r.label)
	if err != nil {
		f.t.Fatal(err)
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(r.nextHop))
	if err != nil {
		f.t.Fatal(err)
	}
	var ecs []bgp.ExtendedCommunityInterface
	for _, rt := range r.targets {
		ec, err := bgp.ParseRouteTarget(rt)
		if err != nil {
			f.t.Fatal(err)
		}
		ecs = append(ecs, ec)
	}
	encap := r.encap
	if encap == 0 {
		encap = bgp.TUNNEL_TYPE_VXLAN
	}
	ecs = append(ecs, bgp.NewEncapExtended(encap))
	if r.mac != "" {
		ecs = append(ecs, bgp.NewRoutersMacExtended(r.mac))
	}
	resp, err := f.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: bgp.RF_EVPN,
		Nlri:   nlri,
		Attrs:  []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), reach, bgp.NewPathAttributeExtendedCommunities(ecs)},
		Age:    time.Now().Unix(),
	}}})
	if err != nil {
		f.t.Fatalf("fabric announces %s: %v", r.prefix, err)
	}
	return resp[0].UUID
}

// withdraw withdraws an announced route
func (f *testFabric) withdraw(id uuid.UUID) {
	f.t.Helper()
	if err := f.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		f.t.Fatalf("fabric withdraws: %v", err)
	}
}

// gatewayRoute is an IP prefix route of the gateway as the fabric router has it
type gatewayRoute struct {
	rd, nextHop, mac string
	label            uint32
	targets          []string
	vxlan            bool
}

// routes are the IP prefix routes that the fabric router has from the gateway, by prefix and route distinguisher
func (f *testFabric) routes() map[string]gatewayRoute {
	f.t.Helper()
	out := make(map[string]gatewayRoute)
	err := f.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_EVPN}, func(n bgp.NLRI, paths []*apiutil.Path) {
		e, ok := n.(*bgp.EVPNNLRI)
		if !ok {
			return
		}
		r, ok := e.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
		if !ok {
			return
		}
		for _, p := range paths {
			if !p.PeerAddress.IsValid() {
				continue
			}
			g := gatewayRoute{rd: r.RD.String(), nextHop: pathNextHop(p).String(), label: r.Label, targets: slices.Sorted(slices.Values(routeTargets(p.Attrs)))}
			for _, a := range p.Attrs {
				if ecs, ok := a.(*bgp.PathAttributeExtendedCommunities); ok {
					for _, c := range ecs.Value {
						switch c := c.(type) {
						case *bgp.RouterMacExtended:
							g.mac = c.Mac.String()
						case *bgp.EncapExtended:
							g.vxlan = c.TunnelType == bgp.TUNNEL_TYPE_VXLAN
						}
					}
				}
			}
			out[netip.PrefixFrom(r.IPPrefix, int(r.IPPrefixLength)).String()+" "+g.rd] = g
		}
	})
	if err != nil {
		f.t.Fatalf("fabric RIB: %v", err)
	}
	return out
}

func isEVPNRoute(typ string, vrf uint32, prefix string) func(Message) bool {
	return func(m Message) bool { return m.Type == typ && m.VRF == vrf && m.Prefix == prefix }
}

// A gateway with two VRFs that use the same prefixes, and a fabric router: the IP prefix routes of each VRF reach the
// fabric with the route distinguisher, the route targets, the L3 VNI and the router MAC of the VRF and the VTEP of the
// gateway as the next hop, and leave it again; the routes of the fabric come to the node in the VRFs whose route targets
// they carry, with their VNI, router MAC and VTEP, and the ones that the gateway does not take do not come at all; a
// prefix offered under two route distinguishers moves from one to the other without a withdrawn message, and goes with
// the last one; what cannot be applied is answered with an error, and the session goes on.
func TestEVPN(t *testing.T) {
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
		Accept:          []string{"198.51.100.0/24"},
		EVPN:            testEVPN(),
	})
	node.wait("ready", false, isType(TypeReady))
	fabric := startFabric(t, 65010, "192.0.2.10", "127.0.0.3", port)
	node.wait("the fabric established", true, isPeer("127.0.0.3", StateEstablished))

	// The prefixes of the two VRFs, which overlap, reach the fabric as two routes
	node.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "10.10.0.0/24"})
	node.send(Message{Type: TypeAnnounce, VRF: 102, Prefix: "10.10.0.0/24"})
	node.send(Message{Type: TypeAnnounce, VRF: 101, Prefix: "2001:db8:10::/64"})
	waitUntil(t, "the fabric has the routes of both VRFs", func() bool { return len(fabric.routes()) == 3 })
	routes := fabric.routes()
	a, b, six := routes["10.10.0.0/24 192.0.2.1:101"], routes["10.10.0.0/24 65000:102"], routes["2001:db8:10::/64 192.0.2.1:101"]
	if a.label != 10101 || a.nextHop != testVTEP || a.mac != DefaultRouterMAC || !a.vxlan || !slices.Equal(a.targets, []string{"65000:10101"}) {
		t.Errorf("the route of VRF 101 at the fabric: %+v", a)
	}
	if b.label != 10102 || b.nextHop != testVTEP || b.mac != DefaultRouterMAC || !b.vxlan || !slices.Equal(b.targets, []string{"192.0.2.1:102", "65000:10102"}) {
		t.Errorf("the route of VRF 102 at the fabric: %+v", b)
	}
	if six.label != 10101 || six.nextHop != testVTEP || six.mac != DefaultRouterMAC {
		t.Errorf("the IPv6 route of VRF 101 at the fabric: %+v", six)
	}

	// The routes of the fabric in its two VRFs, which overlap too
	inA := fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "172.16.1.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, label: 10101, targets: []string{"65000:10101"}})
	fabric.announce(fabricRoute{rd: "192.0.2.10:2", prefix: "172.16.1.0/24", nextHop: testFabricVTEP, mac: testFabricMAC2, label: 10102, targets: []string{"65000:10102"}})
	la := node.wait("learned 172.16.1.0/24 in VRF 101", true, isEVPNRoute(TypeLearned, 101, "172.16.1.0/24"))
	lb := node.wait("learned 172.16.1.0/24 in VRF 102", true, isEVPNRoute(TypeLearned, 102, "172.16.1.0/24"))
	if la.NextHop != testFabricVTEP || la.VNI != 10101 || la.RouterMAC != testFabricMAC || la.Peer != "127.0.0.3" || !slices.Equal(la.VTEPs, []string{testFabricVTEP}) {
		t.Errorf("learned in VRF 101: %+v", la)
	}
	if lb.NextHop != testFabricVTEP || lb.VNI != 10102 || lb.RouterMAC != testFabricMAC2 || lb.Peer != "127.0.0.3" || !slices.Equal(lb.VTEPs, []string{testFabricVTEP}) {
		t.Errorf("learned in VRF 102: %+v", lb)
	}

	// Routes that the gateway does not take: a route target of no VRF, a prefix outside accept, no router MAC, a gateway
	// IP, another encapsulation; then a route of VRF 101 that it takes, which comes after them
	fabric.announce(fabricRoute{rd: "192.0.2.10:3", prefix: "172.16.3.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, label: 10103, targets: []string{"65000:10103"}})
	fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "198.51.100.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, label: 10101, targets: []string{"65000:10101"}})
	fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "172.16.4.0/24", nextHop: testFabricVTEP, label: 10101, targets: []string{"65000:10101"}})
	fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "172.16.5.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, gateway: "172.16.5.1", label: 10101, targets: []string{"65000:10101"}})
	fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "172.16.6.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, label: 10101, targets: []string{"65000:10101"}, encap: bgp.TUNNEL_TYPE_MPLS})
	// The global RIB of the sidecar holds every IP prefix route of the fabric, also the ones that the gateway does not take:
	// the seven so far
	waitUntil(t, "the sidecar has the routes of the fabric", func() bool { return node.hasEVPN(7) })
	fabric.announce(fabricRoute{rd: "192.0.2.10:1", prefix: "172.16.7.0/24", nextHop: testFabricVTEP, mac: testFabricMAC, label: 10101, targets: []string{"65000:10101"}})
	node.wait("learned 172.16.7.0/24 in VRF 101", false, isEVPNRoute(TypeLearned, 101, "172.16.7.0/24"))
	time.Sleep(settleTime)
	node.drain()
	for _, p := range []string{"172.16.3.0/24", "198.51.100.0/24", "172.16.4.0/24", "172.16.5.0/24", "172.16.6.0/24"} {
		if c := node.count(func(m Message) bool { return m.Type == TypeLearned && m.Prefix == p }); c != 0 {
			t.Errorf("the gateway does not take %s, but the node learned it %d times", p, c)
		}
	}

	// A second leaf offers 172.16.1.0/24 of VRF 101 under its own route distinguisher, and has no prefix of its own in the
	// VRF: the node keeps its route, and the learned message names the VTEP of the second leaf beside the next hop, so that
	// the node takes the frames of the second leaf too; when the second leaf withdraws its route, the message names the next
	// hop alone again (SDN-25-R3 #571). Then the route moves to the second leaf when the first withdraws it, without a
	// withdrawn message between. The withdraw waits until the sidecar has the ninth route, the one of the second leaf: else
	// the fabric router may send the withdraw first, and the prefix of VRF 101 is rightly withdrawn and learned again.
	second := fabricRoute{rd: "192.0.2.11:1", prefix: "172.16.1.0/24", nextHop: "192.0.2.11", mac: testFabricMAC2, label: 10101, targets: []string{"65000:10101"}}
	both := []string{testFabricVTEP, "192.0.2.11"}
	withVTEPs := func(vteps []string) func(Message) bool {
		return func(m Message) bool {
			return isEVPNRoute(TypeLearned, 101, "172.16.1.0/24")(m) && slices.Equal(m.VTEPs, vteps)
		}
	}
	inA2 := fabric.announce(second)
	if m := node.wait("172.16.1.0/24 of VRF 101 with the VTEP of the second leaf", false, withVTEPs(both)); m.NextHop != testFabricVTEP || m.RouterMAC != testFabricMAC {
		t.Errorf("the second leaf took the route of 172.16.1.0/24 of VRF 101, which should stay via the first: %+v", m)
	}
	fabric.withdraw(inA2)
	if m := node.wait("172.16.1.0/24 of VRF 101 without the VTEP of the second leaf", false, withVTEPs([]string{testFabricVTEP})); m.NextHop != testFabricVTEP {
		t.Errorf("172.16.1.0/24 of VRF 101 after the second leaf withdrew its route: %+v", m)
	}
	inA2 = fabric.announce(second)
	node.wait("172.16.1.0/24 of VRF 101 with the VTEP of the second leaf again", false, withVTEPs(both))
	waitUntil(t, "the sidecar has the route of the second leaf", func() bool { return node.hasEVPN(9) })
	fabric.withdraw(inA)
	moved := node.wait("172.16.1.0/24 of VRF 101 via the second leaf", false, isEVPNRoute(TypeLearned, 101, "172.16.1.0/24"))
	if moved.NextHop != "192.0.2.11" || moved.RouterMAC != testFabricMAC2 || !slices.Equal(moved.VTEPs, []string{"192.0.2.11"}) {
		t.Errorf("172.16.1.0/24 of VRF 101 via the second leaf: %+v", moved)
	}
	if c := node.count(isEVPNRoute(TypeWithdrawn, 101, "172.16.1.0/24")); c != 0 {
		t.Errorf("the route moved to the second leaf with %d withdrawn messages between", c)
	}
	fabric.withdraw(inA2)
	w := node.wait("withdrawn 172.16.1.0/24 of VRF 101", false, isEVPNRoute(TypeWithdrawn, 101, "172.16.1.0/24"))
	if w.VNI != 10101 || w.Peer != "127.0.0.3" {
		t.Errorf("withdrawn 172.16.1.0/24 of VRF 101: %+v", w)
	}

	// The node withdraws the prefix of VRF 101: the route of VRF 102 stays
	node.send(Message{Type: TypeWithdraw, VRF: 101, Prefix: "10.10.0.0/24"})
	waitUntil(t, "the fabric loses the route of VRF 101", func() bool {
		r := fabric.routes()
		_, a := r["10.10.0.0/24 192.0.2.1:101"]
		_, b := r["10.10.0.0/24 65000:102"]
		return !a && b
	})

	// What cannot be applied is answered with an error; the session goes on. A prefix of VRF 103, which the gateway does
	// not hand to the fabric, goes nowhere, and its withdraw takes nothing of VRF 102
	refused := []Message{
		{Type: TypeAnnounce, VRF: 101, Prefix: "10.20.0.0/24", NextHop: "192.0.2.1"},
		{Type: TypeAnnounce, VRF: 101, Prefix: "10.20.0.1/24"},
		{Type: TypeWithdraw, VRF: 102, Prefix: "10.20.0.0/24"},
		{Type: TypeWithdraw, VRF: 102, Prefix: "not-a-prefix"},
		{Type: TypeAnnounce, VRF: 103, Prefix: "10.30.0.0/24"},
		{Type: TypeWithdraw, VRF: 103, Prefix: "10.10.0.0/24"},
	}
	for _, m := range refused {
		node.send(m)
		e := node.wait("an error for "+m.Type+" "+m.Prefix, false, isType(TypeError))
		if e.Prefix != m.Prefix || e.Error == "" {
			t.Errorf("error for %+v: %+v", m, e)
		}
	}
	time.Sleep(settleTime)
	if _, ok := fabric.routes()["10.10.0.0/24 65000:102"]; !ok {
		t.Error("the fabric lost the route of VRF 102 after a withdraw of VRF 103")
	}
	if n := fabric.unicastRoutes(); n != 0 {
		t.Errorf("the fabric has %d IPv4 unicast routes of the gateway, whose prefixes are of VRFs", n)
	}
}

// unicastRoutes is the number of the IPv4 unicast routes that the fabric router has from the gateway
func (f *testFabric) unicastRoutes() int {
	f.t.Helper()
	num := 0
	err := f.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_IPv4_UC}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, p := range paths {
			if p.PeerAddress.IsValid() {
				num++
			}
		}
	})
	if err != nil {
		f.t.Fatalf("fabric RIB: %v", err)
	}
	return num
}

// hasEVPN reports whether the global RIB of the sidecar holds at least num IP prefix routes of the peers
func (n *testNode) hasEVPN(num int) bool {
	n.t.Helper()
	if n.bgp == nil {
		n.bgp = <-n.started
	}
	found := 0
	err := n.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_EVPN}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, p := range paths {
			if p.PeerAddress.IsValid() {
				found++
			}
		}
	})
	if err != nil {
		n.t.Fatalf("sidecar RIB: %v", err)
	}
	return found >= num
}

// A start whose evpn is not one, or that has an address too (the peering of the standard mode), is answered with an
// error, and the session ends.
func TestEVPNBadStart(t *testing.T) {
	bad := testEVPN()
	bad.VRFs[0].VNI = 0
	cases := []struct {
		name string
		m    Message
		want string
	}{
		{"a VRF without a VNI", Message{Type: TypeStart, ASN: 65001, RouterID: "192.0.2.1", ListenPort: -1, Peers: []Peer{{Address: "192.0.2.2", ASN: 65002}}, EVPN: bad}, "evpn: vrf 101"},
		{"evpn with an address", Message{Type: TypeStart, ASN: 65001, RouterID: "192.0.2.1", ListenPort: -1, Address: "192.0.2.1", EVPN: testEVPN()}, "a start has one of them"},
	}
	for _, c := range cases {
		node := startNode(t, context.Background())
		node.send(c.m)
		m := node.wait("an error for "+c.name, false, isType(TypeError))
		if !strings.Contains(m.Error, c.want) {
			t.Errorf("%s: the error: %+v", c.name, m)
		}
		select {
		case err := <-node.done:
			if err == nil {
				t.Errorf("%s: the session ended without an error", c.name)
			}
		case <-time.After(waitTimeout):
			t.Fatalf("%s: the session did not end", c.name)
		}
	}
}

// A peer of a session with EVPN offers the L2VPN EVPN family besides IPv4 and IPv6 unicast; one of a session without it
// does not.
func TestEVPNPeerFamilies(t *testing.T) {
	families := func(s *session) []string {
		var out []string
		for _, a := range s.withEVPN(s.peerRequest(peerConfig{address: netip.MustParseAddr("192.0.2.2"), asn: 65002})).AfiSafis {
			out = append(out, a.Config.Family.Afi.String()+"/"+a.Config.Family.Safi.String())
		}
		return out
	}
	st, err := parseEVPN(testEVPN(), netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	with := families(&session{evpn: st})
	without := families(&session{})
	if len(with) != 3 || with[2] != "AFI_L2VPN/SAFI_EVPN" || len(without) != 2 || slices.Contains(without, "AFI_L2VPN/SAFI_EVPN") {
		t.Errorf("the families: %v with EVPN, %v without", with, without)
	}
}
