package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// addresses6Of returns the IPv6 addresses of the Node name as "network=address" pairs, in
// Network order.
func addresses6Of(in Intent, name string) string {
	var out []string
	for _, network := range sortedNames(in.Nodes[name].IPv6Addresses) {
		out = append(out, network+"="+in.Nodes[name].IPv6Addresses[network])
	}
	return strings.Join(out, ",")
}

// refuses checks that applying the resources rs to in is refused as an invalid intent, with an
// error that says want.
func refuses(t *testing.T, in Intent, want string, rs ...Resource) {
	t.Helper()
	_, err := Apply(in, doc(rs...), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("%v: the error is %v, want one with %q", rs, err, want)
	}
}

// A Node gets the lowest free host address of the IPv6 pool of each L3 Network of its VRFs, as it
// gets one of the IPv4 pool, and keeps it. An L2 Network allocates nothing, and a Network
// allocates in the families that it has a pool of.
func TestApplyAllocatesIPv6Addresses(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(KindNetwork, "v6", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:2::/112"}`),
		res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv6Pool": "fd12:3456:789a:3::/64"}`),
		res(KindNode, "branch-2", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"branch-1": "lan=fd12:3456:789a:1::1,v6=fd12:3456:789a:2::1",
		"branch-2": "lan=fd12:3456:789a:1::2,v6=fd12:3456:789a:2::2",
	} {
		if got := addresses6Of(in, name); got != want {
			t.Errorf("%s holds the IPv6 addresses %q, want %q", name, got, want)
		}
	}
	if got := addressesOf(in, "branch-1"); got != "lan=10.0.0.1" {
		t.Errorf("branch-1 holds the IPv4 addresses %q, want lan=10.0.0.1 alone", got)
	}
	if p, ok := in.NodeAddress6("branch-1", "lan"); !ok || p.String() != "fd12:3456:789a:1::1/64" {
		t.Errorf("the IPv6 address of branch-1 in lan is %v (%v), want fd12:3456:789a:1::1/64", p, ok)
	}
	if p, ok := in.NodeAddress6("branch-1", "v6"); !ok || p.String() != "fd12:3456:789a:2::1/112" {
		t.Errorf("the IPv6 address of branch-1 in v6 is %v (%v), want fd12:3456:789a:2::1/112", p, ok)
	}
	if _, ok := in.NodeAddress6("branch-1", "dmz"); ok {
		t.Error("branch-1 holds an IPv6 address in the L2 Network dmz")
	}
	if _, ok := in.NodeAddress("branch-1", "v6"); ok {
		t.Error("branch-1 holds an IPv4 address in the Network v6, which has no IPv4 pool")
	}
	if _, ok := in.NodeAddress6("nobody", "lan"); ok {
		t.Error("a Node that does not exist holds an IPv6 address")
	}

	next, err := Apply(in, doc(res(KindNode, "branch-0", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"branch-0": "lan=fd12:3456:789a:1::3,v6=fd12:3456:789a:2::3",
		"branch-1": "lan=fd12:3456:789a:1::1,v6=fd12:3456:789a:2::1",
	} {
		if got := addresses6Of(next, name); got != want {
			t.Errorf("after the second apply %s holds the IPv6 addresses %q, want %q", name, got, want)
		}
	}
	gone, err := Delete(next, KindNetwork, "v6")
	if err != nil {
		t.Fatal(err)
	}
	if got := addresses6Of(gone, "branch-1"); got != "lan=fd12:3456:789a:1::1" {
		t.Errorf("after the delete of v6 branch-1 holds the IPv6 addresses %q", got)
	}
	if got := addresses6Of(next, "branch-1"); got != "lan=fd12:3456:789a:1::1,v6=fd12:3456:789a:2::1" {
		t.Errorf("Delete changed the IPv6 addresses of the intent it was given: %q", got)
	}
}

// A declared IPv6 address is a reservation: it is the Node's, and the Node that comes first in
// name order does not get it. It must be a free host address of the IPv6 pool of an L3 Network of
// the Node's VRFs.
func TestReservedIPv6Addresses(t *testing.T) {
	base, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv6Pool": "fd12:3456:789a:3::/64"}`),
		res(KindNode, "alpha", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "zeta", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "addresses": {"lan": "10.0.0.1"}, "ipv6Addresses": {"lan": "fd12:3456:789a:1::1"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"alpha": "lan=10.0.0.2 lan=fd12:3456:789a:1::2",
		"zeta":  "lan=10.0.0.1 lan=fd12:3456:789a:1::1",
	} {
		if got := addressesOf(base, name) + " " + addresses6Of(base, name); got != want {
			t.Errorf("%s holds %q, want %q: the reservation of zeta is honoured although alpha comes first", name, got, want)
		}
	}
	beta := func(spec string) Resource {
		return res(KindNode, "beta", `{"publicKey": "`+key2+`", "vrfs": ["corp"], `+spec+`}`)
	}
	for _, c := range []struct {
		spec, want string
	}{
		{`"ipv6Addresses": {"lan": "fd12:3456:789a:1::1"}`, `address fd12:3456:789a:1::1 of Network "lan" is already the address of Node "zeta"`},
		{`"ipv6Addresses": {"lan": "fd12:3456:789a:1::"}`, `address fd12:3456:789a:1:: is not a host address of the pool fd12:3456:789a:1::/64`},
		{`"ipv6Addresses": {"lan": "fd12:3456:789a:2::1"}`, `is not a host address of the pool`},
		{`"ipv6Addresses": {"lan": "10.0.0.9"}`, `address "10.0.0.9" of Network "lan" is not an IPv6 address`},
		{`"ipv6Addresses": {"lan": "::ffff:10.0.0.9"}`, `is not an IPv6 address`},
		{`"ipv6Addresses": {"lan": "nonsense"}`, `is not an IPv6 address`},
		{`"ipv6Addresses": {"dmz": "fd12:3456:789a:3::1"}`, `"dmz" is not an L3 Network with an IPv6 pool in a VRF of the node`},
	} {
		refuses(t, base, c.want, beta(c.spec))
	}
}

// The IPv6 pool of a Network lies in the ULA /48 of its VRF, outside the /64 that 4via6 reserves,
// which is the last one of the ULA.
func TestIPv6PoolsLieInTheULA(t *testing.T) {
	base, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		pool, want string
	}{
		{"fd12:3456:789b:1::/64", `Network "n": ipv6Pool fd12:3456:789b:1::/64 is not inside the ULA fd12:3456:789a::/48 of VRF "corp"`},
		{"fd00::/64", `is not inside the ULA fd12:3456:789a::/48 of VRF "corp"`},
		{"fd12:3456:789a::/48", `Network "n": ipv6Pool fd12:3456:789a::/48 overlaps fd12:3456:789a:ffff::/64, the /64 of the ULA of VRF "corp" that 4via6 reserves`},
		{"fd12:3456:789a:ffff::/112", `overlaps fd12:3456:789a:ffff::/64, the /64 of the ULA of VRF "corp" that 4via6 reserves`},
	} {
		refuses(t, base, c.want, res(KindNetwork, "n", `{"vrf": "corp", "ipv6Pool": "`+c.pool+`"}`))
	}
	// A Network in a VRF whose ULA is no ULA is refused for its VRF
	refuses(t, base, `ula "fc00:1:2::/48" is not a ULA /48`,
		res(KindVRF, "bad", `{"ula": "fc00:1:2::/48"}`),
		res(KindNetwork, "n", `{"vrf": "bad", "ipv6Pool": "fc00:1:2:1::/64"}`))
	// The /64 next to the reserved one is a pool, in each VRF
	if _, err := Apply(base, doc(
		res(KindNetwork, "n", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:fffe::/64"}`),
		res(KindNetwork, "m", `{"vrf": "lab", "ipv6Pool": "fd12:3456:789b:fffe::/64"}`),
	), nil); err != nil {
		t.Errorf("the /64 before the one of 4via6: %v", err)
	}

	ula := netip.MustParsePrefix("fd12:3456:789a::/48")
	if got := FourViaSix(ula).String(); got != "fd12:3456:789a:ffff::/64" {
		t.Errorf("the 4via6 /64 of %s is %s, want fd12:3456:789a:ffff::/64", ula, got)
	}
	for _, s := range []string{"10.0.0.0/8", "fd12:3456:789a::/56", "::ffff:10.0.0.0/48"} {
		if p := FourViaSix(netip.MustParsePrefix(s)); p.IsValid() {
			t.Errorf("the 4via6 /64 of %s is %s, want none: it is no ULA /48", s, p)
		}
	}
	if p := FourViaSix(netip.Prefix{}); p.IsValid() {
		t.Errorf("the 4via6 /64 of no prefix is %s", p)
	}
}

// The pools of one VRF do not overlap, whatever their Networks' modes, so that an address names
// one holder in a VRF; two VRFs may use the same range.
func TestPoolsOfOneVRFDoNotOverlap(t *testing.T) {
	base, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	refuses(t, base, `Network "a": the pool 10.0.0.0/24 overlaps the pool 10.0.0.128/25 of Network "b" in VRF "corp"`,
		res(KindNetwork, "a", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "b", `{"vrf": "corp", "ipv4Pool": "10.0.0.128/25"}`))
	refuses(t, base, `Network "a": the pool fd12:3456:789a:1::/64 overlaps the pool fd12:3456:789a:1::/112 of Network "b" in VRF "corp"`,
		res(KindNetwork, "a", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(KindNetwork, "b", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/112"}`))
	refuses(t, base, `Network "a": the pool 10.0.0.0/24 overlaps the pool 10.0.0.0/25 of Network "b" in VRF "corp"`,
		res(KindNetwork, "a", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "b", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.0.0.0/25"}`))

	in, err := Apply(base, doc(
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(in, "a") + " " + addressesOf(in, "b"); got != "corp-lan=10.0.0.1 lab-lan=10.0.0.1" {
		t.Errorf("a and b hold %q, want the first address of the same range in each VRF", got)
	}
}

// A Network reserves prefixes of its pools, and single addresses, that no Node is given: not by
// the allocation, which steps over them whatever their size, and not by a declaration. A Node that
// held a reserved address gets another.
func TestNetworkReservations(t *testing.T) {
	lan := func(extra string) Resource {
		return res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"`+extra+`}`)
	}
	first, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		lan(""),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(first, "a") + " " + addresses6Of(first, "a"); got != "lan=10.0.0.1 lan=fd12:3456:789a:1::1" {
		t.Fatalf("a holds %q before the reservation", got)
	}
	reserved, err := Apply(first, doc(
		lan(`, "reserved": ["10.0.0.9", "10.0.0.0/29", "fd12:3456:789a:1::/124"]`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reserved.Networks["lan"].Reserved, ","); got != "10.0.0.0/29,10.0.0.9/32,fd12:3456:789a:1::/124" {
		t.Errorf("the reservations are stored as %q, want prefixes in order", got)
	}
	for name, want := range map[string]string{
		"a": "lan=10.0.0.8 lan=fd12:3456:789a:1::10",
		"b": "lan=10.0.0.10 lan=fd12:3456:789a:1::11",
	} {
		if got := addressesOf(reserved, name) + " " + addresses6Of(reserved, name); got != want {
			t.Errorf("%s holds %q, want %q past the reservations", name, got, want)
		}
	}
	c := func(spec string) Resource {
		return res(KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["corp"], `+spec+`}`)
	}
	refuses(t, reserved, `address 10.0.0.5 of Network "lan" is reserved by the Network`, c(`"addresses": {"lan": "10.0.0.5"}`))
	refuses(t, reserved, `address 10.0.0.9 of Network "lan" is reserved by the Network`, c(`"addresses": {"lan": "10.0.0.9"}`))
	refuses(t, reserved, `address fd12:3456:789a:1::5 of Network "lan" is reserved by the Network`, c(`"ipv6Addresses": {"lan": "fd12:3456:789a:1::5"}`))

	for _, extra := range []struct {
		spec, want string
	}{
		{`, "reserved": ["nonsense"]`, `Network "lan": reserved: `},
		{`, "reserved": ["10.0.0.0/33"]`, `Network "lan": reserved: `},
		{`, "reserved": ["10.0.0.1/24"]`, `reserved "10.0.0.1/24" has host bits set, the prefix is 10.0.0.0/24`},
		{`, "reserved": ["10.9.0.1"]`, `Network "lan": reserved 10.9.0.1/32 is inside none of the pools of the Network`},
		{`, "reserved": ["10.0.0.9", "10.0.0.9/32"]`, `Network "lan": reserved 10.0.0.9/32 is listed twice`},
		{`, "poolThreshold": 101`, `Network "lan": poolThreshold 101 is not between 1 and 100 (0 is the default, 80)`},
	} {
		refuses(t, first, extra.want, lan(extra.spec))
	}

	// A pool that the Network reserves whole has no free address, and a reservation of half of a
	// /64 is stepped over in one move
	refuses(t, New(), `Network "tiny": the IPv4 pool 10.0.0.0/30 has no free address for Node "a"`,
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "tiny", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/30", "reserved": ["10.0.0.0/30"]}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`))
	big, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "big", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/64", "reserved": ["fd12:3456:789a:1::/65"]}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addresses6Of(big, "a"); got != "big=fd12:3456:789a:1:8000::" {
		t.Errorf("a holds %q, want the first address after the reserved half of the /64", got)
	}
}

// A LAN subnet behind a gateway Node is a route that the gateway advertises in a VRF, never an
// allocation: no Node holds an address in one, and no pool of the VRF may cover one. Two gateways
// may advertise the same subnet.
func TestLANSubnetsAreRoutes(t *testing.T) {
	gw := func(name, key, vrfs, lans string) Resource {
		return res(KindNode, name, `{"publicKey": "`+key+`", "vrfs": `+vrfs+`, "lanSubnets": `+lans+`}`)
	}
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		gw("gw", key1, `["corp", "lab"]`, `{"corp": ["192.168.1.0/24", "10.99.0.0/16", "FD12:3456:789A:5::/64"], "lab": []}`),
		gw("gw-2", key2, `["corp"]`, `{"corp": ["192.168.1.0/24"]}`),
		res(KindNode, "laptop", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Nodes["gw"].LANSubnets; len(got) != 1 || strings.Join(got["corp"], ",") != "10.99.0.0/16,192.168.1.0/24,fd12:3456:789a:5::/64" {
		t.Errorf("the LAN subnets of gw are stored as %v, want the corp ones as prefixes in order, and no empty list of lab", got)
	}
	routes := func(in Intent) string {
		var out []string
		for _, r := range in.Routes() {
			out = append(out, r.VRF+" "+r.Prefix.String()+" via "+r.Via)
		}
		return strings.Join(out, "\n")
	}
	want := "corp 10.99.0.0/16 via gw\ncorp 192.168.1.0/24 via gw\ncorp 192.168.1.0/24 via gw-2\ncorp fd12:3456:789a:5::/64 via gw"
	if got := routes(in); got != want {
		t.Errorf("the routes are\n%s\nwant\n%s", got, want)
	}
	// Never an allocation: the Nodes hold the first addresses of the pool, and none of them is
	// in a LAN subnet
	if got := addressesOf(in, "gw") + " " + addressesOf(in, "gw-2") + " " + addressesOf(in, "laptop"); got != "lan=10.0.0.1 lan=10.0.0.2 lan=10.0.0.3" {
		t.Errorf("the Nodes hold %q, want the first addresses of the pool", got)
	}
	for name := range in.Nodes {
		p, ok := in.NodeAddress(name, "lan")
		for _, r := range in.Routes() {
			if !ok || r.Prefix.Contains(p.Addr()) {
				t.Errorf("%s holds the address %v (%v), which is in the LAN subnet %s that %s advertises", name, p, ok, r.Prefix, r.Via)
			}
		}
	}
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}

	// No pool of the VRF covers a LAN subnet, or lies in one; a pool of another VRF may
	refuses(t, in, `Network "wide": the pool 192.168.0.0/16 overlaps the LAN subnet 192.168.1.0/24 that Node "gw" advertises in VRF "corp": a LAN subnet is a route and never an allocation`,
		res(KindNetwork, "wide", `{"vrf": "corp", "ipv4Pool": "192.168.0.0/16"}`))
	refuses(t, in, `Network "inner": the pool 10.99.5.0/24 overlaps the LAN subnet 10.99.0.0/16 that Node "gw" advertises in VRF "corp"`,
		res(KindNetwork, "inner", `{"vrf": "corp", "ipv4Pool": "10.99.5.0/24"}`))
	refuses(t, in, `Network "v6": the pool fd12:3456:789a:5::/112 overlaps the LAN subnet fd12:3456:789a:5::/64 that Node "gw" advertises in VRF "corp"`,
		res(KindNetwork, "v6", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:5::/112"}`))
	other, err := Apply(in, doc(res(KindNetwork, "wide-lab", `{"vrf": "lab", "ipv4Pool": "192.168.0.0/16"}`)), nil)
	if err != nil {
		t.Fatalf("a pool of lab over the LAN subnet that gw advertises in corp: %v", err)
	}
	if got := addressesOf(other, "gw"); got != "lan=10.0.0.1,wide-lab=192.168.0.1" {
		t.Errorf("gw holds %q, want an address in each pool", got)
	}

	// The LAN subnets of a Node are of its own VRFs, prefixes with no host bits, not the default
	// route, and each once
	gw2 := func(lans string) Resource { return gw("gw-2", key2, `["corp"]`, lans) }
	for _, c := range []struct {
		lans, want string
	}{
		{`{"lab": ["10.1.0.0/24"]}`, `Node "gw-2": lanSubnets: VRF "lab" is not a VRF of the node`},
		{`{"corp": ["192.168.1.1/24"]}`, `LAN subnet "192.168.1.1/24" has host bits set, the prefix is 192.168.1.0/24`},
		{`{"corp": ["0.0.0.0/0"]}`, `LAN subnet "0.0.0.0/0" is the default route, which is no LAN`},
		{`{"corp": ["::ffff:10.1.0.0/112"]}`, `is an IPv4-mapped IPv6 prefix`},
		{`{"corp": ["nonsense"]}`, `Node "gw-2": lanSubnets of VRF "corp": LAN subnet: `},
		{`{"corp": ["192.168.1.0/24", "192.168.1.0/24"]}`, `LAN subnet 192.168.1.0/24 of VRF "corp" is listed twice`},
	} {
		refuses(t, in, c.want, gw2(c.lans))
	}

	// A Node applied again without its LAN subnets advertises none, and the intent it was given
	// keeps them
	dropped, err := Apply(in, doc(res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := routes(dropped); got != "corp 192.168.1.0/24 via gw-2" {
		t.Errorf("the routes after gw left out its LAN subnets are %q, want the one of gw-2", got)
	}
	if got := routes(in); got != want {
		t.Errorf("Apply changed the routes of the intent it was given:\n%s", got)
	}
}

// How full a pool is: its host addresses, the ones Nodes hold, the ones the Network reserves, and
// whether it is at its threshold (80 percent unless the Network sets another).
func TestPoolUse(t *testing.T) {
	lines := func(in Intent) string {
		var out []string
		for _, u := range in.Pools() {
			out = append(out, fmt.Sprintf("%s %s size=%d allocated=%d reserved=%d free=%d percent=%d threshold=%d near=%v",
				u.Network, u.Pool, u.Size, u.Allocated, u.Reserved, u.Free, u.Percent, u.Threshold, u.NearExhaustion))
		}
		return strings.Join(out, "\n")
	}
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "big", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(KindNetwork, "six", `{"vrf": "corp", "ipv4Pool": "10.1.0.0/29", "poolThreshold": 50, "reserved": ["10.1.0.0/30"]}`),
		res(KindNetwork, "tiny", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/30"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "big fd12:3456:789a:1::/64 size=9007199254740992 allocated=1 reserved=0 free=9007199254740991 percent=0 threshold=80 near=false\n" +
		"six 10.1.0.0/29 size=6 allocated=1 reserved=3 free=2 percent=66 threshold=50 near=true\n" +
		"tiny 10.0.0.0/30 size=2 allocated=1 reserved=0 free=1 percent=50 threshold=80 near=false"
	if got := lines(in); got != want {
		t.Errorf("with one Node the pools are\n%s\nwant\n%s", got, want)
	}
	next, err := Apply(in, doc(res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	want = "big fd12:3456:789a:1::/64 size=9007199254740992 allocated=2 reserved=0 free=9007199254740990 percent=0 threshold=80 near=false\n" +
		"six 10.1.0.0/29 size=6 allocated=2 reserved=3 free=1 percent=83 threshold=50 near=true\n" +
		"tiny 10.0.0.0/30 size=2 allocated=2 reserved=0 free=0 percent=100 threshold=80 near=true"
	if got := lines(next); got != want {
		t.Errorf("with two Nodes the pools are\n%s\nwant\n%s", got, want)
	}
	if got := lines(in); !strings.Contains(got, "tiny 10.0.0.0/30 size=2 allocated=1") {
		t.Errorf("Apply changed the pools of the intent it was given:\n%s", got)
	}
}

// The host addresses of a pool, and of a prefix in it, are the ones that Nodes may hold: IPv4
// without its network and broadcast addresses and IPv6 without its Subnet-Router anycast address,
// unless the pool has no more than two addresses; a reservation counts once, however it is listed.
func TestHostsIn(t *testing.T) {
	for _, c := range []struct {
		pool string
		want uint64
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/31", 2},
		{"10.0.0.1/32", 1},
		{"fd12:3456:789a:1::/120", 255},
		{"fd12:3456:789a:1::/127", 2},
		{"fd12:3456:789a:1::1/128", 1},
		{"fd12:3456:789a:1::/64", MaxPoolSize},
	} {
		p := netip.MustParsePrefix(c.pool)
		if got := hostsIn(p, p); got != c.want {
			t.Errorf("the pool %s has %d host addresses, want %d", c.pool, got, c.want)
		}
	}
	pool := netip.MustParsePrefix("10.0.0.0/24")
	for _, c := range []struct {
		prefix string
		want   uint64
	}{
		{"10.0.0.128/25", 127},
		{"10.0.0.0/25", 127},
		{"10.0.0.64/26", 64},
		{"10.0.0.255/32", 0},
	} {
		if got := hostsIn(pool, netip.MustParsePrefix(c.prefix)); got != c.want {
			t.Errorf("%s of %s has %d host addresses, want %d", c.prefix, pool, got, c.want)
		}
	}
	slash29, slash28 := netip.MustParsePrefix("10.0.0.0/29"), netip.MustParsePrefix("10.0.0.0/28")
	if got := reservedCount(pool, []netip.Prefix{slash28, slash29}); got != 15 {
		t.Errorf("a /28 and the /29 in it reserve %d addresses, want 15", got)
	}
	if got := reservedCount(pool, []netip.Prefix{slash29, slash29}); got != 7 {
		t.Errorf("a /29 listed twice reserves %d addresses, want 7", got)
	}
	if got := reservedCount(pool, nil); got != 0 {
		t.Errorf("no reservation reserves %d addresses", got)
	}
	if got := reservedCount(netip.MustParsePrefix("fd12:3456:789a:1::/64"), []netip.Prefix{netip.MustParsePrefix("fd12:3456:789a:1::/65"), netip.MustParsePrefix("fd12:3456:789a:1:8000::/65")}); got != MaxPoolSize {
		t.Errorf("the two halves of a /64 reserve %d addresses, want at most %d", got, uint64(MaxPoolSize))
	}
}

// A Node holds at most MaxAddresses addresses, because the control protocol carries no more.
func TestNodeAddressLimit(t *testing.T) {
	rs := []Resource{res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)}
	for i := 0; i < 9; i++ {
		rs = append(rs, res(KindNetwork, fmt.Sprintf("lan-%d", i),
			fmt.Sprintf(`{"vrf": "corp", "ipv4Pool": "10.%d.0.0/24", "ipv6Pool": "fd12:3456:789a:%x::/64"}`, i, i+1)))
	}
	node := res(KindNode, "n", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`)
	refuses(t, New(), `Node "n": 18 addresses in its Networks, and the control protocol carries at most 16`, append(slices.Clone(rs), node)...)
	// Eight Networks with two pools each are 16 addresses
	if _, err := Apply(New(), doc(append(slices.Clone(rs[:9]), node)...), nil); err != nil {
		t.Errorf("a Node with 16 addresses: %v", err)
	}
}
