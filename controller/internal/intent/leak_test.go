package intent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// leakLines returns the leaks as "from > to route-targets", one per leak.
func leakLines(leaks []Leak) string {
	var lines []string
	for _, l := range leaks {
		lines = append(lines, l.From+" > "+l.To+" "+strings.Join(l.RouteTargets, ","))
	}
	return strings.Join(lines, "\n")
}

// routeLines returns the leaked routes as "vrf prefix via node from vrf", one per route.
func routeLines(routes []LeakedRoute) string {
	var lines []string
	for _, r := range routes {
		lines = append(lines, r.VRF+" "+r.Prefix.String()+" via "+r.Via+" from "+r.From)
	}
	return strings.Join(lines, "\n")
}

// sharedServices applies a shared-services VRF that exports 64512:10 and imports 64512:1, and red
// and blue, which both export 64512:1 and import 64512:10, each with a Network and a Node, with the
// resources of more.
func sharedServices(t *testing.T, more ...Resource) (Intent, error) {
	t.Helper()
	rs := []Resource{
		res(KindVRF, "shared", `{"id": 10, "ula": "fd00:10::/48", "exportTargets": ["64512:10"], "importTargets": ["64512:1"]}`),
		res(KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["64512:01"], "importTargets": ["64512:010"]}`),
		res(KindNetwork, "shared-lan", `{"vrf": "shared", "ipv4Pool": "10.10.0.0/24", "ipv6Pool": "fd00:10:0:1::/64"}`),
		res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(KindNode, "dns", `{"publicKey": "`+key1+`", "vrfs": ["shared"]}`),
		res(KindNode, "red-1", `{"publicKey": "`+key2+`", "vrfs": ["red"]}`),
		res(KindNode, "blue-1", `{"publicKey": "`+key3+`", "vrfs": ["blue"]}`),
	}
	return Apply(New(), doc(append(rs, more...)...), nil)
}

func TestParseRouteTarget(t *testing.T) {
	for _, c := range []struct{ s, want string }{
		{"65000:100", "65000:100"},
		{"1:4294967295", "1:4294967295"},
		{"065000:0100", "65000:100"},
		{"4200000000:65535", "4200000000:65535"},
		{"192.0.2.1:7", "192.0.2.1:7"},
		{"64512:0", "64512:0"},
		{"4294967295:1", "4294967295:1"},
		{"198.51.100.1:65535", "198.51.100.1:65535"},
	} {
		if got, err := ParseRouteTarget(c.s); err != nil || got != c.want {
			t.Errorf("ParseRouteTarget(%q) = %q, %v, want %q", c.s, got, err, c.want)
		}
	}
	for _, c := range []struct{ s, want string }{
		{"", "is not ASN:NUMBER or IPV4:NUMBER"},
		{"65000", "is not ASN:NUMBER or IPV4:NUMBER"},
		{":1", "is not ASN:NUMBER or IPV4:NUMBER"},
		{"65000:", "is not ASN:NUMBER or IPV4:NUMBER"},
		{"65000:x", `the number "x" is not a number`},
		{"65000:4294967296", `the number "4294967296" is not a number`},
		{"65000:-1", `the number "-1" is not a number`},
		{"0:1", "AS number 0 is reserved"},
		{"4294967296:1", "is neither an AS number nor an IPv4 address"},
		{"4200000000:65536", "after an AS number above 65535 the number is at most 65535"},
		{"192.0.2.1:65536", "after an IPv4 address the number is at most 65535"},
		{"2001:db8::1:1", "is neither an AS number nor an IPv4 address"},
		{"[2001:db8::1]:1", "is neither an AS number nor an IPv4 address"},
		{"red:1", "is neither an AS number nor an IPv4 address"},
		{"+65000:1", "is neither an AS number nor an IPv4 address"},
		{"192.0.2.1/32:1", "is neither an AS number nor an IPv4 address"},
		{" 65000:1", "is neither an AS number nor an IPv4 address"},
		{"65000:1 ", "is not a number"},
		{"::ffff:192.0.2.1:1", "is neither an AS number nor an IPv4 address"},
	} {
		if got, err := ParseRouteTarget(c.s); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseRouteTarget(%q) = %q, %v, want an error with %q", c.s, got, err, c.want)
		}
	}
}

// The routes of a VRF leak into every other VRF that imports a route target that it exports, in
// their one form: a shared-services VRF reaches red and blue and they reach it, while red and blue,
// which export to it but import only from it, reach each other not at all.
func TestSharedServicesLeak(t *testing.T) {
	in, err := sharedServices(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.VRFs["blue"]; !slices.Equal(got.ExportTargets, []string{"64512:1"}) || !slices.Equal(got.ImportTargets, []string{"64512:10"}) {
		t.Errorf("the route targets of blue are %v and %v, want them in their one form", got.ExportTargets, got.ImportTargets)
	}
	if got, want := leakLines(in.Leaks()), "blue > shared 64512:1\nred > shared 64512:1\nshared > blue 64512:10\nshared > red 64512:10"; got != want {
		t.Errorf("the leaks are\n%s\nwant\n%s", got, want)
	}
	want := strings.Join([]string{
		"blue 10.10.0.1/32 via dns from shared",
		"blue fd00:10:0:1::1/128 via dns from shared",
		"red 10.10.0.1/32 via dns from shared",
		"red fd00:10:0:1::1/128 via dns from shared",
		"shared 10.1.0.1/32 via red-1 from red",
		"shared 10.2.0.1/32 via blue-1 from blue",
	}, "\n")
	if got := routeLines(in.LeakedRoutes()); got != want {
		t.Errorf("the leaked routes are\n%s\nwant\n%s", got, want)
	}

	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	clone := in.Clone()
	clone.VRFs["red"].ImportTargets[0] = "65000:1"
	if in.VRFs["red"].ImportTargets[0] != "64512:10" {
		t.Error("a clone of the intent shares the route targets of red with it")
	}
}

// A leaked route that overlaps a prefix of the VRF that imports it is refused with an error that
// names both and the 1:1 NAT rule that resolves it. With that rule the address leaks as the outside
// of the rule, and an outside prefix that the importing VRF uses is refused in turn.
func TestOverlappingLeakNeedsNAT(t *testing.T) {
	base := []Resource{
		res(KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:2"]}`),
		res(KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["64512:2"], "importTargets": ["64512:1"]}`),
		res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["blue"]}`),
	}
	_, err := Apply(New(), doc(base...), nil)
	for _, want := range []string{
		`VRF "blue" imports the route target 64512:1 of VRF "red", which leaks the address 10.0.0.1 of Node "a" into it, but VRF "blue" holds the overlapping pool 10.0.0.0/24 of Network "blue-lan": a leaked overlapping prefix needs 1:1 NAT (ADR-0025 decision 8), so give Node "a" a 1:1 NAT rule in VRF "red" whose inside holds 10.0.0.1, and the address leaks as the outside of the rule`,
		`VRF "red" imports the route target 64512:2 of VRF "blue", which leaks the address 10.0.0.1 of Node "b" into it, but VRF "red" holds the overlapping pool 10.0.0.0/24 of Network "red-lan"`,
	} {
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
			t.Errorf("an overlapping leak without 1:1 NAT gave %v, want an error with %q", err, want)
		}
	}

	withNAT := append(slices.Clone(base), nat("a-out", "red", "a", "10.0.0.1/32", "10.201.0.1/32"), nat("b-out", "blue", "b", "10.0.0.1/32", "10.202.0.1/32"))
	in, err := Apply(New(), doc(withNAT...), nil)
	if err != nil {
		t.Fatalf("an overlapping leak with 1:1 NAT: %v", err)
	}
	if got, want := routeLines(in.LeakedRoutes()), "blue 10.201.0.1/32 via a from red\nred 10.202.0.1/32 via b from blue"; got != want {
		t.Errorf("the leaked routes are\n%s\nwant\n%s", got, want)
	}

	used := append(slices.Clone(withNAT), res(KindNetwork, "blue-dmz", `{"vrf": "blue", "ipv4Pool": "10.201.0.0/24"}`))
	if _, err := Apply(New(), doc(used...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(),
		`which leaks the outside 10.201.0.1/32 of NAT "a-out" into it, but VRF "blue" holds the overlapping pool 10.201.0.0/24 of Network "blue-dmz": a leaked overlapping prefix needs 1:1 NAT (ADR-0025 decision 8), so give NAT "a-out" an outside prefix that VRF "blue" does not use`) {
		t.Errorf("an outside prefix that the importing VRF uses: %v", err)
	}

	// Two VRFs that leak one address into a third collide there, and so does a LAN subnet of the
	// importing VRF
	exporters := append(slices.Clone(base[2:]),
		res(KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"]}`),
		res(KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["64512:2"]}`),
		res(KindVRF, "hub", `{"id": 3, "ula": "fd00:3::/48", "importTargets": ["64512:1", "64512:2"]}`))
	for _, c := range []struct{ node, want string }{
		{`{"publicKey": "` + key3 + `", "vrfs": ["hub"]}`,
			`VRF "hub" imports the route target 64512:1 of VRF "red", which leaks the address 10.0.0.1 of Node "a" into it, but VRF "hub" holds the overlapping address 10.0.0.1 of Node "b", which VRF "blue" leaks into it`},
		{`{"publicKey": "` + key3 + `", "vrfs": ["hub"], "lanSubnets": {"hub": ["10.0.0.0/30"]}}`,
			`VRF "hub" imports the route target 64512:2 of VRF "blue", which leaks the address 10.0.0.1 of Node "b" into it, but VRF "hub" holds the overlapping LAN subnet 10.0.0.0/30 that Node "c" advertises`},
	} {
		if _, err := Apply(New(), doc(append(slices.Clone(exporters), res(KindNode, "c", c.node))...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Node c %s in the VRF that imports both: %v, want an error with %q", c.node, err, c.want)
		}
	}
}

// The shortcut connects two VRFs in one document of two VRF resources: each exports a route target,
// its own id under 64512 when it exported none, and imports one of the other. Applying it makes the
// leak both ways, and connecting them again changes nothing.
func TestConnect(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "mtu": 1400}`),
		res(KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["65000:7"]}`),
		res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["blue"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Leaks()) != 0 {
		t.Fatalf("the VRFs leak before they are connected: %+v", in.Leaks())
	}
	d, err := in.Connect("red", "blue")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range d.Resources {
		lines = append(lines, r.Kind+" "+r.Name+" "+string(r.Spec))
	}
	if got, want := strings.Join(lines, "\n"), strings.Join([]string{
		`VRF red {"id":1,"ula":"fd00:1::/48","mtu":1400,"importTargets":["65000:7"],"exportTargets":["64512:1"]}`,
		`VRF blue {"id":2,"ula":"fd00:2::/48","mtu":1280,"importTargets":["64512:1"],"exportTargets":["65000:7"]}`,
	}, "\n"); got != want {
		t.Errorf("Connect gave\n%s\nwant\n%s", got, want)
	}
	next, err := Apply(in, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := leakLines(next.Leaks()), "blue > red 65000:7\nred > blue 64512:1"; got != want {
		t.Errorf("the leaks are\n%s\nwant\n%s", got, want)
	}
	if got, want := routeLines(next.LeakedRoutes()), "blue 10.1.0.1/32 via a from red\nred 10.2.0.1/32 via b from blue"; got != want {
		t.Errorf("the leaked routes are\n%s\nwant\n%s", got, want)
	}
	again, err := next.Connect("blue", "red")
	if err != nil {
		t.Fatal(err)
	}
	if after, err := Apply(next, again, nil); err != nil {
		t.Fatal(err)
	} else if put, gone := Changed(next, after); len(put) != 0 || len(gone) != 0 {
		t.Errorf("connecting two connected VRFs changed %+v, %+v", put, gone)
	}

	if _, err := next.Connect("red", "red"); !errors.Is(err, ErrInvalid) {
		t.Errorf("connecting a VRF to itself: %v", err)
	}
	if _, err := next.Connect("red", "green"); !errors.Is(err, ErrNotFound) {
		t.Errorf("connecting a VRF that does not exist: %v", err)
	}
}

func TestRouteTargetsReject(t *testing.T) {
	many := make([]string, MaxRouteTargets+1)
	for i := range many {
		many[i] = fmt.Sprintf("%q", fmt.Sprintf("64512:%d", i))
	}
	for _, c := range []struct{ spec, want string }{
		{`{"importTargets": ["red"]}`, `VRF "red": importTargets: route target "red" is not ASN:NUMBER or IPV4:NUMBER`},
		{`{"exportTargets": ["0:7"]}`, `VRF "red": exportTargets: route target "0:7": AS number 0 is reserved`},
		{`{"exportTargets": ["64512:7", "64512:007"]}`, `VRF "red": exportTargets lists the route target 64512:7 twice`},
		{`{"importTargets": [` + strings.Join(many, ",") + `]}`, `VRF "red": importTargets holds 33 route targets, at most 32`},
		{`{"importTargets": "64512:7"}`, `VRF "red": spec: json: cannot unmarshal string`},
	} {
		if _, err := Apply(New(), doc(res(KindVRF, "red", c.spec)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.spec, err, c.want)
		}
	}
}

// A Node has at most MaxPeerRoutes routes to one peer: here the address of x and the outside
// prefixes of its 16 1:1 NAT rules leak into the VRF of y.
func TestPeerRoutesAreBounded(t *testing.T) {
	rs := []Resource{
		res(KindVRF, "e", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"]}`),
		res(KindVRF, "i", `{"id": 2, "ula": "fd00:2::/48", "importTargets": ["64512:1"]}`),
		res(KindNetwork, "e-lan", `{"vrf": "e", "ipv4Pool": "10.5.0.0/24"}`),
		res(KindNode, "x", `{"publicKey": "`+key1+`", "vrfs": ["e"]}`),
		res(KindNode, "y", `{"publicKey": "`+key2+`", "vrfs": ["i"]}`),
	}
	for k := range MaxNATRules {
		rs = append(rs, nat(fmt.Sprintf("x-%02d", k), "e", "x", fmt.Sprintf("192.168.%d.0/24", k), fmt.Sprintf("10.200.%d.0/24", k)))
	}
	if _, err := Apply(New(), doc(rs...), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(),
		`Node "y": 17 routes lead to its peer "x", the outside prefixes of the 1:1 NAT rules of the peer with the routes that leaks add, and the control protocol carries at most 16`) {
		t.Errorf("17 leaked routes to one peer: %v", err)
	}
	if _, err := Apply(New(), doc(rs[:len(rs)-1]...), nil); err != nil {
		t.Errorf("16 leaked routes to one peer: %v", err)
	}
}
