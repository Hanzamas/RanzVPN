package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// natBase applies three VRFs and three Nodes, with the resources of more: red and blue both use
// 10.0.0.0/24 and green 10.1.0.0/24; branch-1 is in all three, branch-2 in red with the LAN
// 192.168.7.0/24 behind it, and lab-1 in blue and green.
func natBase(t *testing.T, more ...Resource) (Intent, error) {
	t.Helper()
	rs := []Resource{
		res(KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48"}`),
		res(KindVRF, "blue", `{"id": 202, "ula": "fd00:202::/48"}`),
		res(KindVRF, "green", `{"id": 303, "ula": "fd00:303::/48"}`),
		res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd00:101:0:1::/64"}`),
		res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "green-lan", `{"vrf": "green", "ipv4Pool": "10.1.0.0/24"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["red", "blue", "green"]}`),
		res(KindNode, "branch-2", `{"publicKey": "`+key2+`", "vrfs": ["red"], "lanSubnets": {"red": ["192.168.7.0/24"]}}`),
		res(KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["blue", "green"]}`),
	}
	return Apply(New(), doc(append(rs, more...)...), nil)
}

func nat(name, vrf, node, inside, outside string) Resource {
	return res(KindNAT, name, fmt.Sprintf(`{"vrf": %q, "node": %q, "inside": %q, "outside": %q}`, vrf, node, inside, outside))
}

// ruleLines returns the rules as "vrf inside > outside", one per rule.
func ruleLines(rules []NATRule) string {
	var lines []string
	for _, r := range rules {
		lines = append(lines, r.VRF+" "+r.Inside.String()+" > "+r.Outside.String())
	}
	return strings.Join(lines, "\n")
}

// A NAT resource is a rule of a VRF that a Node of it applies: it is kept in its one form, reads
// back from the stored resources, and comes after the Controllers.
func TestNATApplies(t *testing.T) {
	in, err := natBase(t,
		nat("branch-2-lan", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"),
		nat("branch-2-v6", "red", "branch-2", "FD00:0:7::/64", "fd00:101:0:0099::/64"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := in.NATs["branch-2-v6"], (NAT{VRF: "red", Node: "branch-2", Inside: "fd00:0:7::/64", Outside: "fd00:101:0:99::/64"}); got != want {
		t.Errorf("the completed NAT is %+v, want %+v", got, want)
	}
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	rs := in.Resources()
	if last := rs[len(rs)-1]; last.Kind != KindNAT || last.Name != "branch-2-v6" {
		t.Errorf("the last resource is %s %q, want the NATs last", last.Kind, last.Name)
	}
	if got, want := ruleLines(in.NATRules()["branch-2"]), "red 192.168.7.0/24 > 10.99.7.0/24\nred fd00:0:7::/64 > fd00:101:0:99::/64"; got != want {
		t.Errorf("branch-2 applies\n%s\nwant\n%s", got, want)
	}
}

func TestNATRejects(t *testing.T) {
	for _, c := range []struct {
		rs   []Resource
		want string
	}{
		{[]Resource{nat("n", "lab", "branch-2", "192.168.7.0/24", "10.99.7.0/24")}, `NAT "n": VRF "lab" does not exist`},
		{[]Resource{nat("n", "red", "nobody", "192.168.7.0/24", "10.99.7.0/24")}, `NAT "n": Node "nobody" does not exist`},
		{[]Resource{nat("n", "red", "lab-1", "192.168.7.0/24", "10.99.7.0/24")}, `NAT "n": Node "lab-1" is not a member of VRF "red"`},
		{[]Resource{nat("n", "red", "branch-2", "192.168.7.1/24", "10.99.7.0/24")}, `NAT "n": inside: "192.168.7.1/24" has host bits set, the prefix is 192.168.7.0/24`},
		{[]Resource{nat("n", "red", "branch-2", "x", "10.99.7.0/24")}, `NAT "n": inside: netip.ParsePrefix("x")`},
		{[]Resource{nat("n", "red", "branch-2", "::ffff:192.168.7.0/120", "10.99.7.0/24")}, `is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix`},
		{[]Resource{nat("n", "red", "branch-2", "192.168.7.0/24", "0.0.0.0/0")}, `NAT "n": outside: "0.0.0.0/0" is the default route`},
		{[]Resource{nat("n", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/25")}, `NAT "n": the inside 192.168.7.0/24 and the outside 10.99.7.0/25 are not of one family and length`},
		{[]Resource{nat("n", "red", "branch-2", "192.168.7.0/24", "fd00:101:0:99::/120")}, `are not of one family and length`},
		{[]Resource{nat("n", "red", "branch-2", "10.99.7.0/24", "10.99.7.0/24")}, `NAT "n": the inside and the outside are the same prefix 10.99.7.0/24`},
		{[]Resource{nat("n", "red", "branch-2", "192.168.7.0/25", "10.0.0.128/25")}, `NAT "n": the outside 10.0.0.128/25 overlaps the pool 10.0.0.0/24 of Network "red-lan"`},
		{[]Resource{nat("n", "red", "branch-2", "fd00:7::/64", "fd00:101:0:1::/64")}, `the outside fd00:101:0:1::/64 overlaps the pool fd00:101:0:1::/64 of Network "red-lan"`},
		{[]Resource{nat("n", "red", "branch-2", "172.16.0.0/24", "192.168.7.0/24")}, `NAT "n": the outside 192.168.7.0/24 overlaps the LAN subnet 192.168.7.0/24 that Node "branch-2" advertises in VRF "red"`},
		{[]Resource{nat("n", "red", "branch-2", "fd00:7::/64", "fd00:101:0:ffff::/64")}, `NAT "n": the outside fd00:101:0:ffff::/64 overlaps fd00:101:0:ffff::/64, the /64 of the ULA of VRF "red" that 4via6 reserves`},
		{[]Resource{res(KindNAT, "n", `{"vrf": "red", "node": "branch-2", "inside": "192.168.7.0/24", "outside": "10.99.7.0/24", "ports": "80"}`)}, `NAT "n": spec: json: unknown field "ports"`},
		{[]Resource{nat("a", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"), nat("b", "red", "branch-1", "172.16.0.0/25", "10.99.7.128/25")},
			`NAT "a": the outside 10.99.7.0/24 overlaps the outside 10.99.7.128/25 of NAT "b" in VRF "red"`},
		{[]Resource{nat("a", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"), nat("b", "red", "branch-2", "192.168.7.0/25", "10.99.8.0/25")},
			`NAT "a": the inside 192.168.7.0/24 overlaps the inside 192.168.7.0/25 of NAT "b", a rule of Node "branch-2" in VRF "red" too`},
		{[]Resource{nat("a", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"), nat("b", "red", "branch-2", "10.99.7.0/24", "10.98.7.0/24")},
			`NAT "a": its prefixes 192.168.7.0/24 and 10.99.7.0/24 overlap the prefixes 10.99.7.0/24 and 10.98.7.0/24 of NAT "b", a rule of Node "branch-2" in VRF "red" too`},
	} {
		_, err := natBase(t, c.rs...)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: the error is %v, want one with %q", c.rs, err, c.want)
		}
	}
	// Two Nodes may each map their own LAN to one inside prefix, and rules of other VRFs never meet
	if _, err := natBase(t, nat("a", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"), nat("b", "red", "branch-1", "192.168.7.0/24", "10.99.8.0/24"),
		nat("c", "green", "branch-1", "192.168.7.0/24", "10.99.7.0/24")); err != nil {
		t.Errorf("two Nodes with one inside prefix, and one outside prefix in two VRFs: %v", err)
	}
}

// A Node applies at most MaxNATRules rules, the 4via6 of its overlapping VRFs counted.
func TestNATRulesOfANodeAreBounded(t *testing.T) {
	var rs []Resource
	for i := range MaxNATRules - 1 {
		rs = append(rs, nat(fmt.Sprintf("n%02d", i), "green", "branch-1", fmt.Sprintf("192.168.%d.0/24", i), fmt.Sprintf("10.200.%d.0/24", i)))
	}
	if _, err := natBase(t, rs...); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "branch-1": 17 1:1 NAT rules with the 4via6 of its VRFs, and the control protocol carries at most 16`) {
		t.Errorf("15 rules of branch-1 with the 4via6 of red and blue: %v", err)
	}
	if _, err := natBase(t, rs[1:]...); err != nil {
		t.Errorf("14 rules of branch-1 with the 4via6 of red and blue: %v", err)
	}
}

// A VRF or a Node that a NAT uses cannot be deleted; the NAT can, and then they can.
func TestDeleteNAT(t *testing.T) {
	in, err := natBase(t, nat("branch-2-lan", "red", "branch-2", "192.168.7.0/24", "10.99.7.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindVRF, "red"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `NAT "branch-2-lan"`) {
		t.Errorf("deleting the VRF of a NAT: %v", err)
	}
	if _, err := Delete(in, KindNode, "branch-2"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "branch-2" is used by NAT "branch-2-lan"`) {
		t.Errorf("deleting the Node of a NAT: %v", err)
	}
	if _, err := Delete(in, KindNAT, "other"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a NAT that does not exist: %v", err)
	}
	next, err := Delete(in, KindNAT, "branch-2-lan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(next, KindNode, "branch-2"); err != nil {
		t.Errorf("deleting the Node once its NAT is gone: %v", err)
	}
	if _, ok := in.NATs["branch-2-lan"]; !ok {
		t.Error("Delete changed the intent it was given")
	}
}

// The 4via6 of #176: a Node in two VRFs whose IPv4 ranges overlap applies the 4via6 of each, from
// the /96 at the start of the last /64 of the ULA of the VRF to 0.0.0.0/0, so 10.0.0.5 of red and
// 10.0.0.5 of blue are two addresses; a Node whose VRFs do not overlap applies none.
func TestFourViaSix(t *testing.T) {
	in, err := natBase(t)
	if err != nil {
		t.Fatal(err)
	}
	rules := in.NATRules()
	if got, want := ruleLines(rules["branch-1"]), "blue fd00:202:0:ffff::/96 > 0.0.0.0/0\nred fd00:101:0:ffff::/96 > 0.0.0.0/0"; got != want {
		t.Errorf("branch-1 (red and blue on 10.0.0.0/24, green on 10.1.0.0/24) applies\n%s\nwant\n%s", got, want)
	}
	for _, node := range []string{"branch-2", "lab-1"} {
		if got := rules[node]; len(got) != 0 {
			t.Errorf("%s, in VRFs that do not overlap, applies\n%s", node, ruleLines(got))
		}
	}
	red, blue := netip.MustParsePrefix("fd00:101::/48"), netip.MustParsePrefix("fd00:202::/48")
	a := netip.MustParseAddr("10.0.0.5")
	if got, want := FourViaSixAddr(red, a), netip.MustParseAddr("fd00:101:0:ffff::a00:5"); got != want {
		t.Errorf("the 4via6 address of %s in red is %s, want %s", a, got, want)
	}
	if got, want := FourViaSixAddr(blue, a), netip.MustParseAddr("fd00:202:0:ffff::a00:5"); got != want {
		t.Errorf("the 4via6 address of %s in blue is %s, want %s", a, got, want)
	}
	if got := FourViaSixPrefix(red); got != netip.MustParsePrefix("fd00:101:0:ffff::/96") || !FourViaSix(red).Contains(got.Addr()) {
		t.Errorf("the 4via6 /96 of red is %s, not the start of %s", got, FourViaSix(red))
	}
	if p, b := FourViaSixPrefix(netip.MustParsePrefix("fd00:101::/56")), FourViaSixAddr(red, netip.MustParseAddr("fd00::5")); p.IsValid() || b.IsValid() {
		t.Errorf("the 4via6 of a /56 is %s, the one of an IPv6 address %s", p, b)
	}

	// An outside prefix in green on blue's range makes green and blue overlap
	in, err = natBase(t, nat("lab-1-lan", "green", "lab-1", "192.168.9.0/25", "10.0.0.0/25"))
	if err != nil {
		t.Fatal(err)
	}
	rules = in.NATRules()
	if got, want := ruleLines(rules["lab-1"]), "blue fd00:202:0:ffff::/96 > 0.0.0.0/0\ngreen 192.168.9.0/25 > 10.0.0.0/25\ngreen fd00:303:0:ffff::/96 > 0.0.0.0/0"; got != want {
		t.Errorf("lab-1 applies\n%s\nwant\n%s", got, want)
	}
	if got := len(rules["branch-1"]); got != 3 {
		t.Errorf("branch-1 applies\n%s\nwant the 4via6 of its three VRFs", ruleLines(rules["branch-1"]))
	}
}

// The ULA of a VRF that declares none comes from crypto/rand: a ULA /48 of its own for each VRF,
// with its 4via6 /64 at its end.
func TestULAIsRandomPerVRF(t *testing.T) {
	seen := map[netip.Prefix]string{}
	for round := range 2 {
		in, err := Apply(New(), doc(res(KindVRF, "a", `{}`), res(KindVRF, "b", `{}`)), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a", "b"} {
			ula, err := ParseULA(in.VRFs[name].ULA)
			if err != nil {
				t.Fatalf("round %d, VRF %q: %v", round, name, err)
			}
			if other, ok := seen[ula]; ok {
				t.Errorf("round %d, VRF %q drew the ULA %s of %s", round, name, ula, other)
			}
			seen[ula] = fmt.Sprintf("VRF %q of round %d", name, round)
			a := ula.Addr().As16()
			if got := FourViaSix(ula); got != netip.PrefixFrom(netip.AddrFrom16([16]byte{a[0], a[1], a[2], a[3], a[4], a[5], 0xff, 0xff}), 64) {
				t.Errorf("the 4via6 /64 of %s is %s", ula, got)
			}
		}
	}
}
