package intent

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// prefixText returns prefixes as text, separated by spaces.
func prefixText(prefixes []netip.Prefix) string {
	text := make([]string, len(prefixes))
	for i, p := range prefixes {
		text[i] = p.String()
	}
	return strings.Join(text, " ")
}

// distinctSources returns n different addresses, as the entries of a list of source prefixes.
func distinctSources(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String()
	}
	return out
}

// A list of source prefixes takes prefixes and single addresses, writes each as its prefix and
// keeps the order of the list.
func TestParseSources(t *testing.T) {
	for _, c := range []struct {
		list []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"203.0.113.0/24", "2001:db8::/32"}, "203.0.113.0/24 2001:db8::/32"},
		{[]string{"192.168.0.0/16", "10.0.0.0/8"}, "192.168.0.0/16 10.0.0.0/8"},
		{[]string{"203.0.113.7", "2001:DB8::1"}, "203.0.113.7/32 2001:db8::1/128"},
		{[]string{"::ffff:203.0.113.7"}, "203.0.113.7/32"},
		{[]string{"0.0.0.0/0", "::/0"}, "0.0.0.0/0 ::/0"},
	} {
		got, err := ParseSources(c.list)
		if err != nil {
			t.Errorf("%q: %v", c.list, err)
			continue
		}
		if text := prefixText(got); text != c.want {
			t.Errorf("%q gave %q, want %q", c.list, text, c.want)
		}
	}
	if _, err := ParseSources(distinctSources(MaxSources)); err != nil {
		t.Errorf("a list of %d entries: %v", MaxSources, err)
	}
}

// A list of source prefixes with an entry that is no prefix, one with host bits set, an
// IPv4-mapped IPv6 prefix, an entry twice or too many entries is refused, and the error names
// each entry that it refuses.
func TestParseSourcesRefuses(t *testing.T) {
	for _, c := range []struct {
		list []string
		want string
	}{
		{[]string{"nowhere"}, `source "nowhere" is neither a prefix nor an address`},
		{[]string{""}, `source "" is neither a prefix nor an address`},
		{[]string{"203.0.113.0/33"}, `source "203.0.113.0/33" is neither a prefix nor an address`},
		{[]string{"fe80::1%eth0"}, `source "fe80::1%eth0" is neither a prefix nor an address`},
		{[]string{"fe80::%eth0/64"}, `source "fe80::%eth0/64" is neither a prefix nor an address`},
		{[]string{"203.0.113.5/24"}, `source "203.0.113.5/24" has host bits set, the prefix is 203.0.113.0/24`},
		{[]string{"::ffff:203.0.113.0/120"}, `source "::ffff:203.0.113.0/120" is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix`},
		{[]string{"203.0.113.0/24", "203.0.113.0/24"}, `source "203.0.113.0/24" is listed twice`},
		{[]string{"203.0.113.7", "203.0.113.7/32"}, `source "203.0.113.7/32" is listed twice`},
		{[]string{"a", "203.0.113.5/24"}, `source "a" is neither a prefix nor an address; source "203.0.113.5/24" has host bits set`},
		{distinctSources(MaxSources + 1), "257 source prefixes are more than the 256 that a list holds"},
	} {
		if got, err := ParseSources(c.list); err == nil || !strings.Contains(err.Error(), c.want) || got != nil {
			t.Errorf("%q: the result is %v and %v, want no prefixes and the error %q", c.list, got, err, c.want)
		}
	}
}

// The address of a remote address is the one that the prefixes are matched against: without its
// port, its IPv6 zone, and the IPv4-mapped form of an IPv4 address.
func TestSourceAddr(t *testing.T) {
	for _, c := range []struct {
		remote string
		want   string
	}{
		{"203.0.113.7:50000", "203.0.113.7"},
		{"[2001:db8::7]:50000", "2001:db8::7"},
		{"[fe80::1%eth0]:50000", "fe80::1"},
		{"[::ffff:203.0.113.7]:50000", "203.0.113.7"},
		{"203.0.113.7", "203.0.113.7"},
		{"2001:db8::7", "2001:db8::7"},
		{"fe80::1%eth0", "fe80::1"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"127.0.0.1:1", "127.0.0.1"},
		{"[::1]:1", "::1"},
		{"", ""},
		{"pipe", ""},
		{"203.0.113.7:http", ""},
		{"example.com:443", ""},
	} {
		a, ok := SourceAddr(c.remote)
		if ok != (c.want != "") {
			t.Errorf("SourceAddr(%q) reports %v, want %v", c.remote, ok, c.want != "")
			continue
		}
		if ok && a.String() != c.want {
			t.Errorf("SourceAddr(%q) = %s, want %q", c.remote, a, c.want)
		}
		if !ok && a.IsValid() {
			t.Errorf("SourceAddr(%q) reports no address and returns %s", c.remote, a)
		}
	}
}

// The prefixes of a list hold an address of their family only, and no list holds the invalid
// address.
func TestContainsSource(t *testing.T) {
	prefixes, err := ParseSources([]string{"203.0.113.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		remote string
		want   bool
	}{
		{"203.0.113.255:1", true},
		{"203.0.114.0:1", false},
		{"[2001:db8:ffff::1]:1", true},
		{"[2001:db9::1]:1", false},
		{"[::ffff:203.0.113.9]:1", true},
		{"", false},
	} {
		a, _ := SourceAddr(c.remote)
		if got := ContainsSource(prefixes, a); got != c.want {
			t.Errorf("ContainsSource(%q) = %v, want %v", c.remote, got, c.want)
		}
	}
	if ContainsSource(nil, netip.MustParseAddr("203.0.113.1")) {
		t.Error("an empty list holds an address")
	}
}

// A Node is refused by the first Network, in name order, of a VRF that it joins whose source
// prefixes do not hold its address: a Network of another VRF, one that lists none, a Node that
// joins no VRF and a Node that does not exist refuse nothing.
func TestEnrolRefusedBy(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 11, "ula": "fd12:3456:789b::/48"}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "enrolSources": ["203.0.113.0/24", "2001:db8::/32"]}`),
		res(KindNetwork, "corp-dmz", `{"vrf": "corp", "enrolSources": ["203.0.113.64/26"]}`),
		res(KindNetwork, "corp-open", `{"vrf": "corp"}`),
		res(KindNetwork, "lab-lan", `{"vrf": "lab", "enrolSources": ["198.51.100.0/24"]}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "lab-1", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
		res(KindNode, "loner", `{"publicKey": "`+key3+`"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		node    string
		remote  string
		network string
	}{
		{"branch-1", "203.0.113.70:4000", ""},
		{"branch-1", "[::ffff:203.0.113.70]:4000", ""},
		{"branch-1", "203.0.113.5:4000", "corp-dmz"},
		{"branch-1", "[2001:db8::1]:4000", "corp-dmz"},
		{"branch-1", "198.51.100.1:4000", "corp-dmz"},
		{"branch-1", "", "corp-dmz"},
		{"lab-1", "198.51.100.1:4000", ""},
		{"lab-1", "203.0.113.70:4000", "lab-lan"},
		{"loner", "198.51.100.1:4000", ""},
		{"ghost", "198.51.100.1:4000", ""},
	} {
		addr, _ := SourceAddr(c.remote)
		network, refused := in.EnrolRefusedBy(c.node, addr)
		if network != c.network || refused != (c.network != "") {
			t.Errorf("Node %q from %q is refused by %q (%v), want %q", c.node, c.remote, network, refused, c.network)
		}
	}

	open, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "corp-open", `{"vrf": "corp"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !in.HasEnrolSources() || open.HasEnrolSources() || New().HasEnrolSources() {
		t.Errorf("HasEnrolSources is %v for an intent with source prefixes, %v for one with a Network that lists none and %v for an empty one",
			in.HasEnrolSources(), open.HasEnrolSources(), New().HasEnrolSources())
	}
}

// The source prefixes of a Network are kept as prefixes in order, refused when they are wrong,
// stored and read back with the Network, and not shared with a copy of the intent.
func TestEnrolSourcesInTheIntent(t *testing.T) {
	base, err := Apply(New(), doc(res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	lan := res(KindNetwork, "lan", `{"vrf": "corp", "enrolSources": ["203.0.113.7", "10.0.0.0/8", "2001:DB8::/32"]}`)
	in, err := Apply(base, doc(lan), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(in.Networks["lan"].EnrolSources, " "); got != "10.0.0.0/8 2001:db8::/32 203.0.113.7/32" {
		t.Errorf("the source prefixes of the Network are %q, want them as prefixes in order", got)
	}
	if spec := string(in.Resources()[1].Spec); !strings.Contains(spec, `"enrolSources":["10.0.0.0/8","2001:db8::/32","203.0.113.7/32"]`) {
		t.Errorf("the stored Network is %s", spec)
	}

	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	again, err := Apply(in, doc(lan), nil)
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, again); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the same Network applied again changed the intent: put %+v, gone %+v", put, gone)
	}

	clone := in.Clone()
	clone.Networks["lan"].EnrolSources[0] = "changed"
	if got := in.Networks["lan"].EnrolSources[0]; got != "10.0.0.0/8" {
		t.Errorf("a copy of the intent shares the source prefixes of a Network with it: %q", got)
	}

	for _, c := range []struct {
		spec string
		want string
	}{
		{`{"vrf": "corp", "enrolSources": ["nowhere"]}`, `Network "lan": enrolSources: source "nowhere" is neither a prefix nor an address`},
		{`{"vrf": "corp", "enrolSources": ["10.0.0.1/8"]}`, `Network "lan": enrolSources: source "10.0.0.1/8" has host bits set, the prefix is 10.0.0.0/8`},
		{`{"vrf": "corp", "enrolSources": ["10.0.0.0/8", "10.0.0.0/8"]}`, `Network "lan": enrolSources: source "10.0.0.0/8" is listed twice`},
	} {
		if _, err := Apply(base, doc(res(KindNetwork, "lan", c.spec)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}
}
