package intent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// key4 is a fourth Node key, the public key of the relay of the controller conformance tests.
const key4 = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="

// dnsJSON is a document with overlay DNS on in two VRFs, a Node in both and a DnsRecord in each
// with the same name (SDN-11), for the fuzz test to start from.
const dnsJSON = `{"resources": [
  {"kind": "VRF", "name": "red", "spec": {"id": 101, "ula": "fd00:101::/48", "dns": true}},
  {"kind": "VRF", "name": "blue", "spec": {"id": 202, "ula": "fd00:202::/48", "dns": true, "dnsSuffix": "blue.corp.example"}},
  {"kind": "Network", "name": "red-lan", "spec": {"vrf": "red", "ipv4Pool": "10.1.0.0/24"}},
  {"kind": "Network", "name": "blue-lan", "spec": {"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}},
  {"kind": "Node", "name": "gw", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["red", "blue"]}},
  {"kind": "DnsRecord", "name": "red-files", "spec": {"vrf": "red", "name": "fileserver", "node": "gw"}},
  {"kind": "DnsRecord", "name": "blue-files", "spec": {"vrf": "blue", "name": "fileserver", "addresses": ["10.2.0.20", "fd00:202::20"]}}
]}`

// dnsBase applies two VRFs with overlay DNS on, red (10.1.0.0/24 and fd00:101:0:1::/64) and blue
// (10.2.0.0/24), and green with it off, and three Nodes: files-a in red, files-b in blue and
// laptop in red and blue; with the resources of more.
func dnsBase(t *testing.T, more ...Resource) (Intent, error) {
	t.Helper()
	rs := []Resource{
		res(KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48", "dns": true}`),
		res(KindVRF, "blue", `{"id": 202, "ula": "fd00:202::/48", "dns": true}`),
		res(KindVRF, "green", `{"id": 303, "ula": "fd00:303::/48"}`),
		res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24", "ipv6Pool": "fd00:101:0:1::/64"}`),
		res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(KindNetwork, "green-lan", `{"vrf": "green", "ipv4Pool": "10.3.0.0/24"}`),
		res(KindNode, "files-a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
		res(KindNode, "files-b", `{"publicKey": "`+key2+`", "vrfs": ["blue"]}`),
		res(KindNode, "laptop", `{"publicKey": "`+key3+`", "vrfs": ["red", "blue", "green"]}`),
	}
	return Apply(New(), doc(append(rs, more...)...), nil)
}

func dnsRecord(name, spec string) Resource {
	return res(KindDNSRecord, name, spec)
}

// zoneLines writes the zone of a VRF as its suffix, then one line per record: its name and its
// addresses.
func zoneLines(in Intent, vrf string) string {
	suffix, records, ok := in.Zone(vrf)
	if !ok {
		return "off"
	}
	lines := []string{suffix}
	for _, r := range records {
		line := r.Name
		for _, a := range r.Addresses {
			line += " " + a.String()
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// The same name means different hosts in two VRFs: fileserver of red answers the addresses of
// files-a there, fileserver of blue the addresses of files-b there, each under the suffix of its
// VRF. A record that declares no name has the name of its resource, and its addresses are kept in
// their one form. The records read back from the stored resources and come last.
func TestDNSZones(t *testing.T) {
	in, err := dnsBase(t,
		dnsRecord("red-files", `{"vrf": "red", "name": "fileserver", "node": "files-a"}`),
		dnsRecord("blue-files", `{"vrf": "blue", "name": "fileserver", "node": "files-b"}`),
		dnsRecord("printer", `{"vrf": "blue", "addresses": ["192.168.7.20", "FD00:7::20"]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := zoneLines(in, "red"), "red.ranz.internal\nfileserver 10.1.0.1 fd00:101:0:1::1"; got != want {
		t.Errorf("the zone of red is\n%s\nwant\n%s", got, want)
	}
	if got, want := zoneLines(in, "blue"), "blue.ranz.internal\nfileserver 10.2.0.1\nprinter 192.168.7.20 fd00:7::20"; got != want {
		t.Errorf("the zone of blue is\n%s\nwant\n%s", got, want)
	}
	if got := zoneLines(in, "green"); got != "off" {
		t.Errorf("the zone of green, with overlay DNS off, is\n%s\nwant none", got)
	}
	if got, want := in.DNSRecords["printer"], "printer"; got.Name != want || got.Addresses[1] != "fd00:7::20" {
		t.Errorf("the completed record is %+v, want the name %q and its addresses in their one form", got, want)
	}
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	rs := in.Resources()
	if last := rs[len(rs)-1]; last.Kind != KindDNSRecord || last.Name != "red-files" {
		t.Errorf("the last resource is %s %q, want the DnsRecords last", last.Kind, last.Name)
	}
}

// A VRF declares the suffix of its zone. Two VRFs may share one while no Node joins both; a Node in
// two VRFs whose suffixes are the same or one under the other is refused, unless overlay DNS is off
// in one of them.
func TestDNSSuffix(t *testing.T) {
	shared := func(laptopVRFs string) (Intent, error) {
		return Apply(New(), doc(
			res(KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48", "dns": true, "dnsSuffix": "corp.example"}`),
			res(KindVRF, "blue", `{"id": 202, "ula": "fd00:202::/48", "dns": true, "dnsSuffix": "corp.example"}`),
			res(KindVRF, "lab", `{"id": 303, "ula": "fd00:303::/48", "dns": true, "dnsSuffix": "lab.corp.example"}`),
			res(KindVRF, "dark", `{"id": 404, "ula": "fd00:404::/48", "dnsSuffix": "corp.example"}`),
			res(KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.0.0.0/24"}`),
			res(KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.0.0.0/24"}`),
			res(KindNode, "files-a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
			res(KindNode, "files-b", `{"publicKey": "`+key2+`", "vrfs": ["blue"]}`),
			res(KindNode, "laptop", `{"publicKey": "`+key3+`", "vrfs": `+laptopVRFs+`}`),
			dnsRecord("red-files", `{"vrf": "red", "name": "fileserver", "node": "files-a"}`),
			dnsRecord("blue-files", `{"vrf": "blue", "name": "fileserver", "node": "files-b"}`),
		), nil)
	}
	in, err := shared(`["red", "dark"]`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := zoneLines(in, "red"), "corp.example\nfileserver 10.0.0.1"; got != want {
		t.Errorf("the zone of red is\n%s\nwant\n%s", got, want)
	}
	if got, want := zoneLines(in, "blue"), "corp.example\nfileserver 10.0.0.1"; got != want {
		t.Errorf("the zone of blue is\n%s\nwant\n%s", got, want)
	}
	for vrfs, want := range map[string]string{
		`["red", "blue"]`: `Node "laptop": VRF "blue" has the DNS suffix corp.example and VRF "red" the DNS suffix corp.example, the same or one under the other`,
		`["lab", "red"]`:  `Node "laptop": VRF "lab" has the DNS suffix lab.corp.example and VRF "red" the DNS suffix corp.example`,
	} {
		_, err := shared(vrfs)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
			t.Errorf("laptop in %s: err = %v, want %q", vrfs, err, want)
		}
	}
}

// Each case is applied over dnsBase, so a resource of it replaces the one of dnsBase.
func TestDNSRejects(t *testing.T) {
	base, err := dnsBase(t)
	if err != nil {
		t.Fatal(err)
	}
	var many []Resource
	for i := range MaxDNSRecords + 1 {
		many = append(many, dnsRecord(fmt.Sprintf("r%d", i), fmt.Sprintf(`{"vrf": "red", "addresses": ["10.9.0.%d"]}`, i+1)))
	}
	for _, c := range []struct {
		rs   []Resource
		want string
	}{
		{[]Resource{dnsRecord("r", `{"vrf": "lab", "addresses": ["10.9.0.1"]}`)}, `DnsRecord "r": VRF "lab" does not exist`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "name": "File", "addresses": ["10.9.0.1"]}`)}, `DnsRecord "r": name: "File" is not DNS labels separated by dots`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "name": "a..b", "addresses": ["10.9.0.1"]}`)}, `DnsRecord "r": name: "a..b" is not DNS labels`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "name": "` + strings.Repeat("a.", 64) + `a", "addresses": ["10.9.0.1"]}`)}, `is longer than 127 characters`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "name": "files-a", "addresses": ["10.9.0.1"]}`)}, `DnsRecord "r": "files-a" is the name of Node "files-a", which the zone of VRF "red" answers already`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "name": "x", "addresses": ["10.9.0.1"]}`), dnsRecord("s", `{"vrf": "red", "name": "x", "addresses": ["10.9.0.2"]}`)},
			`DnsRecord "s": the name "x" is already the name of DnsRecord "r" in VRF "red"`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "node": "files-a", "addresses": ["10.9.0.1"]}`)}, `DnsRecord "r": it names Node "files-a" and lists addresses`},
		{[]Resource{dnsRecord("r", `{"vrf": "red"}`)}, `DnsRecord "r": it names no Node and lists no address`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "node": "nobody"}`)}, `DnsRecord "r": Node "nobody" does not exist`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "node": "files-b"}`)}, `DnsRecord "r": Node "files-b" is not a member of VRF "red"`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["1", "2", "3", "4", "5", "6", "7", "8", "9"]}`)}, `DnsRecord "r": 9 addresses, and a name answers at most 8`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["10.9.0.300"]}`)}, `DnsRecord "r": address: ParseAddr("10.9.0.300")`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["fe80::1%eth0"]}`)}, `DnsRecord "r": address: "fe80::1%eth0" has a zone`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["::ffff:10.9.0.1"]}`)}, `is an IPv4-mapped IPv6 address: write it as an IPv4 address`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["0.0.0.0"]}`)}, `DnsRecord "r": address: "0.0.0.0" is the unspecified address`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["10.9.0.1", "10.9.0.1"]}`)}, `DnsRecord "r": the address 10.9.0.1 is listed twice`},
		{[]Resource{dnsRecord("r", `{"vrf": "red", "addresses": ["10.9.0.1"], "ttl": 5}`)}, `unknown field "ttl"`},
		{[]Resource{res(KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48", "dns": true, "dnsSuffix": "-corp.example"}`)}, `VRF "red": dnsSuffix: "-corp.example" is not DNS labels`},
		{many, `VRF "red": 17 DnsRecord resources, and the control protocol carries at most 16`},
	} {
		_, err := Apply(base, doc(c.rs...), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.rs, err, c.want)
		}
	}

	// A Node of a VRF whose only Network is an L2 one holds no address there to answer
	_, err = Apply(New(), doc(
		res(KindVRF, "lab", `{"id": 7, "ula": "fd00:7::/48", "dns": true}`),
		res(KindNetwork, "lab-l2", `{"vrf": "lab", "mode": "L2"}`),
		res(KindNode, "gw", `{"publicKey": "`+key4+`", "vrfs": ["lab"]}`),
		dnsRecord("r", `{"vrf": "lab", "node": "gw"}`),
	), nil)
	if want := `DnsRecord "r": Node "gw" holds no address in VRF "lab"`; !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want %q", err, want)
	}
}

// A record that names a Node answers at most MaxDNSAddresses of its addresses, and a name whose
// suffix makes it longer than a name of DNS is refused.
func TestDNSLimits(t *testing.T) {
	base, err := dnsBase(t)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("abcdefghi.", 12) + "abcdefg"
	longRed := res(KindVRF, "red", `{"id": 101, "ula": "fd00:101::/48", "dns": true, "dnsSuffix": "`+long+`"}`)
	in, err := Apply(base, doc(longRed), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.DNSSuffix("red"); got != long {
		t.Errorf("the suffix of red is %q, want %q", got, long)
	}
	_, err = Apply(base, doc(longRed, dnsRecord("r", `{"vrf": "red", "name": "`+long+`", "addresses": ["10.9.0.1"]}`)), nil)
	if want := `DnsRecord "r": ` + long + "." + long + ` is longer than 253 characters`; !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want %q", err, want)
	}

	var networks []Resource
	for i := range 5 {
		networks = append(networks, res(KindNetwork, fmt.Sprintf("red-%d", i), fmt.Sprintf(`{"vrf": "red", "ipv4Pool": "10.10.%d.0/24", "ipv6Pool": "fd00:101:0:1%d::/64"}`, i, i)))
	}
	in, err = Apply(base, doc(append(networks, dnsRecord("all", `{"vrf": "red", "node": "files-a"}`))...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, records, _ := in.Zone("red"); len(records) != 1 || len(records[0].Addresses) != MaxDNSAddresses {
		t.Errorf("the record of files-a, which holds 12 addresses in red, answers %v, want the first %d", records, MaxDNSAddresses)
	}
}

// A VRF or a Node that a DnsRecord uses cannot be deleted; the record can, and then they can. An
// import drops the records that its document leaves out.
func TestDNSDelete(t *testing.T) {
	in, err := dnsBase(t, dnsRecord("red-files", `{"vrf": "red", "name": "fileserver", "node": "files-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindNode, "files-a"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "files-a" is used by DnsRecord "red-files"`) {
		t.Errorf("deleting Node files-a: err = %v", err)
	}
	if _, err := Delete(in, KindVRF, "red"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `DnsRecord "red-files"`) {
		t.Errorf("deleting VRF red: err = %v", err)
	}
	if _, err := Delete(in, KindDNSRecord, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a DnsRecord that does not exist: err = %v", err)
	}
	next, err := Delete(in, KindDNSRecord, "red-files")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(next, KindNode, "files-a"); err != nil {
		t.Errorf("deleting Node files-a once no record names it: %v", err)
	}
	if _, ok := in.DNSRecords["red-files"]; !ok {
		t.Errorf("Delete changed the intent it was given")
	}

	var rs []Resource
	for _, r := range in.Resources() {
		if r.Kind != KindDNSRecord {
			rs = append(rs, r)
		}
	}
	imported, err := Replace(in, doc(rs...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.DNSRecords) != 0 {
		t.Errorf("the import kept the records %v that its document leaves out", imported.DNSRecords)
	}
}
