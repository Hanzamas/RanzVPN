package desired

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// zoneText writes the zone of the Vrf object vrf in the state s as its suffix, then one line per
// record: its name and its addresses; "off" for a Vrf without a zone, "none" for no Vrf object.
func zoneText(s State, vrf string) string {
	o, ok := s[Key{controlpb.Kind_KIND_VRF, vrf}]
	if !ok {
		return "none"
	}
	z := o.GetVrf().GetDns()
	if z == nil {
		return "off"
	}
	lines := []string{z.GetSuffix()}
	for _, r := range z.GetRecords() {
		line := r.GetName()
		for _, b := range r.GetAddresses() {
			a, _ := netip.AddrFromSlice(b)
			line += " " + a.String()
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// Each member of a VRF with overlay DNS on gets its zone in the Vrf object (SDN-11): the suffix and
// the DnsRecord resources of the VRF, each with the bytes of its addresses, so the same name answers
// different hosts in two VRFs. A VRF with overlay DNS off has no zone, and a node that is no member
// of a VRF gets no zone of it.
func TestCompileZones(t *testing.T) {
	states := compile(t,
		res("VRF", "red", `{"id": 101, "ula": "fd00:101::/48", "dns": true}`),
		res("VRF", "blue", `{"id": 202, "ula": "fd00:202::/48", "dns": true, "dnsSuffix": "blue.corp.example"}`),
		res("VRF", "green", `{"id": 303, "ula": "fd00:303::/48"}`),
		res("Network", "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24", "ipv6Pool": "fd00:101:0:1::/64"}`),
		res("Network", "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res("Node", "files-a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
		res("Node", "files-b", `{"publicKey": "`+key2+`", "vrfs": ["blue"]}`),
		res("Node", "laptop", `{"publicKey": "`+key3+`", "vrfs": ["red", "blue", "green"]}`),
		res("DnsRecord", "red-files", `{"vrf": "red", "name": "fileserver", "node": "files-a"}`),
		res("DnsRecord", "blue-files", `{"vrf": "blue", "name": "fileserver", "node": "files-b"}`),
		res("DnsRecord", "printer", `{"vrf": "blue", "name": "printer.hq", "addresses": ["192.168.7.20"]}`),
	)
	red := "red.ranz.internal\nfileserver 10.1.0.1 fd00:101:0:1::1"
	blue := "blue.corp.example\nfileserver 10.2.0.1\nprinter.hq 192.168.7.20"
	for _, c := range []struct{ node, vrf, want string }{
		{"laptop", "red", red},
		{"laptop", "blue", blue},
		{"laptop", "green", "off"},
		{"files-a", "red", red},
		{"files-a", "blue", "none"},
		{"files-b", "blue", blue},
	} {
		if got := zoneText(states[c.node], c.vrf); got != c.want {
			t.Errorf("%s: the zone of %s is\n%s\nwant\n%s", c.node, c.vrf, got, c.want)
		}
	}
}
