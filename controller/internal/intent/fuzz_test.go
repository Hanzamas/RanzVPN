package intent

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The fuzz tests of the intent package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the controller workflow runs with go test -fuzz.

// ipamJSON is a document with the pools, the reservations, the pool threshold and the LAN
// subnets of IPAM (SDN-10), for the fuzz test to start from.
const ipamJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Network", "name": "lan", "spec": {"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64", "reserved": ["10.0.0.0/30", "fd12:3456:789a:1::/124"], "poolThreshold": 50}},
  {"kind": "Node", "name": "gw", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}}}
]}`

// natJSON is a document with two VRFs on one IPv4 range, a Node in both, which applies their
// 4via6, and a 1:1 NAT rule (SDN-6), for the fuzz test to start from.
const natJSON = `{"resources": [
  {"kind": "VRF", "name": "red", "spec": {"id": 101, "ula": "fd00:101::/48"}},
  {"kind": "VRF", "name": "blue", "spec": {"id": 202, "ula": "fd00:202::/48"}},
  {"kind": "Network", "name": "red-lan", "spec": {"vrf": "red", "ipv4Pool": "10.0.0.0/24"}},
  {"kind": "Network", "name": "blue-lan", "spec": {"vrf": "blue", "ipv4Pool": "10.0.0.0/24"}},
  {"kind": "Node", "name": "gw", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["red", "blue"]}},
  {"kind": "NAT", "name": "gw-lan", "spec": {"vrf": "red", "node": "gw", "inside": "192.168.1.0/24", "outside": "10.99.1.0/24"}}
]}`

// mimicJSON is a document with a Listener that has a mimic section of each decoy (SDN-94), for the fuzz test to start from.
const mimicJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Node", "name": "a", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "endpoints": [{"transport": "mimic", "address": "a.example.com:8443"}]}},
  {"kind": "Node", "name": "b", "spec": {"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"]}},
  {"kind": "Listener", "name": "edge-a", "spec": {"node": "a", "certificate": {"ksp": "AABBCCDDEEFF00112233445566778899AABBCCDD"},
    "mimic": {"listen": ":8443", "serverNames": ["www.example.com", "cdn.example.com"], "maxTimeDiffMs": 60000,
      "decoy": {"acme": {"cacheDir": "C:\\ProgramData\\Ranz\\mimic-acme", "email": "ops@example.com"}}}}},
  {"kind": "Listener", "name": "edge-b", "spec": {"node": "b", "port": 8443, "certificate": {"ksp": "AABBCCDDEEFF00112233445566778899AABBCCDD"},
    "mimic": {"listen": "[2001:db8::1]:443", "serverNames": ["site.example"], "decoy": {"mode": "borrow", "dest": "site.example:443"}}}}
]}`

// FuzzParseDocument reads the input as an intent document, in JSON or YAML as `ranz apply -f`,
// `ranz import -f` and the API take one (ParseDocument), and applies a document that parses to an
// empty intent (Apply) and as the whole intent of one (Replace, the import), which complete and
// check every resource. The ULAs they draw come from a reader of zeros, so a failing input fails
// again. An intent that is applied reads back from its resources, reports its pools and routes,
// and holds no address in a LAN subnet of its VRF; no Node of it applies more 1:1 NAT rules, and no
// zone of overlay DNS holds more records, than the control protocol carries.
func FuzzParseDocument(f *testing.F) {
	f.Add([]byte(docJSON))
	f.Add([]byte(docYAML))
	f.Add([]byte(ipamJSON))
	f.Add([]byte(natJSON))
	f.Add([]byte(policyJSON))
	f.Add([]byte(dnsJSON))
	f.Add([]byte(mimicJSON))
	f.Add([]byte(endpointJSON))
	f.Add([]byte(`{"resources": [{"kind": "Controller", "name": "c1", "spec": {}}]}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		doc, err := ParseDocument(b)
		if err != nil {
			return
		}
		in, err := Apply(New(), doc, bytes.NewReader(make([]byte, 4096)))
		if err == nil {
			if _, err := FromResources(in.Resources()); err != nil {
				t.Fatalf("an applied intent does not load from its own resources: %v", err)
			}
			_ = in.Pools()
			for node, rules := range in.NATRules() {
				if len(rules) > MaxNATRules {
					t.Fatalf("Node %q applies %d 1:1 NAT rules, more than %d", node, len(rules), MaxNATRules)
				}
			}
			// The zones of overlay DNS fit the control protocol (dns.go)
			for vrf := range in.VRFs {
				if _, records, _ := in.Zone(vrf); len(records) > MaxDNSRecords || slices.ContainsFunc(records, func(r ZoneRecord) bool { return len(r.Addresses) > MaxDNSAddresses }) {
					t.Fatalf("the zone of VRF %q has %d records, or a record with more than %d addresses", vrf, len(records), MaxDNSAddresses)
				}
			}
			// What the Endpoints compile to fits the control protocol too (publish.go; SDN-24)
			compiled := in.WithPublished()
			for node, rules := range compiled.NATRules() {
				if len(rules) > MaxNATRules {
					t.Fatalf("Node %q applies %d 1:1 NAT rules with its Endpoints, more than %d", node, len(rules), MaxNATRules)
				}
			}
			for vrf := range compiled.VRFs {
				if _, records, _ := compiled.Zone(vrf); len(records) > MaxDNSRecords {
					t.Fatalf("the zone of VRF %q has %d records with its Endpoints, more than %d", vrf, len(records), MaxDNSRecords)
				}
			}
			// A mimic section that is applied fits the control protocol (listener_mimic.go; SDN-94)
			for name, l := range in.Listeners {
				if m := l.Mimic; m != nil && (len(m.ServerNames) == 0 || len(m.ServerNames) > MaxMimicServerNames || m.MaxTimeDiffMs < 1 || m.MaxTimeDiffMs > MaxMimicMaxTimeDiffMs ||
					len(m.Listen) > MaxAddress) {
					t.Fatalf("Listener %q has the mimic section %+v, which the control protocol does not carry", name, *m)
				}
			}
			for _, r := range in.Routes() {
				for name, n := range in.Nodes {
					for _, held := range []map[string]string{n.Addresses, n.IPv6Addresses} {
						for network, s := range held {
							if a, err := netip.ParseAddr(s); err == nil && in.Networks[network].VRF == r.VRF && r.Prefix.Contains(a) {
								t.Fatalf("Node %q holds %s in Network %q, inside the LAN subnet %s that Node %q advertises in VRF %q", name, a, network, r.Prefix, r.Via, r.VRF)
							}
						}
					}
				}
			}
		}
		// The import of the same document over what Apply made
		_, _ = Replace(in, doc, bytes.NewReader(make([]byte, 4096)))
	})
}

// FuzzParseValues reads the input as each value of a resource that has a parser of its own: the
// ULA of a VRF (ParseULA) and its route targets (ParseRouteTarget, whose one form parses as
// itself), the pools of a Network (ParsePool), the public key of a Node (ParseKey) and its relay
// address (ParseRelay), and, inside the package, a reservation of a Network (parseReserved), a LAN
// subnet of a Node (parseLAN), a prefix of a 1:1 NAT rule (parseNATPrefix), and the DNS suffix of a
// VRF, the name of a DnsRecord (checkDNSName) and its addresses (parseDNSAddress), the address of an
// endpoint of a Node (ParseEndpointAddress, SDN-93), whose host and port write back as the same address,
// and the decoy of a Listener in its one form (canonicalDecoy, checkDecoy; AUD1-DT-4 #452).
func FuzzParseValues(f *testing.F) {
	for _, s := range []string{"fd12:3456:789a::/48", "10.0.0.0/24", "2001:db8::/64", key1, "192.0.2.1:4000", "[2001:db8::1]:4000", "[::ffff:192.0.2.1]:1",
		"10.0.0.1", "192.168.1.0/24", "0.0.0.0/0", "::ffff:10.0.0.0/120", "65000:100", "064512:007", "4200000000:65535",
		"fileserver.default.ranz.internal", "a-b.c1", "fe80::1%eth0", "::",
		"hub.example.com:443", "HUB.Example.com:0443", "hub.example.com", "hub:443:80", "[hub]:443", "300.1.1.1:443", "[::ffff:0.0.0.0]:1", "[fe80::1%eth0]:443",
		"127.0.0.1:8080", "[::1]:8080", "[::ffff:127.0.0.2]:80", "[::1%lo]:80"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if rt, err := ParseRouteTarget(s); err == nil {
			if again, err := ParseRouteTarget(rt); err != nil || again != rt {
				t.Errorf("ParseRouteTarget(%q) = %q, which parses as %q, %v", s, rt, again, err)
			}
		}
		if p, err := ParseULA(s); err == nil && (p.Bits() != 48 || !p.Addr().Is6()) {
			t.Errorf("ParseULA(%q) = %s, not an IPv6 /48", s, p)
		}
		for _, family := range []int{4, 6} {
			if p, err := ParsePool(s, family); err == nil && p != p.Masked() {
				t.Errorf("ParsePool(%q, %d) = %s, with host bits", s, family, p)
			}
		}
		if k, err := ParseKey(s); err == nil && len(k) != KeySize {
			t.Errorf("ParseKey(%q) is %d bytes, not %d", s, len(k), KeySize)
		}
		if ap, err := ParseRelay(s); err == nil && (ap.Port() == 0 || ap.Addr().Is4In6()) {
			t.Errorf("ParseRelay(%q) = %s", s, ap)
		}
		if p, err := parseReserved(s); err == nil && (!p.IsValid() || p != p.Masked()) {
			t.Errorf("parseReserved(%q) = %s, not a prefix without host bits", s, p)
		}
		if p, err := parseLAN(s); err == nil && (p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6()) {
			t.Errorf("parseLAN(%q) = %s", s, p)
		}
		if p, err := parseNATPrefix(s); err == nil && (p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6()) {
			t.Errorf("parseNATPrefix(%q) = %s", s, p)
		}
		if a, err := parseDNSAddress(s); err == nil && (a.Zone() != "" || a.Is4In6() || a.IsUnspecified()) {
			t.Errorf("parseDNSAddress(%q) = %s", s, a)
		}
		if checkDNSName(s) == nil && (len(s) > MaxDNSName || strings.ToLower(s) != s || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".")) {
			t.Errorf("checkDNSName(%q) takes it", s)
		}
		if host, port, err := ParseEndpointAddress(s); err == nil {
			back := net.JoinHostPort(host, strconv.Itoa(int(port)))
			again, p, err := ParseEndpointAddress(back)
			if host == "" || port == 0 || len(back) > MaxAddress || err != nil || again != host || p != port {
				t.Errorf("ParseEndpointAddress(%q) = %q, %d, which write back as %q and parse as %q, %d, %v", s, host, port, back, again, p, err)
			}
		}
		// A decoy that the controller takes is, in the form that it sends, what the node takes too: an address of
		// 127.0.0.0/8 or ::1 without a zone and a port other than 0, in its one form, that fits the field of the node
		if d := canonicalDecoy(s); d != "" && checkDecoy(d) == nil {
			ap, err := netip.ParseAddrPort(d)
			a := ap.Addr()
			loopback := (a.Is4() && a.As4()[0] == 127) || a == netip.IPv6Loopback()
			if err != nil || ap.String() != d || ap.Port() == 0 || a.Zone() != "" || !loopback || len(d) > MaxListenerDecoy {
				t.Errorf("the decoy %q is sent as %q", s, d)
			}
		}
	})
}
