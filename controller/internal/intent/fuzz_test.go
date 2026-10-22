package intent

import (
	"bytes"
	"net/netip"
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

// FuzzParseDocument reads the input as an intent document, in JSON or YAML as `ranz apply -f`,
// `ranz import -f` and the API take one (ParseDocument), and applies a document that parses to an
// empty intent (Apply) and as the whole intent of one (Replace, the import), which complete and
// check every resource. The ULAs they draw come from a reader of zeros, so a failing input fails
// again. An intent that is applied reads back from its resources, reports its pools and routes,
// and holds no address in a LAN subnet of its VRF.
func FuzzParseDocument(f *testing.F) {
	f.Add([]byte(docJSON))
	f.Add([]byte(docYAML))
	f.Add([]byte(ipamJSON))
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
			in.Pools()
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
// ULA of a VRF (ParseULA), the pools of a Network (ParsePool), the public key of a Node (ParseKey)
// and its relay address (ParseRelay).
func FuzzParseValues(f *testing.F) {
	for _, s := range []string{"fd12:3456:789a::/48", "10.0.0.0/24", "2001:db8::/64", key1, "192.0.2.1:4000", "[2001:db8::1]:4000", "[::ffff:192.0.2.1]:1"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
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
	})
}
