package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Overlay DNS (ADR-0028 decisions 6 to 8, SDN-11 #187). A VRF with overlay DNS on has a zone of
// its own: the stub resolver of each member Node answers it on the Node's addresses in the VRF,
// and NRPT rules on the Node's host send only the names under the suffix of the zone to it, so the
// host's own DNS keeps every other name. The name of each Node of the VRF answers that Node's
// addresses there, and a DnsRecord resource adds a name: the addresses of a Node of the VRF, or
// the addresses that it lists. A zone belongs to one VRF, so the same name means different hosts
// in different VRFs. Two VRFs may share a suffix unless a Node joins both: its host sends the
// names of one suffix to one stub resolver.

// KindDNSRecord is the kind of a name of the zone of a VRF.
const KindDNSRecord = "DnsRecord"

const (
	// DNSDomain is what the suffix of the zone of a VRF that declares none ends with, after the
	// name of the VRF: VRF default answers fileserver.default.ranz.internal. It lies under
	// internal, the top-level domain that ICANN reserved for private use, so no name of the
	// internet falls under it.
	DNSDomain = "ranz.internal"
	// MaxDNSName is the length of the longest suffix and of the longest name of a record: they
	// fit the 128-byte fields of the C node (proto/ranz/control/v1/control.options).
	MaxDNSName = 127
	// maxDNSFull is the length of the longest name of DNS, a name of a record with its suffix.
	maxDNSFull = 253
	// MaxDNSRecords is the most DnsRecord resources of one VRF: the zone of the control protocol
	// carries 16.
	MaxDNSRecords = 16
	// MaxDNSAddresses is the most addresses that one name of a zone answers: a record of the
	// control protocol carries 8.
	MaxDNSAddresses = 8
)

// DNSRecord is one name of the zone of a VRF (ADR-0028 decision 7).
type DNSRecord struct {
	VRF string `json:"vrf"`
	// Name is the name in the zone, relative to the suffix of the VRF: DNS labels separated by
	// dots. Left out, it is the name of the resource.
	Name string `json:"name,omitempty"`
	// Node is a Node of the VRF whose addresses there the name answers.
	Node string `json:"node,omitempty"`
	// Addresses are the IPv4 and IPv6 addresses that the name answers when it names no Node.
	Addresses []string `json:"addresses,omitempty"`
}

// ZoneRecord is a name of a zone with the addresses it answers (Zone).
type ZoneRecord struct {
	Name      string
	Addresses []netip.Addr
}

// DNSSuffix returns the suffix of the zone of the VRF vrf: the one that it declares, else its
// name followed by DNSDomain.
func (in Intent) DNSSuffix(vrf string) string {
	if s := in.VRFs[vrf].DNSSuffix; s != "" {
		return s
	}
	return vrf + "." + DNSDomain
}

// Zone returns the zone of the VRF vrf as its members get it: its suffix, and its DnsRecord
// resources ordered by name, each with the addresses it answers; ok is false while overlay DNS is
// off in the VRF. A record that names a Node answers the first MaxDNSAddresses addresses of that
// Node in the VRF, ordered by Network name, the IPv4 address of a Network before its IPv6 address.
// The names of the Nodes of the VRF are no records of the zone: a node answers them from the
// addresses that its state holds. in is an intent that Apply returned.
func (in Intent) Zone(vrf string) (suffix string, records []ZoneRecord, ok bool) {
	if v, exists := in.VRFs[vrf]; !exists || !v.DNS {
		return "", nil, false
	}
	for _, name := range sortedNames(in.DNSRecords) {
		r := in.DNSRecords[name]
		if r.VRF != vrf {
			continue
		}
		zr := ZoneRecord{Name: r.Name}
		if r.Node != "" {
			zr.Addresses = in.nodeAddressesIn(r.Node, vrf)
		}
		for _, s := range r.Addresses {
			if a, err := parseDNSAddress(s); err == nil {
				zr.Addresses = append(zr.Addresses, a)
			}
		}
		if len(zr.Addresses) > MaxDNSAddresses {
			zr.Addresses = zr.Addresses[:MaxDNSAddresses]
		}
		records = append(records, zr)
	}
	slices.SortFunc(records, func(a, b ZoneRecord) int { return strings.Compare(a.Name, b.Name) })
	return in.DNSSuffix(vrf), records, true
}

// nodeAddressesIn returns the addresses of the Node node in the Networks of the VRF vrf, ordered
// by Network name, the IPv4 address of a Network before its IPv6 address.
func (in Intent) nodeAddressesIn(node, vrf string) []netip.Addr {
	var out []netip.Addr
	for _, network := range sortedNames(in.Networks) {
		if in.Networks[network].VRF != vrf {
			continue
		}
		for _, address := range []func(node, network string) (netip.Prefix, bool){in.NodeAddress, in.NodeAddress6} {
			if p, ok := address(node, network); ok {
				out = append(out, p.Addr())
			}
		}
	}
	return out
}

// parseDNSAddress parses an address of a DnsRecord: an IPv4 or an IPv6 address without a zone,
// neither an IPv4-mapped IPv6 address nor the unspecified address.
func parseDNSAddress(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	switch {
	case err != nil:
		return netip.Addr{}, err
	case a.Zone() != "":
		return netip.Addr{}, fmt.Errorf("%q has a zone: a name of the overlay answers the same address on every host", s)
	case a.Is4In6():
		return netip.Addr{}, fmt.Errorf("%q is an IPv4-mapped IPv6 address: write it as an IPv4 address", s)
	case a.IsUnspecified():
		return netip.Addr{}, fmt.Errorf("%q is the unspecified address", s)
	}
	return a, nil
}

// checkDNSName checks a suffix or the name of a record: DNS labels of 1 to 63 lower-case letters,
// digits and hyphens, not starting or ending with a hyphen, separated by dots, MaxDNSName
// characters at most.
func checkDNSName(s string) error {
	if s == "" {
		return errors.New("it is empty")
	}
	if len(s) > MaxDNSName {
		return fmt.Errorf("%q is longer than %d characters", s, MaxDNSName)
	}
	for _, label := range strings.Split(s, ".") {
		if !nameRule.MatchString(label) {
			return fmt.Errorf("%q is not DNS labels separated by dots, each 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", s)
		}
	}
	return nil
}

// cloneDNS returns a copy of the DnsRecord resources of in that shares nothing with them.
func (in Intent) cloneDNS() map[string]DNSRecord {
	out := map[string]DNSRecord{}
	for name, r := range in.DNSRecords {
		r.Addresses = slices.Clone(r.Addresses)
		out[name] = r
	}
	return out
}

// completeDNS gives each DnsRecord of in that declares no name the name of its resource, and
// writes its addresses in their one form. An address that does not parse stays as it is, for
// validateDNS to refuse.
func (in Intent) completeDNS() {
	for name, r := range in.DNSRecords {
		if r.Name == "" {
			r.Name = name
		}
		for i, s := range r.Addresses {
			if a, err := netip.ParseAddr(s); err == nil {
				r.Addresses[i] = a.String()
			}
		}
		in.DNSRecords[name] = r
	}
}

// dnsUsers returns the DnsRecord resources of in that the VRF vrf or the Node node is used by,
// each as its kind and quoted name, in name order. An empty vrf or node matches no record.
func (in Intent) dnsUsers(vrf, node string) []string {
	var out []string
	for _, name := range sortedNames(in.DNSRecords) {
		r := in.DNSRecords[name]
		if (vrf != "" && r.VRF == vrf) || (node != "" && r.Node == node) {
			out = append(out, KindDNSRecord+" "+strconv.Quote(name))
		}
	}
	return out
}

// validateDNS checks overlay DNS of a completed intent: the suffix that a VRF declares is a DNS
// name of MaxDNSName characters at most; no Node is in two VRFs with overlay DNS on whose suffixes
// are the same or one under the other, which its host could not tell apart; and each DnsRecord
// names a VRF and a name that no other record and no Node of the VRF has, and either a Node of the
// VRF that holds an address there or 1 to MaxDNSAddresses addresses. No VRF has more than
// MaxDNSRecords records.
func (in Intent) validateDNS() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		if s := in.VRFs[name].DNSSuffix; s != "" {
			if err := checkDNSName(s); err != nil {
				problems = append(problems, fmt.Errorf("VRF %q: dnsSuffix: %w", name, err))
			}
		}
	}
	for _, node := range sortedNames(in.Nodes) {
		var vrfs []string
		for _, v := range in.Nodes[node].VRFs {
			if in.VRFs[v].DNS {
				vrfs = append(vrfs, v)
			}
		}
		for i, a := range vrfs {
			for _, b := range vrfs[i+1:] {
				sa, sb := in.DNSSuffix(a), in.DNSSuffix(b)
				if sa == sb || strings.HasSuffix(sa, "."+sb) || strings.HasSuffix(sb, "."+sa) {
					problems = append(problems, fmt.Errorf("Node %q: VRF %q has the DNS suffix %s and VRF %q the DNS suffix %s, the same or one under the other, so the host of the Node cannot tell their names apart",
						node, a, sa, b, sb))
				}
			}
		}
	}
	byVRF := map[string]map[string]string{} // the records of each VRF, resource by name
	for _, name := range sortedNames(in.DNSRecords) {
		r := in.DNSRecords[name]
		if _, ok := in.VRFs[r.VRF]; !ok {
			problems = append(problems, fmt.Errorf("DnsRecord %q: VRF %q does not exist", name, r.VRF))
			continue
		}
		if err := checkDNSName(r.Name); err != nil {
			problems = append(problems, fmt.Errorf("DnsRecord %q: name: %w", name, err))
		} else if full := r.Name + "." + in.DNSSuffix(r.VRF); len(full) > maxDNSFull {
			problems = append(problems, fmt.Errorf("DnsRecord %q: %s is longer than %d characters", name, full, maxDNSFull))
		}
		if byVRF[r.VRF] == nil {
			byVRF[r.VRF] = map[string]string{}
		}
		if other, ok := byVRF[r.VRF][r.Name]; ok {
			problems = append(problems, fmt.Errorf("DnsRecord %q: the name %q is already the name of DnsRecord %q in VRF %q", name, r.Name, other, r.VRF))
		} else {
			byVRF[r.VRF][r.Name] = name
		}
		if n, ok := in.Nodes[r.Name]; ok && slices.Contains(n.VRFs, r.VRF) {
			problems = append(problems, fmt.Errorf("DnsRecord %q: %q is the name of Node %q, which the zone of VRF %q answers already", name, r.Name, r.Name, r.VRF))
		}
		switch {
		case r.Node != "" && len(r.Addresses) > 0:
			problems = append(problems, fmt.Errorf("DnsRecord %q: it names Node %q and lists addresses: a record answers one or the other", name, r.Node))
		case r.Node != "":
			if n, ok := in.Nodes[r.Node]; !ok {
				problems = append(problems, fmt.Errorf("DnsRecord %q: Node %q does not exist", name, r.Node))
			} else if !slices.Contains(n.VRFs, r.VRF) {
				problems = append(problems, fmt.Errorf("DnsRecord %q: Node %q is not a member of VRF %q", name, r.Node, r.VRF))
			} else if len(in.nodeAddressesIn(r.Node, r.VRF)) == 0 {
				problems = append(problems, fmt.Errorf("DnsRecord %q: Node %q holds no address in VRF %q", name, r.Node, r.VRF))
			}
		case len(r.Addresses) == 0:
			problems = append(problems, fmt.Errorf("DnsRecord %q: it names no Node and lists no address", name))
		case len(r.Addresses) > MaxDNSAddresses:
			problems = append(problems, fmt.Errorf("DnsRecord %q: %d addresses, and a name answers at most %d", name, len(r.Addresses), MaxDNSAddresses))
		default:
			seen := map[netip.Addr]bool{}
			for _, s := range r.Addresses {
				a, err := parseDNSAddress(s)
				if err != nil {
					problems = append(problems, fmt.Errorf("DnsRecord %q: address: %w", name, err))
					continue
				}
				if seen[a] {
					problems = append(problems, fmt.Errorf("DnsRecord %q: the address %s is listed twice", name, a))
				}
				seen[a] = true
			}
		}
	}
	for _, vrf := range sortedNames(byVRF) {
		if got := len(byVRF[vrf]); got > MaxDNSRecords {
			problems = append(problems, fmt.Errorf("VRF %q: %d DnsRecord resources, and the control protocol carries at most %d", vrf, got, MaxDNSRecords))
		}
	}
	return problems
}
