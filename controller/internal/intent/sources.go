package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// The source prefixes (SDN-39, #232): lists of address prefixes that limit where a connection may
// come from. A Network lists the prefixes that its Nodes may open their control stream from
// (Network.EnrolSources, EnrolRefusedBy), and the admin source allowlist of the controller lists
// the ones that may reach its API and its web UI (internal/api). An entry is a prefix in CIDR
// form, such as 203.0.113.0/24 or 2001:db8::/32, or one address, which is the prefix of that
// address alone.

// MaxSources is the most entries of one list of source prefixes.
const MaxSources = 256

// ParseSources parses a list of source prefixes and returns them in the order of the list. It
// refuses an entry that is neither a prefix nor an address, a prefix with host bits set, an
// IPv4-mapped IPv6 prefix (write it as an IPv4 prefix), an entry that is listed twice, and a list
// of more than MaxSources entries. The error names every entry it refuses.
func ParseSources(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxSources {
		return nil, fmt.Errorf("%d source prefixes are more than the %d that a list holds", len(list), MaxSources)
	}
	var out []netip.Prefix
	var problems []string
	seen := map[netip.Prefix]bool{}
	for _, s := range list {
		p, err := parseSource(s)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case seen[p]:
			problems = append(problems, fmt.Sprintf("source %q is listed twice", s))
		default:
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return out, nil
}

// parseSource parses one entry of a list of source prefixes: a prefix in CIDR form, or one
// address.
func parseSource(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("source %q is neither a prefix nor an address", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return netip.Prefix{}, fmt.Errorf("source %q is neither a prefix nor an address", s)
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("source %q is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix", s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("source %q has host bits set, the prefix is %s", s, p.Masked())
	}
	return p, nil
}

// normalizeSources returns list with each entry that parses written as its prefix, ordered: the
// form in which the intent keeps the source prefixes of a Network. An entry that does not parse
// is left as it is, for validate to name.
func normalizeSources(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s
		if p, err := parseSource(s); err == nil {
			out[i] = p.String()
		}
	}
	slices.Sort(out)
	return out
}

// SourceAddr returns the address of remote, a network address as net and net/http give it:
// host:port, or an address alone. It returns it in the form in which the prefixes of a list are
// matched: an IPv4-mapped IPv6 address as its IPv4 address, and an IPv6 address without its zone.
// It reports false, and returns the invalid address, when remote holds no address.
func SourceAddr(remote string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	a, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// ContainsSource reports whether one of prefixes holds addr, an address in the form that
// SourceAddr returns. The invalid address is held by none.
func ContainsSource(prefixes []netip.Prefix, addr netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// EnrolRefusedBy returns the Network that refuses the Node node when it opens its control stream
// from addr, an address in the form that SourceAddr returns: the first Network, in name order, of
// a VRF of the Node whose EnrolSources do not hold addr. A Network that lists none takes any
// address; one that lists some never takes the invalid address. It reports false when no Network
// refuses the Node, or when the intent has no such Node.
func (in Intent) EnrolRefusedBy(node string, addr netip.Addr) (string, bool) {
	n, ok := in.Nodes[node]
	if !ok {
		return "", false
	}
	refusedBy := ""
	for name, nw := range in.Networks {
		if len(nw.EnrolSources) == 0 || !slices.Contains(n.VRFs, nw.VRF) || (refusedBy != "" && name > refusedBy) {
			continue
		}
		// Apply validated the list; one that does not parse gives no prefix, so it holds nothing
		prefixes, _ := ParseSources(nw.EnrolSources)
		if !ContainsSource(prefixes, addr) {
			refusedBy = name
		}
	}
	return refusedBy, refusedBy != ""
}

// HasEnrolSources reports whether a Network of the intent limits where its Nodes may enrol from.
func (in Intent) HasEnrolSources() bool {
	for _, nw := range in.Networks {
		if len(nw.EnrolSources) > 0 {
			return true
		}
	}
	return false
}
