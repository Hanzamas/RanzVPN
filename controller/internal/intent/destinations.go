package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// The admin destination lists (AUD1-DT-9, #457, ADR-0031 amendment of 2026-10-27): where an operator
// may point the Controller and the Nodes. An operator applies the Intent, so the lists that bound
// the Intent are not part of it: an admin keeps three of them in the store, and the operator works
// inside them.
//
//   - The target hosts are the hosts and the prefixes that an export or an audit target may name
//     although the address is loopback, link-local or the store of the Controller (internal/export,
//     Guard). Any other address needs no entry.
//   - The sensor prefixes are the prefixes that the sensor of every Mirror must be inside.
//   - The UNC servers are the servers that a UNC path of a Listener may name.
//
// An entry of a list of hosts is a DNS name, a prefix in CIDR form such as 192.0.2.0/24 or
// 2001:db8::/32, or one address, which is the prefix of that address alone. An entry of the sensor
// prefixes is a prefix or an address.

// MaxDestinations is the most entries of one of the lists.
const MaxDestinations = 256

// hostLabelRule is a label of a host name of a list: DNS labels, and the underscore that the names
// of Windows may hold.
var hostLabelRule = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Destinations are the three lists of an admin, each entry as text, in the order and the form that
// Normalize gives them. They are the body of PUT /api/v1/admin-destinations and its answer, and the
// answer of GET.
type Destinations struct {
	// Targets are the hosts and the prefixes that a target may name although they are loopback,
	// link-local or the store of the Controller.
	Targets []string `json:"targets"`
	// Sensors are the prefixes that the sensor of a Mirror must be inside.
	Sensors []string `json:"sensors"`
	// UNCServers are the servers that a UNC path of a Listener may name.
	UNCServers []string `json:"uncServers"`
}

// HostList is a list of hosts and prefixes that was parsed: the DNS names, in lower case and with no
// dot at the end, and the prefixes, which hold the addresses that were listed alone.
type HostList struct {
	Names    []string
	Prefixes []netip.Prefix
}

// ParseTargetHosts parses the target hosts: DNS names, prefixes and addresses. It refuses an entry
// that is none of these, a prefix with host bits set, an IPv4-mapped IPv6 prefix, an address with a
// zone, an entry that is listed twice, and a list of more than MaxDestinations entries. The error
// names every entry it refuses.
func ParseTargetHosts(list []string) (HostList, error) {
	return ParseHostList("target host", list)
}

// ParseUNCServers parses the UNC servers: DNS names and NetBIOS names of servers, and addresses and
// prefixes for a server that a path names by its address. The refusals are those of ParseTargetHosts.
func ParseUNCServers(list []string) (HostList, error) {
	return ParseHostList("UNC server", list)
}

// ParseHostList parses a list of hosts and prefixes, whose entries the errors call noun.
func ParseHostList(noun string, list []string) (HostList, error) {
	var out HostList
	var problems []string
	if len(list) > MaxDestinations {
		return out, fmt.Errorf("%d entries are more than the %d that a list holds", len(list), MaxDestinations)
	}
	seen := map[string]bool{}
	for _, s := range list {
		p, name, err := parseHostEntry(noun, s)
		key := name
		if name == "" && err == nil {
			key = p.String()
		}
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case seen[key]:
			problems = append(problems, fmt.Sprintf("%s %q is listed twice", noun, s))
		case name != "":
			seen[key] = true
			out.Names = append(out.Names, name)
		default:
			seen[key] = true
			out.Prefixes = append(out.Prefixes, p)
		}
	}
	if len(problems) > 0 {
		return HostList{}, errors.New(strings.Join(problems, "; "))
	}
	return out, nil
}

// ParseSensorPrefixes parses the sensor prefixes: prefixes and addresses, refused as ParseTargetHosts
// refuses them, and no name.
func ParseSensorPrefixes(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxDestinations {
		return nil, fmt.Errorf("%d entries are more than the %d that a list holds", len(list), MaxDestinations)
	}
	var out []netip.Prefix
	var problems []string
	seen := map[netip.Prefix]bool{}
	for _, s := range list {
		p, err := parseDestinationPrefix("sensor prefix", s)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case seen[p]:
			problems = append(problems, fmt.Sprintf("sensor prefix %q is listed twice", s))
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

// parseHostEntry parses one entry of a list of hosts: a prefix or an address, or a DNS name.
func parseHostEntry(noun, s string) (netip.Prefix, string, error) {
	if _, err := netip.ParseAddr(s); err == nil || strings.Contains(s, "/") {
		p, err := parseDestinationPrefix(noun, s)
		return p, "", err
	}
	name := strings.ToLower(strings.TrimSuffix(s, "."))
	if !hostNameOK(name) {
		return netip.Prefix{}, "", fmt.Errorf("%s %q is neither a host name, a prefix nor an address", noun, s)
	}
	return netip.Prefix{}, name, nil
}

// hostNameOK reports whether name is a host name of a list: at most maxDNSFull characters of labels
// that hostLabelRule allows, and a last label that is no number, so that a spelling of an address
// such as 127.1 is no name.
func hostNameOK(name string) bool {
	if name == "" || len(name) > maxDNSFull {
		return false
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if !hostLabelRule.MatchString(l) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// parseDestinationPrefix parses a prefix in CIDR form, or one address, which is the prefix of that
// address alone, as the entry of a list that its errors call noun.
func parseDestinationPrefix(noun, s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%s %q is neither a prefix nor an address", noun, s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return netip.Prefix{}, fmt.Errorf("%s %q is neither a prefix nor an address", noun, s)
	case p.Addr().Is4In6():
		return netip.Prefix{}, fmt.Errorf("%s %q is an IPv4-mapped IPv6 prefix: write it as an IPv4 prefix", noun, s)
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("%s %q has host bits set, the prefix is %s", noun, s, p.Masked())
	}
	return p, nil
}

// Strings returns the entries of l as text, ordered: the names, and each prefix in the form that
// netip.Prefix prints.
func (l HostList) Strings() []string {
	out := make([]string, 0, len(l.Names)+len(l.Prefixes))
	out = append(out, l.Names...)
	for _, p := range l.Prefixes {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

// Contains reports whether l holds the host host, which resolves to addr: host is one of its names
// (compared in lower case and without a dot at the end), or one of its prefixes holds addr, an
// address in the form that SourceAddr returns.
func (l HostList) Contains(host string, addr netip.Addr) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return (host != "" && slices.Contains(l.Names, host)) || ContainsSource(l.Prefixes, addr)
}

// AllowsServer reports whether l allows the server of a UNC path as the path spells it: a name that l
// holds, or an address, spelled as itself or as a name of the form 2001-db8--1.ipv6-literal.net, that
// one of its prefixes holds. A server that carries an @ and what follows, as the WebDAV form
// server@SSL@443 does, counts as the host before the @.
func (l HostList) AllowsServer(server string) bool {
	name, addr, isAddr := serverIdentity(server)
	if isAddr {
		return ContainsSource(l.Prefixes, addr)
	}
	return name != "" && slices.Contains(l.Names, name)
}

// serverIdentity returns the name of a server of a UNC path in lower case without a dot at the end,
// or its address when the path spells it as one.
func serverIdentity(server string) (name string, addr netip.Addr, isAddr bool) {
	host, _, _ := strings.Cut(server, "@")
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if label, ok := strings.CutSuffix(host, ".ipv6-literal.net"); ok {
		// Windows reads 2001-db8--1.ipv6-literal.net as 2001:db8::1, and an s before the end as the
		// start of the scope id
		label, _, _ = strings.Cut(label, "s")
		if a, err := netip.ParseAddr(strings.ReplaceAll(label, "-", ":")); err == nil {
			return "", a.Unmap(), true
		}
		return host, netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return "", a.WithZone("").Unmap(), true
	}
	return host, netip.Addr{}, false
}

// Normalize parses the three lists and returns them as the controller keeps them: each ordered, the
// names in lower case, and an address written as its prefix. The error names every entry that is
// refused, with its list.
func (d Destinations) Normalize() (Destinations, error) {
	var problems []error
	targets, err := ParseTargetHosts(d.Targets)
	if err != nil {
		problems = append(problems, fmt.Errorf("targets: %w", err))
	}
	sensors, err := ParseSensorPrefixes(d.Sensors)
	if err != nil {
		problems = append(problems, fmt.Errorf("sensors: %w", err))
	}
	servers, err := ParseUNCServers(d.UNCServers)
	if err != nil {
		problems = append(problems, fmt.Errorf("uncServers: %w", err))
	}
	if len(problems) > 0 {
		return Destinations{}, errors.Join(problems...)
	}
	return Destinations{Targets: targets.Strings(), Sensors: HostList{Prefixes: sensors}.Strings(), UNCServers: servers.Strings()}, nil
}

// UNCServer returns the server that the path of a file of a node names, and whether the path is one
// on a network. \\server\share\file is, and so is \\?\UNC\server\share\file, which the Windows API
// takes for a path with no limit of length. A path on a drive is not, in either form. Any other path
// of the device namespace of Windows (\\?\GLOBALROOT\Device\Mup\server\share reaches a server, and
// \\.\pipe\name a pipe) is reported as a path on a network that names no server, which no list
// allows.
func UNCServer(path string) (server string, unc bool) {
	rest, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", false
	}
	if len(rest) >= 2 && (rest[0] == '?' || rest[0] == '.') && rest[1] == '\\' {
		dev := rest[2:]
		switch {
		case len(dev) >= 3 && isDriveLetter(dev[0]) && dev[1] == ':' && dev[2] == '\\':
			return "", false
		case len(dev) >= 4 && strings.EqualFold(dev[:4], `UNC\`):
			rest = dev[4:]
		default:
			return "", true
		}
	}
	server, _, _ = strings.Cut(rest, `\`)
	return server, true
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// OutsideDestinations returns what the Mirrors and the Listeners of in name beyond the lists of an
// admin: the sensor of a Mirror that no prefix of sensors holds, and the UNC path of a Listener
// whose server servers does not allow. A Mirror with a sensor that does not parse, and a path that is
// no UNC path, are left to validation and to the node.
func (in Intent) OutsideDestinations(sensors []netip.Prefix, servers HostList) []error {
	var problems []error
	for _, name := range sortedNames(in.Mirrors) {
		ap, err := ParseSensor(in.Mirrors[name].Sensor)
		if err != nil || ContainsSource(sensors, ap.Addr()) {
			continue
		}
		problems = append(problems, fmt.Errorf("Mirror %q: the sensor %s is outside every prefix that an admin lists for sensors %s: an admin lists one with ranz admin-destinations set -sensors",
			name, ap.Addr(), listedPrefixes(sensors)))
	}
	type nodePath struct{ field, path string }
	for _, name := range sortedNames(in.Listeners) {
		c := in.Listeners[name].Certificate
		paths := []nodePath{{"file", c.File}, {"passwordFile", c.PasswordFile}}
		if c.ACME != nil {
			paths = append(paths, nodePath{"acme: caFile", c.ACME.CAFile})
		}
		for _, p := range paths {
			server, unc := UNCServer(p.path)
			if !unc || (server != "" && servers.AllowsServer(server)) {
				continue
			}
			if server == "" {
				problems = append(problems, fmt.Errorf("Listener %q: certificate: %s: the path %q is in the device namespace of Windows or names no server, and no admin allows such a path: use a path on a drive, or a UNC path of a server that an admin allows",
					name, p.field, p.path))
				continue
			}
			problems = append(problems, fmt.Errorf("Listener %q: certificate: %s: the UNC path %q names the server %q, which no admin allows (%s): an admin lists it with ranz admin-destinations set -unc-servers",
				name, p.field, p.path, server, listedHosts(servers)))
		}
	}
	return problems
}

// listedPrefixes says which prefixes an admin lists: none, or each of them.
func listedPrefixes(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "(none is listed)"
	}
	return "(" + strings.Join(HostList{Prefixes: prefixes}.Strings(), ", ") + ")"
}

// listedHosts says which servers an admin lists: none, or each of them.
func listedHosts(l HostList) string {
	if len(l.Names)+len(l.Prefixes) == 0 {
		return "none is listed"
	}
	return "listed: " + strings.Join(l.Strings(), ", ")
}
