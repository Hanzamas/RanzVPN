package install

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The admin source allowlist that ranz install --controller sets (AUD1-DT-6, #454). TCP 443 and 5555
// are open on every profile, so the first install narrows who may reach the API and the web UI of
// the Controller (the admin source allowlist of SDN-39, internal/api): with no flag, to loopback and
// the subnets of the private interfaces of the host; with --admin-from, to the prefixes that it
// names; with --admin-from any, to nobody in particular, as before. The Controller service takes the
// list as its flag -admin-from and applies it once, at its first start, so a later install never
// changes what an administrator set with `ranz admin-sources`: a service that is registered already,
// and a data directory that ranz uninstall left with the store of an earlier Controller, keep the
// list that their store holds, and ranz install says so. The control stream of the Nodes is not
// behind the list (ADR-0034, ADR-0027): a Network limits where its Nodes enrol from.

// AdminFromAny is the value of --admin-from that leaves the API and the web UI open to every address.
const AdminFromAny = "any"

// loopbackPrefixes are the host of the Controller itself, which the allowlist always lets in; the
// default lists them anyway, so that `ranz status` shows them.
var loopbackPrefixes = []string{"127.0.0.0/8", "::1/128"}

// privateBlocks are the address blocks that count as private for the default: RFC 1918 and the unique
// local addresses of IPv6. The subnet of an interface is listed within the block that holds its
// address, never beyond it.
var privateBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// AdminFrom returns the value of the flag -admin-from of the Controller service for what the
// operator asked: AdminFromAny for --admin-from any, the prefixes of values in their canonical form
// and order, else the default of addrs, the addresses of the interfaces of the host. values is the
// list that --admin-from gave, empty for no flag. It refuses an entry that is not a prefix or an
// address, and any beside another entry. It refuses a default that holds more entries than the list
// does (intent.MaxSources), with which the Controller would not start, and asks for --admin-from.
func AdminFrom(values []string, addrs []net.Addr) (string, error) {
	if len(values) == 0 {
		list := defaultAdminFrom(addrs)
		if len(list) > intent.MaxSources {
			return "", fmt.Errorf("the default admin source allowlist of this host, loopback and %d private subnets, has more than the %d entries that the list holds: name the sources with --admin-from", len(list)-len(loopbackPrefixes), intent.MaxSources)
		}
		return strings.Join(list, ","), nil
	}
	if slices.Contains(values, AdminFromAny) {
		if len(values) > 1 {
			return "", fmt.Errorf("--admin-from %s stands alone: it lifts the restriction, so another prefix beside it means nothing", AdminFromAny)
		}
		return AdminFromAny, nil
	}
	prefixes, err := intent.ParseSources(values)
	if err != nil {
		return "", fmt.Errorf("--admin-from: %w", err)
	}
	list := make([]string, len(prefixes))
	for i, p := range prefixes {
		list[i] = p.String()
	}
	slices.Sort(list)
	return strings.Join(list, ","), nil
}

// defaultAdminFrom returns the default allowlist: loopback, and the subnet of each private address
// that the interfaces of the host hold (RFC 1918 and the unique local addresses of IPv6), ordered,
// each once. A subnet that is wider than the private block of its address, as 172.16.0.5/8 or a
// mask of no bits is, is the block: the list never takes in a public address. A link-local, a public
// and a shared (RFC 6598, the overlay pool of the first install) address adds nothing, and neither
// does an address whose mask is not a prefix.
func defaultAdminFrom(addrs []net.Addr) []string {
	list := slices.Clone(loopbackPrefixes)
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		ip = ip.Unmap()
		if bits == 128 && ip.Is4() {
			ones -= 96
		}
		block := slices.IndexFunc(privateBlocks, func(b netip.Prefix) bool { return b.Contains(ip) })
		if block < 0 || bits == 0 || ones < 0 {
			continue
		}
		p, err := ip.Prefix(max(ones, privateBlocks[block].Bits()))
		if err != nil {
			continue
		}
		if s := p.String(); !slices.Contains(list, s) {
			list = append(list, s)
		}
	}
	slices.Sort(list)
	return list
}

// adminFromMessage is what ranz install says about the allowlist of the Controller service that it
// registers, with the flag value. A Controller that starts for the first time starts with it. When
// keptDir names the data directory of a Controller that started before, whose store ranz uninstall
// left, the Controller keeps the list that the store holds, whatever the flag says, and the message
// says that instead.
func adminFromMessage(value, keptDir string) string {
	switch {
	case keptDir != "":
		return fmt.Sprintf("install: the data directory %s holds the store of a Controller that started before, and the store keeps the admin source allowlist that it has, whatever --admin-from or the default says: ranz status shows it, ranz admin-sources set PREFIX... changes it", keptDir)
	case value == AdminFromAny:
		return "install: the Controller starts with no admin source allowlist (--admin-from any): any address may reach its API and its web UI, with the token as the only barrier"
	}
	return fmt.Sprintf("install: the Controller starts with the admin source allowlist %s: only these sources reach its API and its web UI (every other gets 403), and the control stream of the Nodes is not behind it; change it with ranz admin-sources set PREFIX..., or install with --admin-from PREFIX,... or --admin-from any", strings.ReplaceAll(value, ",", ", "))
}

// adminFromExistingMessage is what ranz install says when the Controller service is registered
// already: it is only started, so --admin-from and the default change nothing. The service sets the
// list that it was registered with at its first start only, and its store keeps the list after that.
func adminFromExistingMessage(service string) string {
	return fmt.Sprintf("install: the %s service is there already, so --admin-from and the default change nothing: it sets the admin source allowlist that it was registered with at its first start only, and after that its store keeps the list: ranz status shows it, ranz admin-sources set PREFIX... changes it", service)
}
