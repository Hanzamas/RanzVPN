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
// changes what an administrator set with `ranz admin-sources`. The control stream of the Nodes is
// not behind the list (ADR-0034, ADR-0027): a Network limits where its Nodes enrol from.

// AdminFromAny is the value of --admin-from that leaves the API and the web UI open to every address.
const AdminFromAny = "any"

// loopbackPrefixes are the host of the Controller itself, which the allowlist always lets in; the
// default lists them anyway, so that `ranz status` shows them.
var loopbackPrefixes = []string{"127.0.0.0/8", "::1/128"}

// AdminFrom returns the value of the flag -admin-from of the Controller service for what the
// operator asked: AdminFromAny for --admin-from any, the prefixes of values in their canonical form
// and order, else the default of addrs, the addresses of the interfaces of the host. values is the
// list that --admin-from gave, empty for no flag. It refuses an entry that is not a prefix or an
// address, and any beside another entry.
func AdminFrom(values []string, addrs []net.Addr) (string, error) {
	if len(values) == 0 {
		return strings.Join(defaultAdminFrom(addrs), ","), nil
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
// each once. A link-local, a public and a shared (RFC 6598, the overlay pool of the first install)
// address adds nothing.
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
		if !ip.IsPrivate() || ones < 0 {
			continue
		}
		p, err := ip.Prefix(ones)
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

// adminFromMessage is what ranz install says about the allowlist that the Controller starts with.
func adminFromMessage(value string) string {
	if value == AdminFromAny {
		return "install: the Controller starts with no admin source allowlist (--admin-from any): any address may reach its API and its web UI, with the token as the only barrier"
	}
	return fmt.Sprintf("install: the Controller starts with the admin source allowlist %s: only these sources reach its API and its web UI (every other gets 403), and the control stream of the Nodes is not behind it; change it with ranz admin-sources set PREFIX..., or install with --admin-from PREFIX,... or --admin-from any", strings.ReplaceAll(value, ",", ", "))
}
