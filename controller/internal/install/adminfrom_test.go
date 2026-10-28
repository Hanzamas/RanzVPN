package install

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

func ipnet(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip
	return n
}

// With no flag, the allowlist is loopback and the subnet of each private address of the host: a
// public, a link-local and a shared (RFC 6598) address add nothing, and a subnet is listed once.
func TestAdminFromDefaultIsLoopbackAndThePrivateSubnets(t *testing.T) {
	addrs := []net.Addr{
		ipnet(t, "10.1.2.3/24"),
		ipnet(t, "10.1.2.9/24"),
		ipnet(t, "192.168.7.20/16"),
		ipnet(t, "172.16.5.5/12"),
		ipnet(t, "fd12:3456:789a::5/64"),
		ipnet(t, "203.0.113.7/24"),
		ipnet(t, "169.254.3.4/16"),
		ipnet(t, "fe80::1/64"),
		ipnet(t, "100.64.0.1/32"),
		ipnet(t, "127.0.0.1/8"),
		&net.IPAddr{IP: net.ParseIP("10.9.9.9")},
	}
	got, err := AdminFrom(nil, addrs)
	if err != nil {
		t.Fatal(err)
	}
	want := "10.1.2.0/24,127.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fd12:3456:789a::/64"
	if got != want {
		t.Errorf("the default allowlist is %s, want %s", got, want)
	}
	if got, err := AdminFrom(nil, nil); err != nil || got != "127.0.0.0/8,::1/128" {
		t.Errorf("the default of a host without addresses is %q (%v), want loopback", got, err)
	}
}

// The default never takes in a public address: the subnet of an interface is listed within the
// private block that holds its address, so a mask that is wider than the block, as 172.16.0.5/8 has,
// or one of no bits, gives the block and not 172.0.0.0/8 or everything. An address whose mask is
// not a prefix adds nothing.
func TestAdminFromDefaultStaysWithinThePrivateBlocks(t *testing.T) {
	crooked := &net.IPNet{IP: net.ParseIP("10.4.4.4"), Mask: net.IPv4Mask(255, 0, 255, 0)}
	for _, c := range []struct {
		what  string
		addrs []net.Addr
		want  string
	}{
		{"a /8 over 172.16", []net.Addr{ipnet(t, "172.16.0.5/8")}, "127.0.0.0/8,172.16.0.0/12,::1/128"},
		{"a /8 over 192.168", []net.Addr{ipnet(t, "192.168.1.5/8")}, "127.0.0.0/8,192.168.0.0/16,::1/128"},
		{"a /0 over 10", []net.Addr{ipnet(t, "10.1.1.1/0")}, "10.0.0.0/8,127.0.0.0/8,::1/128"},
		{"a /4 over a unique local address", []net.Addr{ipnet(t, "fd12::1/4")}, "127.0.0.0/8,::1/128,fc00::/7"},
		{"a /12 that is the block", []net.Addr{ipnet(t, "172.20.1.1/12")}, "127.0.0.0/8,172.16.0.0/12,::1/128"},
		{"a mask that narrows the block", []net.Addr{ipnet(t, "172.20.1.1/24")}, "127.0.0.0/8,172.20.1.0/24,::1/128"},
		{"a mask that is not a prefix", []net.Addr{crooked}, "127.0.0.0/8,::1/128"},
	} {
		if got, err := AdminFrom(nil, c.addrs); err != nil || got != c.want {
			t.Errorf("%s: the default allowlist is %q (%v), want %q", c.what, got, err, c.want)
		}
	}
}

// A host with more private subnets than the list holds gets no default, as the Controller would not
// start with it: ranz install asks for --admin-from. A default of as many entries as the list holds
// is taken.
func TestAdminFromDefaultThatTheListCannotHoldIsRefused(t *testing.T) {
	var addrs []net.Addr
	for i := range intent.MaxSources - len(loopbackPrefixes) + 1 {
		addrs = append(addrs, ipnet(t, fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)))
	}
	if got, err := AdminFrom(nil, addrs); err == nil || !strings.Contains(err.Error(), "--admin-from") {
		t.Errorf("a default of loopback and %d private subnets gave %d entries (%v), want a refusal that asks for --admin-from", len(addrs), strings.Count(got, ",")+1, err)
	}
	got, err := AdminFrom(nil, addrs[1:])
	if err != nil || strings.Count(got, ",")+1 != intent.MaxSources {
		t.Errorf("a default of %d entries, as many as the list holds, gave %d entries (%v)", intent.MaxSources, strings.Count(got, ",")+1, err)
	}
	if _, err := intent.ParseSources(strings.Split(got, ",")); err != nil {
		t.Errorf("the default of %d entries is no list that the Controller takes: %v", intent.MaxSources, err)
	}
}

// --admin-from names prefixes or addresses, canonical and ordered, and any alone restores the open
// default; a wrong entry, a repeated one and any beside a prefix are refused.
func TestAdminFromTakesPrefixesOrAny(t *testing.T) {
	for _, c := range []struct {
		values []string
		want   string
	}{
		{[]string{"203.0.113.0/24"}, "203.0.113.0/24"},
		{[]string{"2001:db8::10", "192.0.2.0/24", "192.0.2.77"}, "192.0.2.0/24,192.0.2.77/32,2001:db8::10/128"},
		{[]string{"any"}, AdminFromAny},
	} {
		if got, err := AdminFrom(c.values, []net.Addr{ipnet(t, "10.1.2.3/24")}); err != nil || got != c.want {
			t.Errorf("--admin-from %q is %q (%v), want %q", c.values, got, err, c.want)
		}
	}
	for _, bad := range [][]string{{"nowhere"}, {"10.0.0.1/8"}, {"192.0.2.0/24", "192.0.2.0/24"}, {"any", "192.0.2.0/24"}} {
		if got, err := AdminFrom(bad, nil); err == nil || !strings.Contains(err.Error(), "--admin-from") {
			t.Errorf("--admin-from %q gave %q (%v), want a refusal", bad, got, err)
		}
	}
}

// ranz install says which sources the Controller allows and how to change it, or that none is
// restricted.
func TestAdminFromMessageSaysWhoIsAllowedAndHowToChangeIt(t *testing.T) {
	m := adminFromMessage("10.1.2.0/24,127.0.0.0/8", "")
	for _, want := range []string{"the Controller starts with the admin source allowlist", "10.1.2.0/24, 127.0.0.0/8", "403", "ranz admin-sources set", "--admin-from any"} {
		if !strings.Contains(m, want) {
			t.Errorf("the message %q does not say %q", m, want)
		}
	}
	if m := adminFromMessage(AdminFromAny, ""); !strings.Contains(m, "any address may reach") {
		t.Errorf("the message for any is %q", m)
	}
}

// A data directory that holds the store of a Controller that started before, which ranz uninstall
// leaves, keeps its list: ranz install does not promise the list of its flag or of the default, and
// says where to see the list and how to change it. A service that is registered already says the
// same.
func TestAdminFromMessageDoesNotPromiseAListThatAStoreKeeps(t *testing.T) {
	for _, value := range []string{"10.1.2.0/24,127.0.0.0/8", AdminFromAny} {
		m := adminFromMessage(value, `C:\ProgramData\Ranz\controller`)
		for _, want := range []string{`C:\ProgramData\Ranz\controller`, "holds the store of a Controller that started before", "keeps the admin source allowlist that it has", "whatever --admin-from or the default says", "ranz status", "ranz admin-sources set"} {
			if !strings.Contains(m, want) {
				t.Errorf("the message for the kept store with the flag %q does not say %q: %s", value, want, m)
			}
		}
		for _, not := range []string{"starts with", "every other gets 403"} {
			if strings.Contains(m, not) {
				t.Errorf("the message for the kept store with the flag %q says %q, which a kept store does not do: %s", value, not, m)
			}
		}
	}
	m := adminFromExistingMessage("ranz-controller")
	for _, want := range []string{"the ranz-controller service is there already", "--admin-from and the default change nothing", "at its first start only", "its store keeps the list", "ranz status", "ranz admin-sources set"} {
		if !strings.Contains(m, want) {
			t.Errorf("the message for a service that is there already does not say %q: %s", want, m)
		}
	}
}
