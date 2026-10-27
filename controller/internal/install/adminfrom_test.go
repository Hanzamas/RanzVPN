package install

import (
	"net"
	"strings"
	"testing"
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
	m := adminFromMessage("10.1.2.0/24,127.0.0.0/8")
	for _, want := range []string{"10.1.2.0/24, 127.0.0.0/8", "403", "ranz admin-sources set", "--admin-from any"} {
		if !strings.Contains(m, want) {
			t.Errorf("the message %q does not say %q", m, want)
		}
	}
	if m := adminFromMessage(AdminFromAny); !strings.Contains(m, "any address may reach") {
		t.Errorf("the message for any is %q", m)
	}
}
