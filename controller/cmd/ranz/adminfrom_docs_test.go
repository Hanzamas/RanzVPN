package main

import (
	"strings"
	"testing"
)

// The docs of AUD1-DT-15 (#497), its third and fourth criteria. The default admin source allowlist that ranz install sets is loopback and
// the private subnets of the host, which is wrong in two cases: it holds no global IPv6 subnet, so a dual-stack client of the same LAN
// that reaches the host by an AAAA name from the same global /64 gets 403, and it is too wide where a proxy, a load balancer or a
// masquerading router inside a private subnet passes callers from the internet on, since every one of them then looks private. The runbook
// of the first test shows what to do about the first, and names both; the threat model names both. A page is written for a person, so
// these tests look for what a reader needs, with the white space of the page (its lines, its table cells) folded into one space.
//
// AUD1-DT-15-R1 (#561) says which router the second case means. A router makes every caller look private only when it rewrites the source
// address of what it passes on (source NAT, which masquerading is) or when it is a proxy. A router that only forwards the port (destination
// NAT, a port forward) keeps the public source of the caller, which the default list refuses with 403, so for it the default is not too wide.

// pageText returns the page docs/name with all white space folded into single spaces.
func pageText(t *testing.T, name string) string {
	t.Helper()
	return strings.Join(strings.Fields(strings.Join(docLines(t, name), "\n")), " ")
}

func TestDocsSayWhereTheDefaultAllowlistIsTooWideAndTooNarrow(t *testing.T) {
	for _, page := range []struct {
		file string
		want []string
		// not is what a page must no longer say
		not []string
	}{
		{"first-test.md", []string{
			// The global IPv6 subnet, and how to allow it
			"A global IPv6 subnet is not in the default",
			"an IPv6 name (an AAAA record)",
			"from an address in the same global `/64`, is answered `403`",
			"`ranz install --controller --admin-from 192.168.1.0/24,2001:db8:1:2::/64`",
			"`--admin-from` replaces the default list, so name the private subnets that you still want",
			"`ranz admin-sources set 192.168.1.0/24 2001:db8:1:2::/64`",
			// The proxy, the load balancer and the router that masquerades, inside a private subnet, and the router that only forwards a port
			"A proxy, a load balancer or a masquerading router inside a private subnet makes the default too wide",
			"a router that rewrites the source address of what it passes on (source NAT, or SNAT, which masquerading is)",
			"every one of those callers reaches the Controller from a private address, and the default list lets them in",
			"A router that only forwards the port (a port forward, also called destination NAT or DNAT) is not a problem here: it keeps the address of the caller, which is public, so the default list answers that caller `403`",
			"A proxy on the PC itself is worse",
		}, []string{
			// A plain port forward is no router that translates addresses in the sense of the case
			"a router that translates addresses",
		}},
		{"threat-model.md", []string{
			"The default list is wrong in two cases",
			"a reverse proxy, a load balancer or a router that rewrites the source address of what it passes on (source NAT, SNAT, which masquerading is) inside such a subnet",
			"makes every one of them look private, and the default lets them in",
			"A router that only forwards the port (destination NAT, DNAT, a port forward) keeps the public source of the caller, and the default list refuses that caller with 403, so it is not this case",
			"The list holds no global IPv6 subnet",
			"from the same global `/64` is refused with 403 until that `/64` is named with `--admin-from`",
		}, []string{
			"a masquerading (NAT) router",
		}},
	} {
		text := pageText(t, page.file)
		for _, want := range page.want {
			if !strings.Contains(text, want) {
				t.Errorf("docs/%s does not say %q", page.file, want)
			}
		}
		for _, gone := range page.not {
			if strings.Contains(text, gone) {
				t.Errorf("docs/%s still says %q, which takes a router that only forwards a port for one that makes every caller look private", page.file, gone)
			}
		}
	}
}
