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

// pageText returns the page docs/name with all white space folded into single spaces.
func pageText(t *testing.T, name string) string {
	t.Helper()
	return strings.Join(strings.Fields(strings.Join(docLines(t, name), "\n")), " ")
}

func TestDocsSayWhereTheDefaultAllowlistIsTooWideAndTooNarrow(t *testing.T) {
	for _, page := range []struct {
		file string
		want []string
	}{
		{"first-test.md", []string{
			// The global IPv6 subnet, and how to allow it
			"A global IPv6 subnet is not in the default",
			"an IPv6 name (an AAAA record)",
			"from an address in the same global `/64`, is answered `403`",
			"`ranz install --controller --admin-from 192.168.1.0/24,2001:db8:1:2::/64`",
			"`--admin-from` replaces the default list, so name the private subnets that you still want",
			"`ranz admin-sources set 192.168.1.0/24 2001:db8:1:2::/64`",
			// The proxy, the load balancer and the masquerading router inside a private subnet
			"A proxy, a load balancer or a masquerading router inside a private subnet makes the default too wide",
			"every one of those callers reaches the Controller from a private address, and the default list lets them in",
			"A proxy on the PC itself is worse",
		}},
		{"threat-model.md", []string{
			"The default list is wrong in two cases",
			"a reverse proxy, a load balancer or a masquerading (NAT) router inside such a subnet",
			"makes every one of them look private, and the default lets them in",
			"The list holds no global IPv6 subnet",
			"from the same global `/64` is refused with 403 until that `/64` is named with `--admin-from`",
		}},
	} {
		text := pageText(t, page.file)
		for _, want := range page.want {
			if !strings.Contains(text, want) {
				t.Errorf("docs/%s does not say %q", page.file, want)
			}
		}
	}
}
