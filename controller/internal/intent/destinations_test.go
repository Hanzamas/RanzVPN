package intent

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The target hosts take names, addresses and prefixes; a name is kept in lower case without a dot at
// the end, an address as its prefix, and the entries come back ordered.
func TestParseTargetHosts(t *testing.T) {
	got, err := ParseTargetHosts([]string{"Siem.Corp.Example.", "127.0.0.1", "10.0.0.0/8", "::1", "fe80::/10", "::ffff:192.0.2.7", "localhost", "_dmarc.example"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "127.0.0.1/32", "192.0.2.7/32", "::1/128", "_dmarc.example", "fe80::/10", "localhost", "siem.corp.example"}; !slices.Equal(got.Strings(), want) {
		t.Errorf("the entries are %v, want %v", got.Strings(), want)
	}

	// Each is refused with its reason, and the error names every one
	_, err = ParseTargetHosts([]string{"", "has space", "10.0.0.1/8", "::ffff:192.0.2.0/120", "fe80::1%eth0", "127.1", "a..b", "-x.example", strings.Repeat("a", 64) + ".example", "300.1.1.1", "Localhost", "localhost."})
	if err == nil {
		t.Fatal("entries that are none of a host name, a prefix and an address were taken")
	}
	for _, want := range []string{`target host "" is neither`, `"has space" is neither`, `"10.0.0.1/8" has host bits set, the prefix is 10.0.0.0/8`,
		`"::ffff:192.0.2.0/120" is an IPv4-mapped IPv6 prefix`, `"fe80::1%eth0" is neither a prefix nor an address`, `"127.1" is neither a host name`,
		`"a..b" is neither`, `"-x.example" is neither`, `"300.1.1.1" is neither`, `"localhost." is listed twice`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	if _, err := ParseTargetHosts([]string{"fe80::/10%eth0"}); err == nil {
		t.Error("a prefix with a zone was taken")
	}
	if _, err := ParseTargetHosts([]string{strings.Repeat("a.", 130) + "example"}); err == nil || !strings.Contains(err.Error(), "neither a host name") {
		t.Errorf("a name of more than 253 characters gave %v, want a refusal", err)
	}

	// A list is at most MaxDestinations entries
	var many []string
	for i := range MaxDestinations + 1 {
		many = append(many, fmt.Sprintf("h%d.example", i))
	}
	if _, err := ParseTargetHosts(many[:MaxDestinations]); err != nil {
		t.Errorf("%d entries gave %v", MaxDestinations, err)
	}
	if _, err := ParseTargetHosts(many); err == nil || !strings.Contains(err.Error(), "more than the 256") {
		t.Errorf("%d entries gave %v, want a refusal", len(many), err)
	}
	if l, err := ParseTargetHosts(nil); err != nil || len(l.Strings()) != 0 {
		t.Errorf("no entry gave %+v, %v, want an empty list", l, err)
	}
}

// The UNC servers are refused as the target hosts are, and say so in their own words.
func TestParseUNCServers(t *testing.T) {
	l, err := ParseUNCServers([]string{"FS01", "files.corp.example", "192.0.2.0/24"})
	if err != nil || !slices.Equal(l.Strings(), []string{"192.0.2.0/24", "files.corp.example", "fs01"}) {
		t.Fatalf("the servers are %v (%v)", l.Strings(), err)
	}
	if _, err := ParseUNCServers([]string{"fs01", "FS01"}); err == nil || !strings.Contains(err.Error(), `UNC server "FS01" is listed twice`) {
		t.Errorf("a server twice gave %v", err)
	}
}

// The sensor prefixes take prefixes and addresses, no name.
func TestParseSensorPrefixes(t *testing.T) {
	got, err := ParseSensorPrefixes([]string{"192.0.2.0/24", "2001:db8::5", "::ffff:198.51.100.9"})
	if err != nil || fmt.Sprint(got) != "[192.0.2.0/24 2001:db8::5/128 198.51.100.9/32]" {
		t.Fatalf("the prefixes are %v (%v)", got, err)
	}
	_, err = ParseSensorPrefixes([]string{"sensor.example", "192.0.2.1/24", "192.0.2.0/24", "192.0.2.0/24", "fe80::1%eth0", "::ffff:10.0.0.0/104"})
	if err == nil {
		t.Fatal("entries that are no prefix were taken")
	}
	for _, want := range []string{`sensor prefix "sensor.example" is neither a prefix nor an address`, `"192.0.2.1/24" has host bits set`, `"192.0.2.0/24" is listed twice`,
		`"fe80::1%eth0" is neither`, `"::ffff:10.0.0.0/104" is an IPv4-mapped`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	if _, err := ParseSensorPrefixes(make([]string, MaxDestinations+1)); err == nil || !strings.Contains(err.Error(), "more than the 256") {
		t.Errorf("too many entries gave %v", err)
	}
}

// Normalize gives the three lists in the form that the controller keeps, and names the list of each
// entry that it refuses.
func TestNormalizeDestinations(t *testing.T) {
	got, err := Destinations{Targets: []string{"Hooks.Example", "10.0.0.0/8", "127.0.0.1"}, Sensors: []string{"192.0.2.9", "10.1.0.0/16"}, UNCServers: []string{"FS01"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := Destinations{Targets: []string{"10.0.0.0/8", "127.0.0.1/32", "hooks.example"}, Sensors: []string{"10.1.0.0/16", "192.0.2.9/32"}, UNCServers: []string{"fs01"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the lists are %+v, want %+v", got, want)
	}
	// What Normalize made is its own fixed point, and nothing is nil, so that it reads back as []
	if again, err := got.Normalize(); err != nil || fmt.Sprint(again) != fmt.Sprint(got) {
		t.Errorf("the normal form normalized again is %+v (%v)", again, err)
	}
	if empty, err := (Destinations{}).Normalize(); err != nil || empty.Targets == nil || empty.Sensors == nil || empty.UNCServers == nil {
		t.Errorf("no lists gave %#v (%v), want three empty lists that are not nil", empty, err)
	}
	_, err = Destinations{Targets: []string{"???"}, Sensors: []string{"host.example"}, UNCServers: []string{"a", "a"}}.Normalize()
	if err == nil {
		t.Fatal("lists with wrong entries were taken")
	}
	for _, want := range []string{`targets: target host "???"`, `sensors: sensor prefix "host.example"`, `uncServers: UNC server "a" is listed twice`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
}

// The list of hosts holds a host by its name, or by the address that it resolves to.
func TestHostListContains(t *testing.T) {
	l, err := ParseTargetHosts([]string{"collector.example", "10.0.0.0/8", "fe80::/10"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host string
		addr string
		want bool
	}{
		{"collector.example", "127.0.0.1", true},
		{"COLLECTOR.example.", "169.254.169.254", true},
		{"other.example", "127.0.0.1", false},
		{"other.example", "10.20.30.40", true},
		{"10.20.30.40", "10.20.30.40", true},
		{"169.254.169.254", "169.254.169.254", false},
		{"", "127.0.0.1", false},
		{"x", "fe80::1", true},
		{"x", "2001:db8::1", false},
	} {
		if got := l.Contains(c.host, netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("Contains(%q, %s) = %v, want %v", c.host, c.addr, got, c.want)
		}
	}
	if (HostList{}).Contains("localhost", netip.MustParseAddr("127.0.0.1")) {
		t.Error("an empty list holds a host")
	}
	if l.Contains("collector.example", netip.Addr{}) != true {
		t.Error("a listed name is held with no address")
	}
}

// UNCServer finds the server of a path on a network, in the forms that Windows takes for one, and
// reports a path on a drive as none.
func TestUNCServer(t *testing.T) {
	for _, c := range []struct {
		path   string
		server string
		unc    bool
	}{
		{`C:\ProgramData\Ranz\node.pfx`, "", false},
		{`c:\x`, "", false},
		{`\\server\share\pfx.txt`, "server", true},
		{`\\server`, "server", true},
		{`\\Server.Corp.Example\share`, "Server.Corp.Example", true},
		{`\\192.0.2.7\share\x`, "192.0.2.7", true},
		{`\\files@SSL@443\DavWWWRoot\x.pfx`, "files@SSL@443", true},
		{`\\?\UNC\server\share\x`, "server", true},
		{`\\?\unc\server\share\x`, "server", true},
		{`\\.\UNC\server\share\x`, "server", true},
		{`\\?\C:\ProgramData\x`, "", false},
		{`\\.\d:\x`, "", false},
		{`\\?\GLOBALROOT\Device\Mup\server\share\x`, "", true},
		{`\\.\pipe\name`, "", true},
		{`\\?\Volume{0123}\x`, "", true},
		{`\\?\`, "", true},
		{`\\\share`, "", true},
		{`\\`, "", true},
		{``, "", false},
		{`/etc/ranz`, "", false},
		{`//server/share`, "", false},
	} {
		server, unc := UNCServer(c.path)
		if server != c.server || unc != c.unc {
			t.Errorf("UNCServer(%q) = %q, %v; want %q, %v", c.path, server, unc, c.server, c.unc)
		}
	}
}

// A server is allowed by its name, in any case and with or without the dot of the root, or by an
// address in a listed prefix, whether the path spells it as an address or as an ipv6-literal.net name.
func TestAllowsServer(t *testing.T) {
	l, err := ParseUNCServers([]string{"fs01", "files.corp.example", "192.0.2.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		server string
		want   bool
	}{
		{"fs01", true},
		{"FS01", true},
		{"fs01.", true},
		{"Files.Corp.Example", true},
		{"files@SSL@443", false},
		{"fs01@SSL", true},
		{"fs02", false},
		{"fs01.corp.example", false},
		{"", false},
		{"192.0.2.7", true},
		{"192.0.3.7", false},
		{"::ffff:192.0.2.7", true},
		{"2001-db8--1.ipv6-literal.net", true},
		{"2001-db8--1s4.ipv6-literal.net", true},
		{"2001-db9--1.ipv6-literal.net", false},
		{"nothex-zz.ipv6-literal.net", false},
		{"010.0.0.5", false},
		{"2130706433", false},
		{"0x7f000001", false},
	} {
		if got := l.AllowsServer(c.server); got != c.want {
			t.Errorf("AllowsServer(%q) = %v, want %v", c.server, got, c.want)
		}
	}
	if (HostList{}).AllowsServer("fs01") {
		t.Error("an empty list allows a server")
	}
}

// A Mirror whose sensor is outside the listed prefixes, and a Listener with a UNC path to a server
// that is not allowed, are named; the ones inside, a path on a drive and a Listener of another source
// are not.
func TestOutsideDestinations(t *testing.T) {
	in, err := Apply(mirrorBase(t), doc(
		res(KindMirror, "inside", `{"tag": "ids", "sensor": "192.0.2.50"}`),
		res(KindMirror, "outside", `{"tag": "ids", "sensor": "198.51.100.7:4790"}`),
		res(KindMirror, "outside-v6", `{"vrf": "lab", "sensor": "[2001:db8::5]:6081"}`),
		res(KindListener, "unc", `{"node": "a", "certificate": {"file": "\\\\evil.example\\share\\x.pfx", "passwordFile": "\\\\fs01\\share\\pw.txt"}}`),
		res(KindListener, "acme", `{"node": "b", "certificate": {"acme": {"names": ["vpn.example.com"], "caFile": "\\\\evil.example\\ca\\roots.pem"}}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	sensors, err := ParseSensorPrefixes([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	servers, err := ParseUNCServers([]string{"fs01"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range in.OutsideDestinations(sensors, servers) {
		got = append(got, p.Error())
	}
	want := []string{
		`Mirror "outside": the sensor 198.51.100.7 is outside every prefix that an admin lists for sensors (192.0.2.0/24)`,
		`Mirror "outside-v6": the sensor 2001:db8::5 is outside every prefix that an admin lists for sensors (192.0.2.0/24)`,
		`Listener "acme": certificate: acme: caFile: the UNC path "\\\\evil.example\\ca\\roots.pem" names the server "evil.example", which no admin allows (listed: fs01)`,
		`Listener "unc": certificate: file: the UNC path "\\\\evil.example\\share\\x.pfx" names the server "evil.example", which no admin allows (listed: fs01)`,
	}
	if len(got) != len(want) {
		t.Fatalf("the problems are\n%s\nwant %d", strings.Join(got, "\n"), len(want))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("problem %d is\n%s\nwant it to start with\n%s", i, got[i], want[i])
		}
	}

	// With nothing listed, every Mirror and every UNC path is outside, and the message says so
	all := in.OutsideDestinations(nil, HostList{})
	if len(all) != 6 || !strings.Contains(all[0].Error(), "(none is listed)") || !strings.Contains(all[3].Error(), "(none is listed)") {
		t.Errorf("with no list the problems are %v, want all 6 of them, saying that none is listed", all)
	}
	// Everything listed: nothing is outside
	every, err := ParseSensorPrefixes([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	evil, err := ParseUNCServers([]string{"evil.example", "fs01"})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.OutsideDestinations(every, evil); len(got) != 0 {
		t.Errorf("with everything listed the problems are %v", got)
	}
	// A path on a drive and an intent with neither are never outside
	if got := New().OutsideDestinations(nil, HostList{}); len(got) != 0 {
		t.Errorf("an empty intent has the problems %v", got)
	}
}

// A path of the device namespace of Windows that is no drive path can reach a server through
// \\?\GLOBALROOT\Device\Mup, so it is refused unless it names an allowed server in a form that
// UNCServer reads.
func TestOutsideDestinationsRefusesDevicePaths(t *testing.T) {
	servers, err := ParseUNCServers([]string{"fs01"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		ok   bool
	}{
		{`C:\ProgramData\Ranz\node.pfx`, true},
		{`\\?\C:\ProgramData\Ranz\node.pfx`, true},
		{`\\fs01\share\node.pfx`, true},
		{`\\?\UNC\fs01\share\node.pfx`, true},
		{`\\?\UNC\evil\share\node.pfx`, false},
		{`\\?\GLOBALROOT\Device\Mup\fs01\share\node.pfx`, false},
		{`\\.\pipe\x`, false},
	} {
		in := Intent{Listeners: map[string]Listener{"l": {Node: "a", Certificate: ListenerCertificate{File: c.path}}}}
		got := in.OutsideDestinations(nil, servers)
		if (len(got) == 0) != c.ok {
			t.Errorf("the path %q gave the problems %v, want ok = %v", c.path, got, c.ok)
		}
	}
}
