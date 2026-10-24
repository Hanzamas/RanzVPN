package intent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// policyJSON is a document with the conntrack of a VRF and tag rules between the Nodes of it
// (SDN-8), for the fuzz test to start from.
const policyJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48", "conntrack": {"maxFlows": 4096, "timeouts": {"udp": 30, "icmp": 5}}}},
  {"kind": "Node", "name": "web-1", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "tags": ["web"]}},
  {"kind": "Policy", "name": "web-to-db", "spec": {"vrf": "corp", "action": "allow", "priority": 100, "from": {"tags": ["web"]}, "to": {"tags": ["db"], "addresses": ["10.1.0.0/16"]}, "protocol": "tcp", "ports": [5432, "8000-8080"]}},
  {"kind": "Policy", "name": "no-guests", "spec": {"vrf": "corp", "action": "deny", "from": {"tags": ["guest"]}}}
]}`

// policyBase applies two VRFs and two Nodes, with the resources of more: corp declares its
// conntrack, lab does not; web-1 (tag web) is in corp, db-1 (tag db) in corp and lab.
func policyBase(t *testing.T, more ...Resource) (Intent, error) {
	t.Helper()
	rs := []Resource{
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "conntrack": {"maxFlows": 4096, "timeouts": {"udp": 30, "icmp": 5}}}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNode, "web-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["web"]}`),
		res(KindNode, "db-1", `{"publicKey": "`+key2+`", "vrfs": ["corp", "lab"], "tags": ["db"]}`),
	}
	return Apply(New(), doc(append(rs, more...)...), nil)
}

func policy(name, spec string) Resource {
	return res(KindPolicy, name, spec)
}

// ruleText returns a rule as one line: its VRF, priority, action, ends, protocol and ports.
func ruleText(r Rule) string {
	action := "allow"
	if r.Deny {
		action = "deny"
	}
	end := func(e RuleEnd) string { return fmt.Sprintf("%v%v", e.Tags, e.Prefixes) }
	return fmt.Sprintf("%s %s %d %s %s>%s %d %v", r.VRF, r.Name, r.Priority, action, end(r.From), end(r.To), r.Protocol, r.Ports)
}

// A Policy is kept in its one form: its tags sorted, its addresses and ports as they print and
// its protocol by name; it reads back from the stored resources, and Rules gives it parsed, its
// priority filled in, ordered by VRF, then name. A VRF keeps the conntrack it declares.
func TestPolicyApplies(t *testing.T) {
	in, err := policyBase(t,
		policy("web-to-db", `{"vrf": "corp", "action": "allow", "priority": 100, "from": {"tags": ["web"]}, "to": {"tags": ["db"], "addresses": ["10.1.0.0/16"]},
			"protocol": 6, "ports": [5432, "8000-8080", "443-443"]}`),
		policy("ping", `{"vrf": "corp", "action": "allow", "protocol": "1", "to": {"addresses": ["FD12::0005", "192.168.1.7/32", "fd12::/64"]}}`),
		policy("no-guests", `{"vrf": "corp", "action": "deny", "from": {"tags": ["guest", "b-guest"]}, "to": {}}`),
		policy("lab-gre", `{"vrf": "lab", "action": "allow", "protocol": "47"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"web-to-db": `{"vrf":"corp","action":"allow","priority":100,"from":{"tags":["web"]},"to":{"tags":["db"],"addresses":["10.1.0.0/16"]},"protocol":"tcp","ports":["5432","8000-8080","443"]}`,
		"ping":      `{"vrf":"corp","action":"allow","to":{"addresses":["fd12::5","192.168.1.7","fd12::/64"]},"protocol":"icmp"}`,
		"no-guests": `{"vrf":"corp","action":"deny","from":{"tags":["b-guest","guest"]}}`,
		"lab-gre":   `{"vrf":"lab","action":"allow","protocol":"47"}`,
	} {
		if got := string(resource(KindPolicy, name, in.Policies[name]).Spec); got != want {
			t.Errorf("Policy %q is stored as\n%s\nwant\n%s", name, got, want)
		}
	}
	if got, want := string(resource(KindVRF, "corp", in.VRFs["corp"]).Spec), `{"id":10,"ula":"fd12:3456:789a::/48","mtu":1280,"conntrack":{"maxFlows":4096,"timeouts":{"udp":30,"icmp":5}}}`; got != want {
		t.Errorf("VRF corp is stored as\n%s\nwant\n%s", got, want)
	}
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	var lines []string
	for _, r := range in.Rules() {
		lines = append(lines, ruleText(r))
	}
	want := []string{
		"corp no-guests 1000 deny [b-guest guest][]>[][] 0 []",
		"corp ping 1000 allow [][]>[][fd12::5/128 192.168.1.7/32 fd12::/64] 1 []",
		"corp web-to-db 100 allow [web][]>[db][10.1.0.0/16] 6 [{5432 5432} {8000 8080} {443 443}]",
		"lab lab-gre 1000 allow [][]>[][] 47 []",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("the rules are\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestPolicyRejects(t *testing.T) {
	seventeen := `"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13", "t14", "t15", "t16"`
	for _, c := range []struct {
		r    Resource
		want string
	}{
		{policy("p", `{"vrf": "corp", "action": "allow", "priority": 1000001}`), `Policy "p": priority 1000001 is more than 1000000`},
		{policy("p", `{"vrf": "corp", "action": "allow", "from": {"tags": ["Web"]}}`), `Policy "p": from: tag "Web" must be 1 to 63 lower-case letters`},
		{policy("p", `{"vrf": "corp", "action": "allow", "to": {"tags": ["db", "db"]}}`), `Policy "p": to: tag "db" is listed twice`},
		{policy("p", `{"vrf": "corp", "action": "allow", "from": {"tags": [`+seventeen+`]}}`), `Policy "p": from: 17 tags and 0 addresses, at most 16 of each`},
		{policy("p", `{"vrf": "corp", "action": "allow", "to": {"addresses": ["10.0.0.1/24"]}}`), `Policy "p": to: address "10.0.0.1/24" has host bits set, the prefix is 10.0.0.0/24`},
		{policy("p", `{"vrf": "corp", "action": "allow", "to": {"addresses": ["x"]}}`), `Policy "p": to: address "x" is neither an IP address nor a prefix`},
		{policy("p", `{"vrf": "corp", "action": "allow", "to": {"addresses": ["::ffff:10.0.0.1"]}}`), `address "::ffff:10.0.0.1" is an IPv4-mapped IPv6 address: write it as IPv4`},
		{policy("p", `{"vrf": "corp", "action": "allow", "from": {"addresses": ["fe80::1%eth0"]}}`), `Policy "p": from: address "fe80::1%eth0" has a zone`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "sctp"}`), `Policy "p": protocol "sctp" is neither tcp, udp nor icmp, nor a number from 1 to 255`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "TCP"}`), `Policy "p": protocol "TCP" is neither tcp`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": 256}`), `Policy "p": protocol "256" is neither tcp`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "047"}`), `Policy "p": protocol "047" is neither tcp`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": true}`), `a protocol or a port is a number or a string`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "icmp", "ports": [80]}`), `Policy "p": ports are for the protocol tcp or udp only`},
		{policy("p", `{"vrf": "corp", "action": "allow", "ports": ["80"]}`), `Policy "p": ports are for the protocol tcp or udp only`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "udp", "ports": [70000]}`), `Policy "p": port "70000" is not a port from 0 to 65535 or a range of them "first-last"`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "udp", "ports": ["90-80"]}`), `Policy "p": port "90-80" is not a port`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "udp", "ports": ["53-x"]}`), `Policy "p": port "53-x" is not a port`},
		{policy("p", `{"vrf": "corp", "action": "allow", "protocol": "udp", "ports": [`+strings.Repeat(`1, `, 16)+`1]}`), `Policy "p": 17 ports, at most 16`},
		{policy("p", `{"vrf": "nowhere", "action": "allow"}`), `Policy "p": VRF "nowhere" does not exist`},
		{policy("p", `{"vrf": "corp", "action": "drop"}`), `Policy "p": the action must be allow or deny, not "drop"`},
		{res(KindVRF, "ops", `{"id": 30, "ula": "fd12:3456:789c::/48", "conntrack": {"maxFlows": 1048577}}`), `VRF "ops": conntrack.maxFlows 1048577 is more than 1048576`},
		{res(KindVRF, "ops", `{"id": 30, "ula": "fd12:3456:789c::/48", "conntrack": {"timeouts": {"udp": 604801, "other": 604801}}}`),
			`VRF "ops": conntrack.timeouts.udp 604801 is more than 604800 seconds`},
		{res(KindVRF, "ops", `{"id": 30, "ula": "fd12:3456:789c::/48", "conntrack": {"timeouts": {"tcp": 60}}}`), `VRF "ops": spec: json: unknown field "tcp"`},
	} {
		_, err := policyBase(t, c.r)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.r.Spec, err, c.want)
		}
	}
	// The largest values pass: the quota, the timeouts and the priority at their bounds, and 16 of each kind
	sixteen := `"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13", "t14", "t15"`
	if _, err := policyBase(t,
		res(KindVRF, "ops", `{"id": 30, "ula": "fd12:3456:789c::/48", "conntrack": {"maxFlows": 1048576, "timeouts": {"tcpEstablished": 604800, "tcpTransitory": 1, "udp": 604800, "icmp": 1, "other": 604800}}}`),
		policy("p", `{"vrf": "ops", "action": "deny", "priority": 1000000, "from": {"tags": [`+sixteen+`]}, "protocol": "tcp", "ports": [`+strings.Repeat(`0, `, 15)+`"65535"]}`),
	); err != nil {
		t.Errorf("the largest values: %v", err)
	}
}

// An end holds a Node with one of its tags, and any Node when it names none.
func TestRuleEndHolds(t *testing.T) {
	for _, c := range []struct {
		end  RuleEnd
		tags []string
		want bool
	}{
		{RuleEnd{}, nil, true},
		{RuleEnd{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, []string{"web"}, true},
		{RuleEnd{Tags: []string{"db", "web"}}, []string{"web"}, true},
		{RuleEnd{Tags: []string{"db"}}, []string{"web", "laptop"}, false},
		{RuleEnd{Tags: []string{"db"}}, nil, false},
	} {
		if got := c.end.Holds(c.tags); got != c.want {
			t.Errorf("%+v holds %v: %v, want %v", c.end, c.tags, got, c.want)
		}
	}
}

// A clone of an intent shares no slice of a Policy with it.
func TestPolicyClone(t *testing.T) {
	in, err := policyBase(t, policy("p", `{"vrf": "corp", "action": "allow", "from": {"tags": ["web"], "addresses": ["10.0.0.0/8"]}, "to": {"tags": ["db"]}, "protocol": "tcp", "ports": [22]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := in.Clone()
	p := c.Policies["p"]
	p.From.Tags[0], p.From.Addresses[0], p.To.Tags[0], p.Ports[0] = "x", "x", "x", "x"
	if got, want := string(resource(KindPolicy, "p", in.Policies["p"]).Spec), `{"vrf":"corp","action":"allow","from":{"tags":["web"],"addresses":["10.0.0.0/8"]},"to":{"tags":["db"]},"protocol":"tcp","ports":["22"]}`; got != want {
		t.Errorf("a change of the clone changed the intent:\n%s\nwant\n%s", got, want)
	}
}

// A protocol or a port is a JSON number or string, nothing else.
func TestPolicyValue(t *testing.T) {
	for in, want := range map[string]string{`443`: "443", `"8000-8080"`: "8000-8080", `null`: ""} {
		var v PolicyValue
		if err := json.Unmarshal([]byte(in), &v); err != nil || string(v) != want {
			t.Errorf("%s: %q, %v; want %q", in, v, err, want)
		}
	}
	for _, in := range []string{`true`, `[1]`, `{}`} {
		var v PolicyValue
		if err := json.Unmarshal([]byte(in), &v); err == nil {
			t.Errorf("%s: %q, want an error", in, v)
		}
	}
}
