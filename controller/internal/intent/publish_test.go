package intent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// endpointJSON is a document with an Endpoint of corp into vendor, whose range overlaps the one of corp (SDN-24), for the
// fuzz test to start from.
const endpointJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 101, "ula": "fd00:101::/48"}},
  {"kind": "VRF", "name": "vendor", "spec": {"id": 202, "ula": "fd00:202::/48", "dns": true}},
  {"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}},
  {"kind": "Network", "name": "vendor-lan", "spec": {"vrf": "vendor", "ipv4Pool": "10.0.0.0/24"}},
  {"kind": "Node", "name": "app", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "addresses": {"corp-lan": "10.0.0.1"}}},
  {"kind": "Node", "name": "buyer", "spec": {"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["vendor"], "tags": ["buyer"], "addresses": {"vendor-lan": "10.0.0.1"}}},
  {"kind": "NAT", "name": "buyer-out", "spec": {"vrf": "vendor", "node": "buyer", "inside": "10.0.0.1/32", "outside": "172.16.2.1/32"}},
  {"kind": "Endpoint", "name": "billing", "spec": {"vrf": "corp", "node": "app", "address": "10.0.0.1", "port": 443, "consumer": "vendor", "as": "172.16.1.1", "consumerTags": ["buyer"]}}
]}`

// billingSpec is the Endpoint of these tests: the HTTPS port of app, which holds 10.0.0.1 in corp, published into vendor as
// 172.16.1.1 for the Nodes that have the tag buyer. plainSpec is the same for every Node of vendor.
const (
	billingSpec = `{"vrf": "corp", "node": "app", "address": "10.0.0.1", "port": 443, "consumer": "vendor", "as": "172.16.1.1", "consumerTags": ["buyer"]}`
	plainSpec   = `{"vrf": "corp", "node": "app", "address": "10.0.0.1", "port": 443, "consumer": "vendor", "as": "172.16.1.1"}`
)

// publishNet returns the resources of the Endpoint tests: corp, which uses 10.0.0.0/24, with the Nodes app (10.0.0.1) and db
// (10.0.0.5), and vendor, which has overlay DNS on and uses the range that vendor names, three bytes of an IPv4 address, with
// the Nodes buyer (tag buyer, .1) and guest (.2). With 10.0.0 the two ranges overlap, and buyer holds the address of app.
func publishNet(vendor string) []Resource {
	return []Resource{
		res(KindVRF, "corp", `{"id": 101, "ula": "fd00:101::/48"}`),
		res(KindVRF, "vendor", `{"id": 202, "ula": "fd00:202::/48", "dns": true}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "vendor-lan", `{"vrf": "vendor", "ipv4Pool": "`+vendor+`.0/24"}`),
		res(KindNode, "app", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["app"], "addresses": {"corp-lan": "10.0.0.1"}}`),
		res(KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "addresses": {"corp-lan": "10.0.0.5"}}`),
		res(KindNode, "buyer", `{"publicKey": "`+key3+`", "vrfs": ["vendor"], "tags": ["buyer"], "addresses": {"vendor-lan": "`+vendor+`.1"}}`),
		res(KindNode, "guest", `{"publicKey": "`+key4+`", "vrfs": ["vendor"], "addresses": {"vendor-lan": "`+vendor+`.2"}}`),
	}
}

// publishApply applies the resources rs and more to an empty intent.
func publishApply(rs []Resource, more ...Resource) (Intent, error) {
	return Apply(New(), doc(append(rs, more...)...), nil)
}

// billing applies the Endpoint billing over the overlapping ranges, with the 1:1 NAT rule that buyer needs to present its
// address to corp.
func billing(t *testing.T) Intent {
	t.Helper()
	in, err := publishApply(publishNet("10.0.0"), nat("buyer-out", "vendor", "buyer", "10.0.0.1/32", "172.16.2.1/32"), res(KindEndpoint, "billing", billingSpec))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// An Endpoint compiles to the 1:1 NAT rule of its Node, a rule of the policy of each VRF and the name in the zone of the
// consumer VRF, as the resources of those kinds, which the stored intent does not hold; and to the route to its published
// address into the consumer VRF, held by the consumers, and the route back to each consumer into the source VRF, held by the
// Node that serves it, where a consumer whose range overlaps the source VRF presents its address through its own 1:1 NAT rule.
func TestEndpointCompiles(t *testing.T) {
	in := billing(t)
	want := PublishedEndpoint{VRF: "corp", Node: "app", Address: "10.0.0.1", Port: 443, Protocol: "tcp", Consumer: "vendor", As: "172.16.1.1", Name: "billing",
		ConsumerTags: []string{"buyer"}}
	if got := in.Endpoints["billing"]; !reflect.DeepEqual(got, want) {
		t.Errorf("the completed Endpoint is %+v, want %+v", got, want)
	}
	if len(in.NATs) != 1 || len(in.Policies) != 0 || len(in.DNSRecords) != 0 {
		t.Errorf("the stored intent holds %d NATs, %d Policies and %d DnsRecords: only buyer-out, which the administrator declared", len(in.NATs), len(in.Policies), len(in.DNSRecords))
	}

	d := in.WithPublished()
	if got, want := d.NATs["billing.nat"], (NAT{VRF: "corp", Node: "app", Inside: "10.0.0.1/32", Outside: "172.16.1.1/32"}); got != want {
		t.Errorf("the NAT of the Endpoint is %+v, want %+v", got, want)
	}
	wantSource := Policy{VRF: "corp", Action: PolicyAllow, To: PolicyEnd{Addresses: []string{"172.16.1.1"}}, Protocol: "tcp", Ports: []PolicyValue{"443"}}
	if got := d.Policies["billing.source"]; !reflect.DeepEqual(got, wantSource) {
		t.Errorf("the rule of the source VRF is %+v, want %+v", got, wantSource)
	}
	wantConsumer := Policy{VRF: "vendor", Action: PolicyAllow, From: PolicyEnd{Tags: []string{"buyer"}}, To: PolicyEnd{Addresses: []string{"172.16.1.1"}}, Protocol: "tcp",
		Ports: []PolicyValue{"443"}}
	if got := d.Policies["billing.consumer"]; !reflect.DeepEqual(got, wantConsumer) {
		t.Errorf("the rule of the consumer VRF is %+v, want %+v", got, wantConsumer)
	}
	if got, want := d.DNSRecords["billing.dns"], (DNSRecord{VRF: "vendor", Name: "billing", Addresses: []string{"172.16.1.1"}}); !reflect.DeepEqual(got, want) {
		t.Errorf("the record of the Endpoint is %+v, want %+v", got, want)
	}
	if len(d.Rules()) != 2 {
		t.Errorf("the compiled intent holds %d rules, want the two of the Endpoint", len(d.Rules()))
	}
	suffix, records, ok := d.Zone("vendor")
	if !ok || suffix != "vendor.ranz.internal" || len(records) != 1 || records[0].Name != "billing" || len(records[0].Addresses) != 1 || records[0].Addresses[0].String() != "172.16.1.1" {
		t.Errorf("the zone of vendor is %q, %+v, %v", suffix, records, ok)
	}
	if got, want := ruleLines(d.NATRules()["app"]), "corp 10.0.0.1/32 > 172.16.1.1/32"; got != want {
		t.Errorf("app applies\n%s\nwant\n%s", got, want)
	}

	// The routes are the same whether in or the compiled intent says them
	lines := "corp 172.16.2.1/32 via buyer from vendor\nvendor 172.16.1.1/32 via app from corp"
	routes := d.LeakedRoutes()
	if got := routeLines(routes); got != lines {
		t.Errorf("the compiled intent leaks\n%s\nwant\n%s", got, lines)
	}
	if got := routeLines(in.LeakedRoutes()); got != lines {
		t.Errorf("the stored intent leaks\n%s\nwant\n%s", got, lines)
	}
	if len(routes) != 2 || !reflect.DeepEqual(routes[0].Nodes, []string{"app"}) || !reflect.DeepEqual(routes[1].Nodes, []string{"buyer"}) {
		t.Fatalf("the nodes that hold the routes are %+v", routes)
	}
	if !routes[0].HeldBy("app") || routes[0].HeldBy("db") || !routes[1].HeldBy("buyer") || routes[1].HeldBy("guest") {
		t.Errorf("the route back is held by app alone and the route to the service by buyer alone: %+v", routes)
	}
}

// An Endpoint reads back from its resource, comes after the other kinds in the resources, is left out of an import that does not
// declare it, and is deleted by name; a VRF it publishes from or into and the Node that serves it cannot be deleted.
func TestEndpointResources(t *testing.T) {
	in := billing(t)
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	rs := in.Resources()
	if last := rs[len(rs)-1]; last.Kind != KindEndpoint || last.Name != "billing" {
		t.Errorf("the last resource is %s %q, want the Endpoints last", last.Kind, last.Name)
	}
	if changes := Diff(nil, rs); changes[len(changes)-1].Kind != KindEndpoint {
		t.Errorf("the last change of a diff against nothing is %+v, want the Endpoint", changes[len(changes)-1])
	}

	var kept []Resource
	for _, r := range rs {
		if r.Kind != KindEndpoint {
			kept = append(kept, r)
		}
	}
	if next, err := Replace(in, Document{Resources: kept}, nil); err != nil || len(next.Endpoints) != 0 {
		t.Errorf("an import that does not declare the Endpoint leaves %d of them: %v", len(next.Endpoints), err)
	}
	if next, err := Replace(in, Document{Resources: rs}, nil); err != nil || len(next.Endpoints) != 1 {
		t.Errorf("an import that declares the Endpoint leaves %d of them: %v", len(next.Endpoints), err)
	}

	for _, c := range []struct{ kind, name, want string }{
		{KindVRF, "corp", `VRF "corp" is used by Network "corp-lan", Node "app", Node "db", Endpoint "billing"`},
		{KindVRF, "vendor", `Endpoint "billing"`},
		{KindNode, "app", `Node "app" serves Endpoint "billing"`},
	} {
		if _, err := Delete(in, c.kind, c.name); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("deleting %s %q: %v, want an error that says %q", c.kind, c.name, err, c.want)
		}
	}
	next, err := Delete(in, KindEndpoint, "billing")
	if err != nil || len(next.Endpoints) != 0 || len(next.WithPublished().NATs) != 1 || len(next.LeakedRoutes()) != 0 {
		t.Errorf("deleting the Endpoint: %v, %d Endpoints left", err, len(next.Endpoints))
	}
	if _, err := Delete(next, KindEndpoint, "billing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting the Endpoint again: %v, want ErrNotFound", err)
	}
	if _, err := Delete(next, KindNode, "app"); err != nil {
		t.Errorf("deleting the Node that served the Endpoint after it: %v", err)
	}
}

// An Endpoint that leaves out its protocol, its name and the order of its tags gets the one form of each, and every value that
// the control protocol or the data plane could not carry is refused.
func TestEndpointRejects(t *testing.T) {
	with := func(old, replacement string) string { return strings.Replace(plainSpec, old, replacement, 1) }
	manyTags := `"consumerTags": ["a1","a2","a3","a4","a5","a6","a7","a8","a9","b1","b2","b3","b4","b5","b6","b7","b8"], "port": 443`
	lab := res(KindVRF, "lab", `{"id": 303, "ula": "fd00:303::/48"}`)
	for _, c := range []struct {
		spec  string
		extra []Resource
		want  string
	}{
		{with(`"vrf": "corp"`, `"vrf": "nowhere"`), nil, `Endpoint "e": VRF "nowhere" does not exist`},
		{with(`"consumer": "vendor"`, `"consumer": "nowhere"`), nil, `Endpoint "e": the consumer VRF "nowhere" does not exist`},
		{with(`"consumer": "vendor"`, `"consumer": "corp"`), nil, `Endpoint "e": the consumer VRF is the source VRF "corp"`},
		{with(`"consumer": "vendor"`, `"consumer": "lab"`), []Resource{lab}, `Endpoint "e": overlay DNS is off in the consumer VRF "lab"`},
		{with(`"node": "app"`, `"node": "nobody"`), nil, `Endpoint "e": Node "nobody" does not exist`},
		{with(`"node": "app"`, `"node": "buyer"`), nil, `Endpoint "e": Node "buyer" is not a member of VRF "corp"`},
		{with(`"address": "10.0.0.1"`, `"address": "10.0.0.300"`), nil, `Endpoint "e": address: "10.0.0.300" is not an IP address`},
		{with(`"address": "10.0.0.1"`, `"address": "fe80::1%eth0"`), nil, `has a zone`},
		{with(`"address": "10.0.0.1"`, `"address": "::ffff:10.0.0.1"`), nil, `is an IPv4-mapped IPv6 address`},
		{with(`"address": "10.0.0.1"`, `"address": "127.0.0.1"`), nil, `Endpoint "e": address: "127.0.0.1" is no address of a host of the overlay`},
		{with(`"as": "172.16.1.1"`, `"as": "224.0.0.9"`), nil, `Endpoint "e": as: "224.0.0.9" is no address of a host of the overlay`},
		{with(`"as": "172.16.1.1"`, `"as": "fd00::1"`), nil, `the address 10.0.0.1 and the published address fd00::1 are of two families`},
		{with(`"as": "172.16.1.1"`, `"as": "10.0.0.1"`), nil, `the address and the published address are the same 10.0.0.1`},
		{with(`"port": 443`, `"port": 0`), nil, `port 0 is no port of a service`},
		{with(`"port": 443`, `"port": 65536`), nil, `Endpoint "e": spec: json: cannot unmarshal number 65536`},
		{with(`"port": 443`, `"protocol": "icmp", "port": 443`), nil, `protocol "icmp" must be tcp or udp`},
		{with(`"port": 443`, `"protocol": "sctp", "port": 443`), nil, `protocol "sctp" is neither tcp, udp nor icmp`},
		{with(`"port": 443`, `"name": "Bad_Name", "port": 443`), nil, `Endpoint "e": name: "Bad_Name" is not DNS labels`},
		{with(`"port": 443`, `"consumerTags": ["Bad"], "port": 443`), nil, `consumer tag "Bad" must be`},
		{with(`"port": 443`, `"consumerTags": ["a", "a"], "port": 443`), nil, `consumer tag "a" is listed twice`},
		{with(`"port": 443`, manyTags), nil, `Endpoint "e": 17 consumer tags, at most 16`},
		{with(`"port": 443`, `"colour": 1, "port": 443`), nil, `Endpoint "e": spec: json: unknown field "colour"`},
	} {
		_, err := publishApply(publishNet("10.1.0"), append([]Resource{res(KindEndpoint, "e", c.spec)}, c.extra...)...)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}
	long := strings.Repeat("a", MaxEndpointName+1)
	if _, err := publishApply(publishNet("10.1.0"), res(KindEndpoint, long, plainSpec)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `the name is longer than 54 characters`) {
		t.Errorf("an Endpoint with a name of %d characters: %v", len(long), err)
	}
	in, err := publishApply(publishNet("10.1.0"), res(KindEndpoint, "e", `{"vrf": "corp", "node": "app", "address": "10.0.0.1", "port": 53, "protocol": "UDP", "consumer": "vendor", "as": "172.16.1.1", "consumerTags": ["guest", "buyer"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := PublishedEndpoint{VRF: "corp", Node: "app", Address: "10.0.0.1", Port: 53, Protocol: "udp", Consumer: "vendor", As: "172.16.1.1", Name: "e", ConsumerTags: []string{"buyer", "guest"}}
	if got := in.Endpoints["e"]; !reflect.DeepEqual(got, want) {
		t.Errorf("the completed Endpoint is %+v, want %+v", got, want)
	}
}

// What an Endpoint compiles to is checked as the resources of its kinds are: a published address that the consumer VRF or the
// source VRF uses, a consumer whose address overlaps the source VRF and has no 1:1 NAT rule to present it, and the rules that
// two Endpoints of one service make.
func TestEndpointOverlaps(t *testing.T) {
	other := []Resource{
		res(KindVRF, "other", `{"id": 404, "ula": "fd00:404::/48", "dns": true}`),
		res(KindNetwork, "other-lan", `{"vrf": "other", "ipv4Pool": "192.168.9.0/24"}`),
	}
	for _, c := range []struct {
		name   string
		vendor string
		more   []Resource
		want   []string
	}{
		{"the published address is in the pool of the consumer VRF", "10.0.0", []Resource{res(KindEndpoint, "e", strings.Replace(plainSpec, "172.16.1.1", "10.0.0.77", 1))},
			[]string{`Endpoint "e": the published address 10.0.0.77 is published into VRF "vendor", which holds the overlapping pool 10.0.0.0/24 of Network "vendor-lan": choose a published address that the consumer VRF does not use`}},
		{"a consumer holds an address of the source VRF", "10.0.0", []Resource{res(KindEndpoint, "e", plainSpec)},
			[]string{`Endpoint "e": the address 10.0.0.1 of Node "buyer" must route back in VRF "corp"`, `Endpoint "e": the address 10.0.0.2 of Node "guest" must route back in VRF "corp"`,
				`a leaked overlapping prefix needs 1:1 NAT (ADR-0025 decision 8), so give Node "buyer" a 1:1 NAT rule in VRF "vendor" whose inside holds 10.0.0.1, and the address leaks as the outside of the rule`}},
		{"the 1:1 NAT rule of a consumer presents an address of the source VRF", "10.1.0", []Resource{nat("buyer-out", "vendor", "buyer", "10.1.0.1/32", "10.0.0.200/32"), res(KindEndpoint, "e", plainSpec)},
			[]string{`Endpoint "e": the outside 10.0.0.200/32 of NAT "buyer-out" must route back in VRF "corp"`, `give NAT "buyer-out" an outside prefix that VRF "corp" does not use`}},
		{"the published address is in the pool of the source VRF", "10.1.0", append([]Resource{res(KindEndpoint, "e", strings.NewReplacer("172.16.1.1", "10.0.0.77", `"vendor"`, `"other"`).Replace(plainSpec))}, other...),
			[]string{`NAT "e.nat": the outside 10.0.0.77/32 overlaps the pool 10.0.0.0/24 of Network "corp-lan"`}},
		{"two Endpoints publish one service at two addresses", "10.1.0", []Resource{res(KindEndpoint, "a", plainSpec), res(KindEndpoint, "b", strings.Replace(plainSpec, "172.16.1.1", "172.16.1.2", 1))},
			[]string{`NAT "a.nat": the inside 10.0.0.1/32 overlaps the inside 10.0.0.1/32 of NAT "b.nat"`}},
		{"the name of an Endpoint is the name of a Node", "10.1.0", []Resource{res(KindEndpoint, "guest", plainSpec)},
			[]string{`DnsRecord "guest.dns": "guest" is the name of Node "guest"`}},
	} {
		_, err := publishApply(publishNet(c.vendor), c.more...)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: the error is %v, want ErrInvalid", c.name, err)
			continue
		}
		for _, want := range c.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error\n%v\nlacks %q", c.name, err, want)
			}
		}
	}
}

// Two Endpoints that publish two ports of one service at one address share its 1:1 NAT rule and its routes, and a route that a
// leak of route targets holds for every member of the VRF is not added again.
func TestEndpointsShareRoutes(t *testing.T) {
	in, err := publishApply(publishNet("10.1.0"), res(KindEndpoint, "web-443", plainSpec),
		res(KindEndpoint, "web-80", strings.NewReplacer(`"port": 443`, `"port": 80`, `"consumer"`, `"name": "web-http", "consumer"`).Replace(plainSpec)))
	if err != nil {
		t.Fatal(err)
	}
	d := in.WithPublished()
	if _, ok := d.NATs["web-443.nat"]; !ok || len(d.NATs) != 1 {
		t.Errorf("the NAT rules of two Endpoints of one service are %+v, want web-443.nat alone", d.NATs)
	}
	if len(d.Policies) != 4 || len(d.DNSRecords) != 2 || d.DNSRecords["web-80.dns"].Name != "web-http" {
		t.Errorf("the compiled intent holds %d rules and the records %+v", len(d.Policies), d.DNSRecords)
	}
	routes := d.LeakedRoutes()
	if want := "corp 10.1.0.1/32 via buyer from vendor\ncorp 10.1.0.2/32 via guest from vendor\nvendor 172.16.1.1/32 via app from corp"; routeLines(routes) != want {
		t.Errorf("the compiled intent leaks\n%s\nwant\n%s", routeLines(routes), want)
	}
	if len(routes) != 3 || !reflect.DeepEqual(routes[2].Nodes, []string{"buyer", "guest"}) {
		t.Errorf("the nodes that hold the route to the service are %+v", routes)
	}

	// corp leaks its routes into vendor with route targets, which holds the route to the published address already
	rs := publishNet("10.1.0")
	rs[0] = res(KindVRF, "corp", `{"id": 101, "ula": "fd00:101::/48", "exportTargets": ["64512:101"]}`)
	rs[1] = res(KindVRF, "vendor", `{"id": 202, "ula": "fd00:202::/48", "dns": true, "importTargets": ["64512:101"]}`)
	in, err = publishApply(rs, res(KindEndpoint, "billing", billingSpec))
	if err != nil {
		t.Fatal(err)
	}
	routes = in.WithPublished().LeakedRoutes()
	if want := "corp 10.1.0.1/32 via buyer from vendor\nvendor 10.0.0.5/32 via db from corp\nvendor 172.16.1.1/32 via app from corp"; routeLines(routes) != want {
		t.Errorf("the compiled intent leaks\n%s\nwant\n%s", routeLines(routes), want)
	}
	if len(routes) != 3 || !reflect.DeepEqual(routes[0].Nodes, []string{"app"}) || routes[1].Nodes != nil || routes[2].Nodes != nil {
		t.Errorf("the nodes that hold the routes are %+v: the route back alone is held by app", routes)
	}
}

// An Endpoint whose Node is gone, as for a Node that a licence leaves out, or that does not parse, compiles to nothing, and one
// that no Node of its consumer VRF can use (no tag that matches) leaks nothing but keeps its other resources.
func TestEndpointThatCompilesToNothing(t *testing.T) {
	in := billing(t)
	gone := in.Without([]string{"app"})
	if d := gone.WithPublished(); len(d.NATs) != 1 || len(d.Policies) != 0 || len(d.DNSRecords) != 0 || len(d.LeakedRoutes()) != 0 {
		t.Errorf("the Endpoint of a Node that is gone compiles to %d NATs, %d rules, %d records and the routes %v", len(d.NATs), len(d.Policies), len(d.DNSRecords), d.LeakedRoutes())
	}
	junk := in.Clone()
	junk.Endpoints["junk"] = PublishedEndpoint{VRF: "corp", Node: "app", Address: "x", As: "172.16.9.9", Protocol: "tcp", Port: 1, Consumer: "vendor", Name: "junk"}
	junk.Endpoints["nowhere"] = PublishedEndpoint{VRF: "nowhere", Node: "app", Address: "10.0.0.1", As: "172.16.9.9", Protocol: "tcp", Port: 1, Consumer: "vendor", Name: "nowhere"}
	junk.Endpoints["lost"] = PublishedEndpoint{VRF: "corp", Node: "app", Address: "10.0.0.1", As: "172.16.9.9", Protocol: "tcp", Port: 1, Consumer: "nowhere", Name: "lost"}
	junk.Endpoints["stranger"] = PublishedEndpoint{VRF: "corp", Node: "buyer", Address: "10.0.0.1", As: "172.16.9.9", Protocol: "tcp", Port: 1, Consumer: "vendor", Name: "stranger"}
	if d := junk.WithPublished(); len(d.NATs) != 2 || len(d.Policies) != 2 || len(d.DNSRecords) != 1 || len(d.LeakedRoutes()) != 2 {
		t.Errorf("four Endpoints that compile to nothing add %d NATs, %d rules, %d records and %d routes beside the Endpoint billing", len(d.NATs)-1, len(d.Policies)-2, len(d.DNSRecords)-1, len(d.LeakedRoutes())-2)
	}

	tagged, err := publishApply(publishNet("10.1.0"), res(KindEndpoint, "e", strings.Replace(plainSpec, `"as"`, `"consumerTags": ["nobody-has-this"], "as"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if d := tagged.WithPublished(); len(d.NATs) != 1 || len(d.Policies) != 2 || len(d.LeakedRoutes()) != 0 {
		t.Errorf("an Endpoint that no Node uses compiles to %d NATs, %d rules and the routes %v", len(d.NATs), len(d.Policies), d.LeakedRoutes())
	}
}

// An Endpoint of IPv6 publishes the address of a service at an address of the ULA of its source VRF, which a consumer of the
// other ULA needs no 1:1 NAT rule to route back to; a protocol and the name of the service are written in their one form.
func TestEndpointOfIPv6(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 101, "ula": "fd00:101::/48"}`),
		res(KindVRF, "vendor", `{"id": 202, "ula": "fd00:202::/48", "dns": true}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd00:101:0:1::/64"}`),
		res(KindNetwork, "vendor-lan", `{"vrf": "vendor", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd00:202:0:1::/64"}`),
		res(KindNode, "app", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "addresses": {"corp-lan": "10.0.0.1"}, "ipv6Addresses": {"corp-lan": "fd00:101:0:1::10"}}`),
		res(KindNode, "buyer", `{"publicKey": "`+key3+`", "vrfs": ["vendor"], "addresses": {"vendor-lan": "10.0.0.1"}, "ipv6Addresses": {"vendor-lan": "fd00:202:0:1::10"}}`),
		res(KindEndpoint, "web6", `{"vrf": "corp", "node": "app", "address": "FD00:101:0:1::10", "port": 8443, "protocol": "UDP", "consumer": "vendor", "as": "fd00:101:0:9::10", "name": "web.v6"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := in.WithPublished()
	if got, want := d.NATs["web6.nat"], (NAT{VRF: "corp", Node: "app", Inside: "fd00:101:0:1::10/128", Outside: "fd00:101:0:9::10/128"}); got != want {
		t.Errorf("the NAT of the Endpoint is %+v, want %+v", got, want)
	}
	if p := d.Policies["web6.source"]; p.Protocol != "udp" || !reflect.DeepEqual(p.Ports, []PolicyValue{"8443"}) || !reflect.DeepEqual(p.To.Addresses, []string{"fd00:101:0:9::10"}) {
		t.Errorf("the rule of the source VRF is %+v", p)
	}
	if got, want := routeLines(d.LeakedRoutes()), "corp fd00:202:0:1::10/128 via buyer from vendor\nvendor fd00:101:0:9::10/128 via app from corp"; got != want {
		t.Errorf("the compiled intent leaks\n%s\nwant\n%s", got, want)
	}
	if _, records, _ := d.Zone("vendor"); len(records) != 1 || records[0].Name != "web.v6" || records[0].Addresses[0].String() != "fd00:101:0:9::10" {
		t.Errorf("the zone of vendor holds %+v", records)
	}
}
