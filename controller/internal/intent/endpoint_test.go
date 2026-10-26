package intent

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// endpointBase is an intent with a VRF and two Nodes for the endpoints of the tests.
func endpointBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// nodeSpec is the spec of Node a with the endpoints es, each the JSON of one endpoint.
func nodeSpec(es ...string) string {
	return `{"publicKey": "` + key1 + `", "vrfs": ["corp"], "endpoints": [` + strings.Join(es, ", ") + `]}`
}

// A Node that names endpoints has them in their one form, in the order of its resource: the transport in
// lower case, the host of a name in lower case, an IPv6 address in brackets and compressed, an IPv4-mapped IPv6
// address as an IPv4 address and the port without its zeros. They read back from the resources, apply again
// unchanged, share nothing with a clone, and a Node that names none has none.
func TestApplyEndpoints(t *testing.T) {
	in, err := Apply(endpointBase(t), doc(res(KindNode, "a", nodeSpec(
		`{"transport": "QUIC", "address": "Hub.Example.COM:0443"}`,
		`{"transport": "tls", "address": "[2001:DB8:0::1]:443"}`,
		`{"transport": "tls", "address": "192.0.2.10:8443"}`,
		`{"transport": "mimic", "address": "[::ffff:192.0.2.11]:4443"}`,
	))), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{
		{Transport: TransportQUIC, Address: "hub.example.com:443"},
		{Transport: TransportTLS, Address: "[2001:db8::1]:443"},
		{Transport: TransportTLS, Address: "192.0.2.10:8443"},
		{Transport: TransportMimic, Address: "192.0.2.11:4443"},
	}
	if got := in.Nodes["a"].Endpoints; !reflect.DeepEqual(got, want) {
		t.Errorf("the endpoints of Node a are %+v, want %+v", got, want)
	}
	if got := in.Nodes["b"].Endpoints; len(got) != 0 {
		t.Errorf("Node b names no endpoint and has %+v", got)
	}

	// They read back from the resources, and the one form applies again unchanged
	rs := in.Resources()
	back, err := FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Nodes["a"].Endpoints; !reflect.DeepEqual(got, want) {
		t.Errorf("the endpoints read back are %+v, want %+v", got, want)
	}
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || !reflect.DeepEqual(again.Nodes["a"].Endpoints, want) {
		t.Errorf("the resources applied again: %v, the endpoints %+v", err, again.Nodes["a"].Endpoints)
	}
	for _, r := range rs {
		if r.Kind == KindNode && r.Name == "b" && strings.Contains(string(r.Spec), "endpoints") {
			t.Errorf("the resource of Node b, which names none, is %s", r.Spec)
		}
	}

	// A clone shares no endpoint with the intent
	c := in.Clone()
	c.Nodes["a"].Endpoints[0].Address = "other.example.com:443"
	if in.Nodes["a"].Endpoints[0].Address != "hub.example.com:443" {
		t.Error("a change of a clone changed the endpoints of the intent")
	}

	// A resource that leaves them out takes them away: an apply replaces the whole Node
	next, err := Apply(in, doc(res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`)), nil)
	if err != nil || len(next.Nodes["a"].Endpoints) != 0 || len(in.Nodes["a"].Endpoints) != 4 {
		t.Errorf("an apply without endpoints: %v, %d left, %d in the intent before", err, len(next.Nodes["a"].Endpoints), len(in.Nodes["a"].Endpoints))
	}
}

// A malformed endpoint is refused with a message that names the Node, the place of the endpoint in its list
// and what is wrong with it: an unknown transport, an address without a port, or a host that is no DNS name.
func TestApplyEndpointsRejects(t *testing.T) {
	base := endpointBase(t)
	nine := make([]string, MaxEndpoints+1)
	for i := range nine {
		nine[i] = `{"transport": "tls", "address": "hub` + strconv.Itoa(i) + `.example.com:443"}`
	}
	for _, c := range []struct {
		spec string
		want string
	}{
		{nodeSpec(`{"transport": "udp", "address": "hub.example.com:443"}`), `Node "a": endpoints[0]: the transport must be quic, tls or mimic, not "udp"`},
		{nodeSpec(`{"address": "hub.example.com:443"}`), `the transport must be quic, tls or mimic, not ""`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:443"}`, `{"transport": "wss", "address": "hub.example.com:443"}`), `endpoints[1]: the transport must be quic, tls or mimic, not "wss"`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com"}`), `Node "a": endpoints[0]: address "hub.example.com" has no port: write host:port`},
		{nodeSpec(`{"transport": "quic"}`), `address "" has no port: write host:port`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:"}`), `address "hub.example.com:" has the port "", not a number from 1 to 65535`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:0"}`), `has the port "0", not a number from 1 to 65535`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:65536"}`), `has the port "65536", not a number from 1 to 65535`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:https"}`), `has the port "https", not a number from 1 to 65535`},
		{nodeSpec(`{"transport": "quic", "address": ":443"}`), `address ":443" has no host`},
		{nodeSpec(`{"transport": "tls", "address": "2001:db8::1:443"}`), `an IPv6 address goes in brackets, as [2001:db8::1]:443`},
		{nodeSpec(`{"transport": "tls", "address": "[2001:db8::1"}`), `is not host:port: missing ']' in address`},
		{nodeSpec(`{"transport": "tls", "address": "bad_name.example:443"}`), `address "bad_name.example:443": the host is not a DNS name: "bad_name.example" is not DNS labels`},
		{nodeSpec(`{"transport": "tls", "address": "-a.example:443"}`), `the host is not a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "a..example:443"}`), `the host is not a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "a.example.:443"}`), `the host is not a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "` + strings.Repeat("a", 64) + `.example:443"}`), `the host is not a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "` + strings.Repeat("a", 250) + `.example:443"}`), `is longer than 255 characters`},
		{nodeSpec(`{"transport": "tls", "address": "300.1.1.1:443"}`), `the host "300.1.1.1" is neither an IP address nor a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "01.2.3.4:443"}`), `is neither an IP address nor a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "1234:443"}`), `is neither an IP address nor a DNS name`},
		{nodeSpec(`{"transport": "tls", "address": "[hub]:443"}`), `"hub" in brackets is not an IP address`},
		{nodeSpec(`{"transport": "tls", "address": "[fe80::1%eth0]:443"}`), `the IP address fe80::1%eth0 has a zone`},
		{nodeSpec(`{"transport": "tls", "address": "0.0.0.0:443"}`), `0.0.0.0 is not the address of one Node`},
		{nodeSpec(`{"transport": "tls", "address": "[::]:443"}`), `:: is not the address of one Node`},
		{nodeSpec(`{"transport": "tls", "address": "[::ffff:0.0.0.0]:443"}`), `is not the address of one Node`},
		{nodeSpec(`{"transport": "tls", "address": "224.0.0.1:443"}`), `224.0.0.1 is not the address of one Node`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:443"}`, `{"transport": "QUIC", "address": "HUB.example.com:0443"}`), `endpoints[1]: quic hub.example.com:443 is listed twice`},
		{nodeSpec(`{"transport": "udp", "address": "hub.example.com"}`), `the transport must be quic, tls or mimic, not "udp"`},
		{nodeSpec(`{"transport": "udp", "address": "hub.example.com"}`), `address "hub.example.com" has no port`},
		{nodeSpec(nine...), `Node "a": it has 9 endpoints, more than 8`},
		{nodeSpec(`{"transport": "quic", "address": "hub.example.com:443", "port": 443}`), `spec: json: unknown field "port"`},
	} {
		_, err := Apply(base, doc(res(KindNode, "a", c.spec)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}
}

// ParseEndpointAddress gives the host and the port of an address in the form that net.JoinHostPort writes back,
// and refuses what is no host:port with a host that names one Node.
func TestParseEndpointAddress(t *testing.T) {
	for _, c := range []struct {
		in   string
		host string
		port uint16
	}{
		{"hub.example.com:443", "hub.example.com", 443},
		{"HUB.Example.com:443", "hub.example.com", 443},
		{"hub:443", "hub", 443},
		{"a-1.b-2.example:1", "a-1.b-2.example", 1},
		{"192.0.2.1:1", "192.0.2.1", 1},
		{"[192.0.2.1]:443", "192.0.2.1", 443},
		{"[2001:db8::1]:65535", "2001:db8::1", 65535},
		{"[2001:DB8:0:0:0:0:0:1]:443", "2001:db8::1", 443},
		{"[::ffff:192.0.2.1]:443", "192.0.2.1", 443},
		{"[::1]:443", "::1", 443},
		{"127.0.0.1:0443", "127.0.0.1", 443},
	} {
		host, port, err := ParseEndpointAddress(c.in)
		if err != nil || host != c.host || port != c.port {
			t.Errorf("ParseEndpointAddress(%q) = %q, %d, %v, want %q, %d", c.in, host, port, err, c.host, c.port)
			continue
		}
		// What it gives parses as itself
		again, p, err := ParseEndpointAddress(net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil || again != host || p != port {
			t.Errorf("ParseEndpointAddress(%q) gave %q and %d, which parse as %q, %d, %v", c.in, host, port, again, p, err)
		}
	}
	for _, in := range []string{"", "hub", ":443", "hub:0", "hub:70000", "hub:-1", "hub:+1", "hub: 1", "[::]:1", "224.0.0.1:1", "x_y:1", "1.2.3:1",
		"hub:443:80", "[hub]:1", "fe80::1%eth0", "[fe80::1%eth0]:1", "http://hub:443", "hub:443/path", "hub.:443", "hub example:443"} {
		if host, port, err := ParseEndpointAddress(in); err == nil {
			t.Errorf("ParseEndpointAddress(%q) = %q, %d, want an error", in, host, port)
		}
	}
}
