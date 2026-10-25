package intent

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The key of a Device in these tests: any 32 bytes, base64.
const deviceKey = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="

// deviceLab returns the intent of a VRF with an L3 Network, the gateway gw and the node host, and
// the Device phone of the Network through gw.
func deviceLab(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`),
		res(KindNetwork, "lab-l2", `{"vrf": "lab", "mode": "L2", "ipv4Pool": "10.71.0.0/24"}`),
		res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "GW.Example.net"}}`),
		res(KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
		res(KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`", "tags": ["phones", "alice"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// A Device takes the lowest free host address of each pool of its Network after the Nodes, and
// keeps it when it is applied again, when a Node that sorts first comes, and when it declares the
// address it holds; a Node may not take its address, nor it the address of a Node. The WireGuard
// end of a gateway and the tags of a Device take their one form.
func TestDeviceAddresses(t *testing.T) {
	in := deviceLab(t)
	d := in.Devices["phone"]
	if d.Address != "10.70.0.3" || d.IPv6Address != "fd07:7:7:1::3" {
		t.Fatalf("Device phone holds %q and %q, want 10.70.0.3 and fd07:7:7:1::3", d.Address, d.IPv6Address)
	}
	if strings.Join(d.Tags, ",") != "alice,phones" {
		t.Errorf("the tags of Device phone are %v, want them sorted", d.Tags)
	}
	if w := in.Nodes["gw"].WireGuard; w.Endpoint != "gw.example.net" || w.Port != DefaultWireGuardPort {
		t.Errorf("the WireGuard end of gw is %+v, want gw.example.net and port %d", w, DefaultWireGuardPort)
	}
	for family, want := range map[int]string{4: "10.70.0.3/32", 6: "fd07:7:7:1::3/128"} {
		if p, ok := in.DeviceAddress("phone", family); !ok || p.String() != want {
			t.Errorf("the IPv%d address of Device phone is %v (%v), want %s", family, p, ok, want)
		}
	}

	next, err := Apply(in, doc(
		res(KindNode, "alpha", `{"publicKey": "`+key3+`", "vrfs": ["lab"]}`),
		res(KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`", "address": "10.70.0.3"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := next.Devices["phone"]; d.Address != "10.70.0.3" || d.IPv6Address != "fd07:7:7:1::3" {
		t.Errorf("after a Node that sorts first, Device phone holds %q and %q, want what it held", d.Address, d.IPv6Address)
	}
	if got := addressesOf(next, "alpha"); got != "lab-net=10.70.0.4" {
		t.Errorf("Node alpha holds %q, want lab-net=10.70.0.4, past the address of the Device", got)
	}
	// The pools in Network order: the IPv4 pool of lab-l2, then the IPv4 and the IPv6 pool of lab-net
	if u := next.Pools()[1]; u.Network != "lab-net" || u.Allocated != 4 {
		t.Errorf("the pools are %+v, want the IPv4 pool of lab-net with 4 addresses allocated: 3 Nodes and the Device", next.Pools())
	}

	for _, c := range []struct {
		name string
		res  Resource
		want string
	}{
		{"a Node on the address of the Device", res(KindNode, "alpha", `{"publicKey": "`+key3+`", "vrfs": ["lab"], "addresses": {"lab-net": "10.70.0.3"}}`),
			`Node "alpha": address 10.70.0.3 of Network "lab-net" is already the address of Device "phone"`},
		{"a Device on the address of a Node", res(KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`", "address": "10.70.0.2"}`),
			`Device "phone": address 10.70.0.2 of Network "lab-net" is already the address of Node "host"`},
		{"a Device on an address outside the pool", res(KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`", "address": "10.99.0.2"}`),
			`Device "phone": address 10.99.0.2 is not a host address of the pool 10.70.0.0/24 of Network "lab-net"`},
	} {
		if _, err := Apply(in, doc(c.res), nil); err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.want)
		}
	}
}

// The intent refuses a Device that cannot join: its Network is L2 or missing, its gateway is
// missing, not in the VRF or has no WireGuard end, its key is the key of another Device, or the
// WireGuard end of its gateway is no DNS name.
func TestDeviceRefusals(t *testing.T) {
	in := deviceLab(t)
	for _, c := range []struct {
		name string
		res  []Resource
		want string
	}{
		{"an L2 Network", []Resource{res(KindDevice, "tab", `{"network": "lab-l2", "gateway": "gw", "publicKey": "`+key3+`"}`)},
			`Device "tab": Network "lab-l2" is an L2 Network, and a Device joins an L3 Network: WireGuard carries no L2`},
		{"no Network", []Resource{res(KindDevice, "tab", `{"network": "none", "gateway": "gw", "publicKey": "`+key3+`"}`)},
			`Device "tab": Network "none" does not exist`},
		{"no gateway", []Resource{res(KindDevice, "tab", `{"network": "lab-net", "gateway": "none", "publicKey": "`+key3+`"}`)},
			`Device "tab": its gateway, Node "none", does not exist`},
		{"a gateway without a WireGuard end", []Resource{res(KindDevice, "tab", `{"network": "lab-net", "gateway": "host", "publicKey": "`+key3+`"}`)},
			`Device "tab": its gateway, Node "host", has no wireguard end`},
		{"the key of another Device", []Resource{res(KindDevice, "tab", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`"}`)},
			`Device "tab": the publicKey is already the key of Device "phone"`},
		{"a gateway outside the VRF", []Resource{
			res(KindVRF, "other", `{"id": 8, "ula": "fd08:8:8::/48"}`),
			res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["other"], "wireguard": {"endpoint": "gw.example.net"}}`)},
			`Device "phone": its gateway, Node "gw", is not in VRF "lab" of Network "lab-net"`},
		{"an endpoint that is no DNS name", []Resource{res(KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw example"}}`)},
			`Node "gw": wireguard.endpoint "gw example" is not a DNS name`},
	} {
		if _, err := Apply(in, doc(c.res...), nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.want)
		}
	}
	for _, c := range []struct{ kind, name, want string }{
		{KindNode, "gw", `Node "gw" is the gateway of Device "phone"`},
		{KindNetwork, "lab-net", `Network "lab-net" is used by Device "phone"`},
	} {
		if _, err := Delete(in, c.kind, c.name); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("deleting %s %s: %v, want an error that says %q", c.kind, c.name, err, c.want)
		}
	}
	next, err := Delete(in, KindDevice, "phone")
	if err != nil || len(next.Devices) != 0 {
		t.Errorf("deleting Device phone: %v, %d Devices left", err, len(next.Devices))
	}
}

// A Device counts as a client node for the licence, after the Nodes: a cap that the Nodes fill
// leaves no Device, and a Device whose gateway is above the cap goes with it.
func TestCappedCountsDevices(t *testing.T) {
	in := deviceLab(t)
	if in.Licensed() != 3 {
		t.Errorf("the intent counts %d nodes for the licence, want 3: two Nodes and a Device", in.Licensed())
	}
	for _, c := range []struct {
		n       int
		nodes   string
		devices int
	}{
		{3, "gw,host", 1},
		{2, "gw,host", 0},
		{1, "gw", 0},
	} {
		got := in.Capped(c.n)
		if names := strings.Join(sortedNames(got.Nodes), ","); names != c.nodes || len(got.Devices) != c.devices {
			t.Errorf("Capped(%d) keeps the Nodes %s and %d Devices, want %s and %d", c.n, names, len(got.Devices), c.nodes, c.devices)
		}
	}
	if len(in.Devices) != 1 {
		t.Errorf("Capped changed the intent it was given: %v", in.Devices)
	}
	if got := strings.Join(in.AddedDevices(New()), ","); got != `Device "phone"` {
		t.Errorf("the Devices added to an empty intent are %s", got)
	}
}

// The configuration of a Device names its addresses, the MTU of its VRF and its gateway with the key
// that the gateway reported, routes the pools of every Network of the VRF to it and keeps the NAT
// mapping of the Device open, unless the battery saver turns the keepalive off. Without a key of the
// gateway there is no configuration.
func TestDeviceConfig(t *testing.T) {
	in := deviceLab(t)
	key := make([]byte, KeySize)
	got, err := in.DeviceConfig("phone", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.70.0.3/32, fd07:7:7:1::3/128\n",
		"MTU = 1280\n",
		"PublicKey = " + base64.StdEncoding.EncodeToString(key) + "\n",
		"Endpoint = gw.example.net:51820\n",
		"AllowedIPs = 10.70.0.0/24, 10.71.0.0/24, fd07:7:7:1::/64\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the configuration of phone has no line %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\nPrivateKey") || strings.Contains(got, "DNS") {
		t.Errorf("the configuration of phone holds a private key or a DNS line:\n%s", got)
	}
	saver, err := Apply(in, doc(res(KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+deviceKey+`", "batterySaver": true}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := saver.DeviceConfig("phone", key); err != nil || strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("with the battery saver the configuration is %v:\n%s", err, got)
	}
	if _, err := in.DeviceConfig("phone", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("without a key of the gateway: %v, want ErrNotFound", err)
	}
	if _, err := in.DeviceConfig("tablet", key); !errors.Is(err, ErrNotFound) {
		t.Errorf("a Device that does not exist: %v, want ErrNotFound", err)
	}
}
