package intent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// mirrorBase is an intent with two VRFs and two Nodes for the Mirrors of the tests: a in both VRFs
// with the tag ids, b in lab only.
func mirrorBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"], "tags": ["ids"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// A Mirror gets the port of its sensor and the default rate limit, and selects the Nodes that
// match each part of its source.
func TestApplyMirror(t *testing.T) {
	in, err := Apply(mirrorBase(t), doc(
		res(KindMirror, "by-tag", `{"tag": "ids", "protocol": "udp", "port": 53, "sensor": "192.0.2.50"}`),
		res(KindMirror, "by-vrf", `{"vrf": "lab", "protocol": "icmp", "sensor": "[2001:db8::5]:6081", "vni": 77, "rateLimit": 1000000}`),
		res(KindMirror, "by-node", `{"node": "b", "vrf": "corp", "sensor": "::ffff:192.0.2.51"}`),
		res(KindMirror, "by-name", `{"node": "a", "protocol": "47", "sensor": "192.0.2.52:4790"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := in.Mirrors["by-tag"]; m.Sensor != "192.0.2.50:4789" || m.RateLimit != DefaultMirrorRate {
		t.Errorf("the Mirror by-tag is %+v, want the sensor 192.0.2.50:4789 and the rate limit %d", m, DefaultMirrorRate)
	}
	if m := in.Mirrors["by-vrf"]; m.Sensor != "[2001:db8::5]:6081" || m.RateLimit != 1000000 || m.VNI != 77 {
		t.Errorf("the Mirror by-vrf is %+v, want its own sensor port, rate limit and vni", m)
	}
	if m := in.Mirrors["by-node"]; m.Sensor != "192.0.2.51:4789" {
		t.Errorf("the sensor of by-node is %q, want the IPv4 address 192.0.2.51:4789", m.Sensor)
	}
	for _, c := range []struct {
		node string
		want []string
	}{
		{"a", []string{"by-name", "by-tag", "by-vrf"}},
		{"b", []string{"by-vrf"}},
		{"c", nil},
	} {
		if got := in.MirrorsOf(c.node); !slices.Equal(got, c.want) {
			t.Errorf("the Mirrors of %s are %v, want %v", c.node, got, c.want)
		}
	}

	// The Mirrors read back from the resources, after the Policies and before the Controllers
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Mirrors) != 4 || back.Mirrors["by-vrf"] != in.Mirrors["by-vrf"] {
		t.Errorf("the Mirrors read back are %+v, want %+v", back.Mirrors, in.Mirrors)
	}
	if kindOrder(KindMirror) <= kindOrder(KindPolicy) || kindOrder(KindMirror) >= kindOrder(KindController) {
		t.Error("a Mirror is not ordered between the Policies and the Controllers")
	}

	// An import of a document without the Mirrors takes them away
	var rest []Resource
	for _, r := range in.Resources() {
		if r.Kind != KindMirror || r.Name == "by-tag" {
			rest = append(rest, r)
		}
	}
	next, err := Replace(in, Document{Resources: rest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Mirrors) != 1 || next.MirrorsOf("b") != nil {
		t.Errorf("after the import the Mirrors are %+v, want by-tag alone", next.Mirrors)
	}
}

func TestApplyMirrorRejects(t *testing.T) {
	base := mirrorBase(t)
	big, err := Apply(base, doc(res(KindVRF, "big", `{"id": 16777216, "ula": "fd12:3456:789c::/48"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		spec string
		want string
	}{
		{`{"sensor": "192.0.2.50"}`, `Mirror "m": the source needs a tag, a node or a vrf`},
		{`{"tag": "IDS", "sensor": "192.0.2.50"}`, `Mirror "m": tag "IDS" must be`},
		{`{"node": "-a", "sensor": "192.0.2.50"}`, `Mirror "m": node "-a" is not the name of a Node`},
		{`{"vrf": "dmz", "sensor": "192.0.2.50"}`, `Mirror "m": VRF "dmz" does not exist`},
		{`{"tag": "ids", "protocol": "sctp", "sensor": "192.0.2.50"}`, `protocol "sctp" is neither tcp, udp nor icmp`},
		{`{"tag": "ids", "protocol": "0", "sensor": "192.0.2.50"}`, `protocol "0" is neither`},
		{`{"tag": "ids", "protocol": "256", "sensor": "192.0.2.50"}`, `protocol "256" is neither`},
		{`{"tag": "ids", "protocol": "06", "sensor": "192.0.2.50"}`, `protocol "06" is neither`},
		{`{"tag": "ids", "protocol": "icmp", "port": 53, "sensor": "192.0.2.50"}`, `port 53 needs the protocol tcp or udp, or none, not "icmp"`},
		{`{"tag": "ids", "sensor": "sensor.example"}`, `sensor "sensor.example" is neither an IP address nor an IP address and a port`},
		{`{"tag": "ids"}`, `sensor "" is neither`},
		{`{"tag": "ids", "sensor": "0.0.0.0"}`, `needs a unicast IP address without a zone`},
		{`{"tag": "ids", "sensor": "[ff02::1]:4789"}`, `needs a unicast IP address`},
		{`{"tag": "ids", "sensor": "192.0.2.50:0"}`, `a port other than 0`},
		{`{"tag": "ids", "sensor": "fe80::1%eth0"}`, `without a zone`},
		{`{"tag": "ids", "sensor": "192.0.2.50", "vni": 16777216}`, `vni 16777216 has more than 24 bits`},
		{`{"tag": "ids", "sensor": "192.0.2.50", "mirror": true}`, `spec: json: unknown field "mirror"`},
	} {
		_, err := Apply(base, doc(res(KindMirror, "m", c.spec)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}

	// The id of a VRF is the VNI of a copy when the Mirror has none, so it must fit in 24 bits
	if _, err := Apply(big, doc(res(KindMirror, "m", `{"vrf": "big", "sensor": "192.0.2.50"}`)), nil); err == nil || !strings.Contains(err.Error(), `the id 16777216 of VRF "big" has more than the 24 bits of a VNI`) {
		t.Errorf("a Mirror without a vni of a VRF with a 25-bit id: %v, want an error", err)
	}
	if _, err := Apply(big, doc(res(KindMirror, "m", `{"tag": "ids", "sensor": "192.0.2.50"}`)), nil); err == nil || !strings.Contains(err.Error(), `VRF "big"`) {
		t.Errorf("a Mirror without a vni or a VRF, beside a VRF with a 25-bit id: %v, want an error", err)
	}
	if _, err := Apply(big, doc(res(KindMirror, "m", `{"vrf": "big", "sensor": "192.0.2.50", "vni": 9}`)), nil); err != nil {
		t.Errorf("a Mirror with a vni of a VRF with a 25-bit id: %v", err)
	}

	// A node takes MaxMirrors at most
	var rs []Resource
	for i := range MaxMirrors + 1 {
		rs = append(rs, res(KindMirror, fmt.Sprintf("m%d", i), `{"node": "a", "sensor": "192.0.2.50"}`))
	}
	if _, err := Apply(base, doc(rs...), nil); err == nil || !strings.Contains(err.Error(), `Node "a": 17 Mirrors select it, more than the 16`) {
		t.Errorf("%d Mirrors of one Node: %v, want an error", MaxMirrors+1, err)
	}
	if _, err := Apply(base, doc(rs[:MaxMirrors]...), nil); err != nil {
		t.Errorf("%d Mirrors of one Node: %v", MaxMirrors, err)
	}
}

// A VRF that a Mirror names cannot be deleted; the Mirror can.
func TestDeleteMirror(t *testing.T) {
	in, err := Apply(mirrorBase(t), doc(res(KindMirror, "m", `{"vrf": "corp", "sensor": "192.0.2.50"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindVRF, "corp"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Mirror "m"`) {
		t.Errorf("deleting VRF corp, which Mirror m names: %v, want an error that names the Mirror", err)
	}
	next, err := Delete(in, KindMirror, "m")
	if err != nil || len(next.Mirrors) != 0 || len(in.Mirrors) != 1 {
		t.Errorf("deleting Mirror m: %v, %d Mirrors left, %d in the intent before", err, len(next.Mirrors), len(in.Mirrors))
	}
	if _, err := Delete(next, KindMirror, "m"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting Mirror m again: %v, want ErrNotFound", err)
	}
	if _, err := Delete(next, "Router", "r"); err == nil || !strings.Contains(err.Error(), "Policy, Mirror, Controller, NAT, DnsRecord, Group, User, Listener, Device, SessionProfile or Stretch") {
		t.Errorf("deleting a resource of no kind: %v, want an error that lists the kinds", err)
	}
}
