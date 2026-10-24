package desired

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A node gets the Mirrors that select it, in name order, with the id of the VRF of a Mirror, 0 for
// a Mirror without one, the number of its protocol and the bytes of its sensor; a node that no
// Mirror selects gets none.
func TestCompileMirrors(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"], "tags": ["ids"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindMirror, "by-tag", `{"tag": "ids", "protocol": "udp", "port": 53, "sensor": "192.0.2.50"}`),
		res(intent.KindMirror, "by-vrf", `{"vrf": "lab", "protocol": "icmp", "sensor": "[2001:db8::5]:6081", "vni": 77, "rateLimit": 1000000}`),
		res(intent.KindMirror, "by-node", `{"node": "b", "vrf": "lab", "sensor": "192.0.2.51"}`),
	)
	v6 := netip.MustParseAddr("2001:db8::5").As16()
	want := []*controlpb.Mirror{
		{Name: "by-tag", Protocol: 17, Port: 53, Sensor: []byte{192, 0, 2, 50}, SensorPort: 4789, RateLimit: intent.DefaultMirrorRate},
		{Name: "by-vrf", VrfId: 20, Protocol: 1, Sensor: v6[:], SensorPort: 6081, Vni: 77, RateLimit: 1000000},
	}
	got := states["a"][Key{controlpb.Kind_KIND_NODE, "a"}].GetNode().GetMirrors()
	if len(got) != len(want) {
		t.Fatalf("the Mirrors of a are %v, want %v", got, want)
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Errorf("Mirror %d of a is %v, want %v", i, got[i], want[i])
		}
	}
	if got := states["b"][Key{controlpb.Kind_KIND_NODE, "b"}].GetNode().GetMirrors(); len(got) != 0 {
		t.Errorf("b, which no Mirror selects, has the Mirrors %v", got)
	}
}

// A Mirror that the intent holds, and that does not parse, fails the compile.
func TestCompileMirrorsRefuses(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindMirror, "m", `{"node": "a", "sensor": "192.0.2.50"}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(m *intent.Mirror){
		func(m *intent.Mirror) { m.Protocol = "sctp" },
		func(m *intent.Mirror) { m.Sensor = "sensor.example" },
	} {
		bad := in.Clone()
		m := bad.Mirrors["m"]
		change(&m)
		bad.Mirrors["m"] = m
		if _, err := Compile(bad); err == nil {
			t.Errorf("the compile of the Mirror %+v gave no error", m)
		}
	}
}
