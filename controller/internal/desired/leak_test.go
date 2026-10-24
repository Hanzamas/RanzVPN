package desired

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const key4 = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="

// A shared-services VRF that red and blue import from, and that imports from them, is reachable
// from both: each node of red and blue gets the address of dns as a route of its Peer dns that goes
// into VRF shared, and dns gets theirs as routes that go into red and blue. red and blue import
// nothing of each other, so their nodes are no peers of each other; two nodes of red stay peers as
// before, with no leaked route between them.
func TestCompileLeaks(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "shared", `{"id": 10, "ula": "fd00:10::/48", "exportTargets": ["64512:10"], "importTargets": ["64512:1"]}`),
		res(intent.KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(intent.KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(intent.KindNetwork, "shared-lan", `{"vrf": "shared", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(intent.KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(intent.KindNode, "dns", `{"publicKey": "`+key1+`", "vrfs": ["shared"]}`),
		res(intent.KindNode, "r", `{"publicKey": "`+key2+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "r2", `{"publicKey": "`+key4+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key3+`", "vrfs": ["blue"]}`),
	)
	for _, c := range []struct {
		node, peer string
		want       string // the VRFs shared, then each route as "vrf prefix > peer vrf"; "none" for no Peer
	}{
		{"dns", "b", "[]; 10 10.2.0.1/32 > 2"},
		{"dns", "r", "[]; 10 10.1.0.1/32 > 1"},
		{"dns", "r2", "[]; 10 10.1.0.2/32 > 1"},
		{"r", "dns", "[]; 1 10.10.0.1/32 > 10"},
		{"r", "r2", "[1]"},
		{"r", "b", "none"},
		{"r2", "dns", "[]; 1 10.10.0.1/32 > 10"},
		{"b", "dns", "[]; 2 10.10.0.1/32 > 10"},
		{"b", "r", "none"},
		{"b", "r2", "none"},
	} {
		o, ok := states[c.node][Key{controlpb.Kind_KIND_PEER, c.peer}]
		got := "none"
		if ok {
			p := o.GetPeer()
			got = fmt.Sprint(p.GetVrfIds())
			for _, r := range p.GetRoutes() {
				got += fmt.Sprintf("; %d %s > %d", r.GetVrfId(), prefixText(r.GetPrefix()), r.GetPeerVrfId())
			}
		}
		if got != c.want {
			t.Errorf("the Peer %s of %s is %q, want %q", c.peer, c.node, got, c.want)
		}
	}
	if n := len(states["dns"][Key{controlpb.Kind_KIND_PEER, "r"}].GetPeer().GetAddresses()); n != 0 {
		t.Errorf("the Peer r of dns has %d addresses, want none: they share no VRF, and its address is a leaked route", n)
	}
}

// The "connect VRF" shortcut leaks both ways, and the NAT routes of a peer and its leaked routes
// go together in one ordered list.
func TestCompileConnectedVRFs(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: []intent.Resource{
		res(intent.KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48"}`),
		res(intent.KindVRF, "blue", `{"id": 2, "ula": "fd00:2::/48"}`),
		res(intent.KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(intent.KindNetwork, "blue-lan", `{"vrf": "blue", "ipv4Pool": "10.2.0.0/24"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["blue", "red"]}`),
		res(intent.KindNAT, "b-lan", `{"vrf": "blue", "node": "b", "inside": "192.168.7.0/24", "outside": "10.99.7.0/24"}`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	connect, err := in.Connect("red", "blue")
	if err != nil {
		t.Fatal(err)
	}
	if in, err = intent.Apply(in, connect, nil); err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range states["a"][Key{controlpb.Kind_KIND_PEER, "b"}].GetPeer().GetRoutes() {
		got = append(got, fmt.Sprintf("%d %s > %d", r.GetVrfId(), prefixText(r.GetPrefix()), r.GetPeerVrfId()))
	}
	// b shares red with a, so a reaches it in red as before; blue leaks the address of b and the
	// outside prefix of its rule into red
	if want := "1 10.2.0.1/32 > 2; 1 10.99.7.0/24 > 2"; strings.Join(got, "; ") != want {
		t.Errorf("the routes of the Peer b of a are %q, want %q", strings.Join(got, "; "), want)
	}
	// and red leaks the address of a into blue, where b reaches it too
	got = nil
	for _, r := range states["b"][Key{controlpb.Kind_KIND_PEER, "a"}].GetPeer().GetRoutes() {
		got = append(got, fmt.Sprintf("%d %s > %d", r.GetVrfId(), prefixText(r.GetPrefix()), r.GetPeerVrfId()))
	}
	if want := "2 10.1.0.1/32 > 1"; strings.Join(got, "; ") != want {
		t.Errorf("the routes of the Peer a of b are %q, want %q", strings.Join(got, "; "), want)
	}
}
