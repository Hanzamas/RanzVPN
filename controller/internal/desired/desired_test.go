package desired

import (
	"encoding/json"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const (
	key1 = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	key2 = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="
)

func compile(t *testing.T, rs ...intent.Resource) map[string]State {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func res(kind, name, spec string) intent.Resource {
	return intent.Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
}

// A node gets itself, its VRFs with their Networks, and the nodes it shares a VRF with as
// peers; nothing of a VRF it is not a member of.
func TestCompile(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	)
	got := states["b"].keys()
	want := []Key{
		{controlpb.Kind_KIND_NODE, "b"},
		{controlpb.Kind_KIND_VRF, "lab"},
		{controlpb.Kind_KIND_NETWORK, "lab-lan"},
		{controlpb.Kind_KIND_PEER, "a"},
	}
	if len(got) != len(want) {
		t.Fatalf("the state of b holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the state of b holds %v, want %v", got, want)
		}
	}
	peer := states["b"][Key{controlpb.Kind_KIND_PEER, "a"}].GetPeer()
	if ids := peer.GetVrfIds(); len(ids) != 1 || ids[0] != 20 {
		t.Errorf("the peer a of b shares the VRFs %v, want [20]", ids)
	}
	if n := len(states["a"]); n != 6 {
		t.Errorf("the state of a holds %d objects, want 6 (itself, 2 VRFs, 2 Networks, 1 peer)", n)
	}
}

// A relay is a Relay object of each node it shares a VRF with, with its key and its address, and
// of no other node (ADR-0015).
func TestCompileRelays(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"], "relay": "[2001:db8::7]:7000"}`),
	)
	if _, ok := states["a"][Key{controlpb.Kind_KIND_RELAY, "b"}]; ok {
		t.Error("a, which shares no VRF with the relay b, has a Relay object of it")
	}

	states = compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "relay": "[::ffff:192.0.2.10]:7000"}`),
	)
	relay := states["a"][Key{controlpb.Kind_KIND_RELAY, "b"}].GetRelay()
	if relay == nil || len(relay.GetPublicKey()) != 32 || len(relay.GetAddress()) != 4 || relay.GetPort() != 7000 {
		t.Errorf("the Relay object of b in the state of a is %v, want b's key, the IPv4 address 192.0.2.10 and port 7000", relay)
	}
	if _, ok := states["b"][Key{controlpb.Kind_KIND_RELAY, "b"}]; ok {
		t.Error("the relay b has a Relay object of itself")
	}
}

// Apply of the delta from one state to another gives the other, and the delta holds only what
// changed.
func TestDeltaApply(t *testing.T) {
	from := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "lan", `{"vrf": "corp"}`),
		res(intent.KindNetwork, "dmz", `{"vrf": "corp"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	)["a"]
	to := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}`),
		res(intent.KindNetwork, "lan", `{"vrf": "corp"}`),
		res(intent.KindNetwork, "wan", `{"vrf": "corp"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	)["a"]

	u := Delta(from, 4, to, 5)
	if u.GetGeneration() != 5 || u.GetBaseGeneration() != 4 {
		t.Errorf("the delta goes from %d to %d, want 4 to 5", u.GetBaseGeneration(), u.GetGeneration())
	}
	var set []Key
	for _, o := range u.GetSet() {
		set = append(set, KeyOf(o))
	}
	if len(set) != 2 || set[0] != (Key{controlpb.Kind_KIND_VRF, "corp"}) || set[1] != (Key{controlpb.Kind_KIND_NETWORK, "wan"}) {
		t.Errorf("the delta sets %v, want the VRF corp and the Network wan", set)
	}
	if r := u.GetRemove(); len(r) != 1 || r[0].GetKind() != controlpb.Kind_KIND_NETWORK || r[0].GetName() != "dmz" {
		t.Errorf("the delta removes %v, want the Network dmz", r)
	}

	got, err := Apply(from, 4, u)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, to) {
		t.Error("the delta applied to the old state is not the new state")
	}
	if _, err := Apply(from, 3, u); err == nil {
		t.Error("a delta from generation 4 applied to generation 3")
	}
	full, err := FromFull(Full(to, 5))
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(full, to) {
		t.Error("the full update does not carry the state")
	}
	if u := Delta(from, 0, to, 1); u.GetBaseGeneration() != 0 || len(u.GetSet()) != len(to) || len(u.GetRemove()) != 0 {
		t.Error("the delta from generation 0 is not the full state")
	}
}
