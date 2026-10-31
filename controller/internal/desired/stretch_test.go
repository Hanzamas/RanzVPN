package desired

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// stretchResources is an intent for the tests of the Stretches: VRF dc with the L2 Networks dc-l2 and dc-l2b and the Nodes gw and
// host, and the Stretch s of gw and dc-l2, which declares every value but the limit of the BUM rate.
func stretchResources() []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "dc", `{"id": 30, "ula": "fd30:1:2::/48"}`),
		res(intent.KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"}`),
		res(intent.KindNetwork, "dc-l2b", `{"vrf": "dc", "mode": "L2"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["dc"]}`),
		res(intent.KindStretch, "s", `{"gateway": "gw", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010", "64512:10"],
			"esi": "00:11:22:33:44:55:66:77:88:99", "irb": true, "macImportLimit": 500, "staleTimer": 30}`),
	}
}

// The gateway of a Stretch gets it in the object of its Network, with the values that the Intent completed, and no other node and
// no other Network of the gateway does.
func TestCompileStretch(t *testing.T) {
	states := compile(t, stretchResources()...)
	l2 := Key{controlpb.Kind_KIND_NETWORK, "dc-l2"}
	want := &controlpb.Stretch{Vni: 5010, RouteTargets: []string{"64512:10", "65000:5010"}, Esi: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		BumRateLimit: intent.DefaultBUMRateLimit, MacImportLimit: 500, StaleTimer: 30, Irb: true}
	if got := states["gw"][l2].GetNetwork().GetStretch(); !proto.Equal(got, want) {
		t.Errorf("the Network dc-l2 of gw has the Stretch %v, want %v", got, want)
	}
	if got := states["host"][l2].GetNetwork().GetStretch(); got != nil {
		t.Errorf("the Network dc-l2 of host has the Stretch %v, want none: gw is its gateway", got)
	}
	l2b := Key{controlpb.Kind_KIND_NETWORK, "dc-l2b"}
	for _, node := range []string{"gw", "host"} {
		if got := states[node][l2b].GetNetwork().GetStretch(); got != nil {
			t.Errorf("the Network dc-l2b of %s has the Stretch %v, want none: no Stretch binds it", node, got)
		}
	}
	if got, want := states["gw"][l2].GetNetwork().GetMode(), controlpb.NetworkMode_NETWORK_MODE_L2; got != want {
		t.Errorf("the Network dc-l2 of gw is of mode %s, want %s", got, want)
	}
}

// A Stretch that declares no limit and no ESI reaches its gateway with the defaults of the Intent: 10,000 remote MAC addresses, a
// stale timer of 120 s, the BUM rate limit that is always on, irb off and no ESI.
func TestCompileStretchDefaults(t *testing.T) {
	rs := stretchResources()
	rs[5] = res(intent.KindStretch, "s", `{"gateway": "gw", "network": "dc-l2b", "vni": 5011, "routeTargets": ["65000:5011"]}`)
	states := compile(t, rs...)
	want := &controlpb.Stretch{Vni: 5011, RouteTargets: []string{"65000:5011"}, BumRateLimit: intent.DefaultBUMRateLimit, MacImportLimit: 10000, StaleTimer: 120}
	if got := states["gw"][Key{controlpb.Kind_KIND_NETWORK, "dc-l2b"}].GetNetwork().GetStretch(); !proto.Equal(got, want) {
		t.Errorf("the Network dc-l2b of gw has the Stretch %v, want %v", got, want)
	}
	if got := states["gw"][Key{controlpb.Kind_KIND_NETWORK, "dc-l2"}].GetNetwork().GetStretch(); got != nil {
		t.Errorf("the Network dc-l2 of gw has the Stretch %v, want none", got)
	}
}

// Without its Stretches the Intent compiles to states whose Networks carry none, and the update that takes the gateway from the one
// state to the other sets its Network and removes no object: the Network stays, the Stretch is gone from it.
func TestCompileWithoutStretches(t *testing.T) {
	in, err := intent.Apply(intent.New(), intent.Document{Resources: stretchResources()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	with, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	without, err := Compile(in.WithoutStretches())
	if err != nil {
		t.Fatal(err)
	}
	l2 := Key{controlpb.Kind_KIND_NETWORK, "dc-l2"}
	if got := without["gw"][l2].GetNetwork().GetStretch(); got != nil {
		t.Errorf("the Network dc-l2 of gw has the Stretch %v, want none: the Intent was compiled without its Stretches", got)
	}
	if Equal(with["gw"], without["gw"]) {
		t.Error("the state of gw is the same with and without its Stretch")
	}
	if !Equal(with["host"], without["host"]) {
		t.Error("the state of host, which is no gateway, changed with the Stretch")
	}
	u := Delta(with["gw"], 1, without["gw"], 2)
	if len(u.GetSet()) != 1 || u.GetSet()[0].GetNetwork().GetName() != "dc-l2" || u.GetSet()[0].GetNetwork().GetStretch() != nil || len(u.GetRemove()) != 0 {
		t.Errorf("the update that takes gw to the state without the Stretch is %v, want the Network dc-l2 set without it", u)
	}
	back := Delta(without["gw"], 2, with["gw"], 3)
	if len(back.GetSet()) != 1 || back.GetSet()[0].GetNetwork().GetStretch() == nil || len(back.GetRemove()) != 0 {
		t.Errorf("the update that gives the Stretch back is %v, want the Network dc-l2 set with it", back)
	}
	// The state of the gateway applies the delta as the node does
	next, err := Apply(with["gw"], 1, u)
	if err != nil || !Equal(next, without["gw"]) {
		t.Errorf("applying the update to the state of gw gave %v, %v, want the state without the Stretch", next, err)
	}
}
