package controller

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The static keys of the Nodes of the tests of the pool event: the public keys of the fixed keys
// 1, 33 and 97 of the conformance tests.
const (
	poolKey1 = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	poolKey2 = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="
)

func poolResource(kind, name, spec string) intent.Resource {
	return intent.Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
}

// poolApply applies rs to prev, as the controller does before it compares the pools of the two.
func poolApply(t *testing.T, prev intent.Intent, rs ...intent.Resource) intent.Intent {
	t.Helper()
	next, err := intent.Apply(prev, intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// checkPoolEvent checks that evs is the one event of revision rev that says want.
func checkPoolEvent(t *testing.T, evs []event.Event, rev intent.Revision, want string) {
	t.Helper()
	if len(evs) != 1 {
		t.Errorf("the events are %+v, want one that says %q", evs, want)
		return
	}
	if e := evs[0]; e.Type != event.PoolNearExhaustion || e.Message != want || e.Revision != rev.ID || !e.Time.Equal(rev.Time) {
		t.Errorf("the event is %+v, want a %s event of revision %d at %v that says %q", e, event.PoolNearExhaustion, rev.ID, rev.Time, want)
	}
}

// A change that takes a pool to its threshold raises one event; a change that leaves the pool
// there raises none; the pool that falls below its threshold and is taken there again raises
// another. A pool that another prefix replaces is a new pool, and a pool that a Network sets at
// its threshold with its reservations alone raises the event when the Network is applied.
func TestPoolEvents(t *testing.T) {
	rev := intent.Revision{ID: 7, Time: time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)}
	vrf := poolResource(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)
	node := func(name, key string) intent.Resource {
		return poolResource(intent.KindNode, name, `{"publicKey": "`+key+`", "vrfs": ["corp"]}`)
	}

	// The default threshold, 80 percent: a /30 holds 2 host addresses
	empty := poolApply(t, intent.New(), vrf, poolResource(intent.KindNetwork, "tiny", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/30"}`))
	one := poolApply(t, empty, node("a", poolKey1))
	two := poolApply(t, one, node("b", poolKey2))
	if evs := poolEvents(empty, one, rev); len(evs) != 0 {
		t.Errorf("a pool at 50 percent raised the events %+v", evs)
	}
	checkPoolEvent(t, poolEvents(one, two, rev), rev,
		`Network "tiny" of VRF "corp": the IPv4 pool 10.0.0.0/30 is 100% used (2 of its 2 addresses), at or above its threshold of 80%`)
	if evs := poolEvents(two, two, rev); len(evs) != 0 {
		t.Errorf("a change that leaves the pool at its threshold raised the events %+v", evs)
	}
	if evs := poolEvents(two, one, rev); len(evs) != 0 {
		t.Errorf("a change that takes the pool below its threshold raised the events %+v", evs)
	}
	checkPoolEvent(t, poolEvents(one, two, rev), rev,
		`Network "tiny" of VRF "corp": the IPv4 pool 10.0.0.0/30 is 100% used (2 of its 2 addresses), at or above its threshold of 80%`)

	// A pool that another prefix replaces is a new pool
	moved := poolApply(t, two, poolResource(intent.KindNetwork, "tiny", `{"vrf": "corp", "ipv4Pool": "10.2.0.0/30"}`))
	checkPoolEvent(t, poolEvents(two, moved, rev), rev,
		`Network "tiny" of VRF "corp": the IPv4 pool 10.2.0.0/30 is 100% used (2 of its 2 addresses), at or above its threshold of 80%`)

	// A threshold that the Network sets, and the addresses that it reserves: 3 of the 6 host
	// addresses of a /29 are 50 percent
	reserved := poolApply(t, empty, poolResource(intent.KindNetwork, "six", `{"vrf": "corp", "ipv4Pool": "10.1.0.0/29", "poolThreshold": 50, "reserved": ["10.1.0.0/30"]}`))
	checkPoolEvent(t, poolEvents(empty, reserved, rev), rev,
		`Network "six" of VRF "corp": the IPv4 pool 10.1.0.0/29 is 50% used (3 of its 6 addresses), at or above its threshold of 50%`)

	// An IPv6 pool: a /127 holds 2 addresses, and a /64 never comes near its threshold
	v6 := poolApply(t, intent.New(), vrf, poolResource(intent.KindNetwork, "v6", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/127"}`))
	v6full := poolApply(t, v6, node("a", poolKey1), node("b", poolKey2))
	checkPoolEvent(t, poolEvents(v6, v6full, rev), rev,
		`Network "v6" of VRF "corp": the IPv6 pool fd12:3456:789a:1::/127 is 100% used (2 of its 2 addresses), at or above its threshold of 80%`)
	big := poolApply(t, intent.New(), vrf, poolResource(intent.KindNetwork, "big", `{"vrf": "corp", "ipv6Pool": "fd12:3456:789a:1::/64", "poolThreshold": 1}`))
	bigFull := poolApply(t, big, node("a", poolKey1), node("b", poolKey2))
	if evs := poolEvents(big, bigFull, rev); len(evs) != 0 {
		t.Errorf("a /64 with 2 addresses in use raised the events %+v", evs)
	}
}
