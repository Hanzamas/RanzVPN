package desired

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// tracedResources returns an intent of the VRFs corp and lab, the Node a in both and b in lab alone, a dual-stack Network
// of corp whose trace is off, corp dual-stack Networks of corp and lab of lab whose trace is on, and, with v4, one more
// Network of lab whose trace is on, with an IPv4 pool alone.
func tracedResources(corp, lab int, v4 bool) []intent.Resource {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-off", `{"vrf": "corp", "ipv4Pool": "10.10.99.0/24", "ipv6Pool": "fd12:3456:789a:99::/64"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	}
	for i := range corp {
		rs = append(rs, res(intent.KindNetwork, fmt.Sprintf("corp-%d", i),
			fmt.Sprintf(`{"vrf": "corp", "ipv4Pool": "10.10.%d.0/24", "ipv6Pool": "fd12:3456:789a:%d::/64", "trace": true}`, i, i+1)))
	}
	for i := range lab {
		rs = append(rs, res(intent.KindNetwork, fmt.Sprintf("lab-%d", i),
			fmt.Sprintf(`{"vrf": "lab", "ipv4Pool": "10.20.%d.0/24", "ipv6Pool": "fd12:3456:789b:%d::/64", "trace": true}`, i, i+1)))
	}
	if v4 {
		rs = append(rs, res(intent.KindNetwork, "lab-v4", `{"vrf": "lab", "ipv4Pool": "10.20.99.0/24", "trace": true}`))
	}
	return rs
}

// A Node holds MaxTracedPools pools of the Networks whose trace is on at most (SDN-89-R1, #630). Compile counts the IPv4
// and the IPv6 pool of each Network whose trace is on in the VRFs of a Node, and nothing of a Network whose trace is off:
// a gets the 10 of corp and the 6 of lab, 16, which a Node takes, and b the 6 of lab. One more pool in lab gives a 17, and
// Compile refuses the intent with an error that wraps intent.ErrInvalid and names a, its pools and the limit, as the Node
// would leave a pool out; b, with 7, is not what it refuses.
func TestCompileRefusesMoreTracedPoolsThanANodeTakes(t *testing.T) {
	states := compile(t, tracedResources(5, 3, false)...)
	if got := tracedPools(states["a"]); got != MaxTracedPools {
		t.Errorf("the state of a holds %d pools of Networks whose trace is on, want %d", got, MaxTracedPools)
	}
	if got := tracedPools(states["b"]); got != 6 {
		t.Errorf("the state of b holds %d pools of Networks whose trace is on, want 6", got)
	}

	_, err := Compile(mustApply(t, tracedResources(5, 3, true)))
	want := `Node "a" gets 17 pools of the Networks whose trace is on in its VRFs, and a Node traces the packets of 16 pools at most`
	if !errors.Is(err, intent.ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("Compile of an intent that gives a 17 pools of Networks whose trace is on gave %v, want an error with %q", err, want)
	}
}

// MaxTracedPools is what the C node takes: CONTROL_MAX_TRACED of src/Core/Control.h, the size of the pools of the
// Networks that trace in its state (CONTROL_STATE.Traced), which the Node fills from the Network objects (ControlTrace.c).
func TestMaxTracedPoolsIsWhatTheNodeTakes(t *testing.T) {
	b, err := os.ReadFile("../../../src/Core/Control.h")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^#define CONTROL_MAX_TRACED\s+(\d+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("src/Core/Control.h defines no CONTROL_MAX_TRACED")
	}
	if n, err := strconv.Atoi(string(m[1])); err != nil || n != MaxTracedPools {
		t.Errorf("CONTROL_MAX_TRACED of src/Core/Control.h is %s, and MaxTracedPools is %d", m[1], MaxTracedPools)
	}
}
