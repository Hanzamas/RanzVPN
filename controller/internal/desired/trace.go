package desired

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The trace of a packet (SDN-89 #388): a Network whose trace is on reaches the state of every Node of its VRF with its
// pools, and the Node traces the packets of the IPv4 and the IPv6 pool of each such Network of its VRFs. A Node holds
// MaxTracedPools of those pools at most and would leave the others out, so Compile refuses an intent that gives a Node
// more (SDN-89-R1 #630), and the operator sees it when the intent is applied, not as a trace that never comes. A Node holds
// an address in each pool of the L3 Networks of its VRFs, intent.MaxAddresses of them at most, so it is the pools of the L2
// Networks, which give it no address, that pass the limit.

// MaxTracedPools is the most pools of the Networks whose trace is on that the state of a Node holds: CONTROL_MAX_TRACED of
// the C node (src/Core/Control.h), the IPv4 and the IPv6 pool of 8 Networks in its VRFs.
const MaxTracedPools = 16

// tracedPools returns the number of pools of the Networks whose trace is on in the state s, as the Node of s counts them:
// the IPv4 and the IPv6 pool of each such Network object.
func tracedPools(s State) int {
	pools := 0
	for _, o := range s {
		nw := o.GetNetwork()
		if nw == nil || !nw.GetTrace() {
			continue
		}
		if nw.GetIpv4Pool() != nil {
			pools++
		}
		if nw.GetIpv6Pool() != nil {
			pools++
		}
	}
	return pools
}

// checkTraced returns an error that wraps intent.ErrInvalid when a state of states, by node name, holds more than
// MaxTracedPools pools of the Networks whose trace is on, which names the first such Node by name and the limit.
func checkTraced(states map[string]State) error {
	for _, name := range slices.Sorted(maps.Keys(states)) {
		if pools := tracedPools(states[name]); pools > MaxTracedPools {
			return fmt.Errorf("%w: Node %q gets %d pools of the Networks whose trace is on in its VRFs, and a Node traces the packets of %d pools at most: switch the trace of some of those Networks off",
				intent.ErrInvalid, name, pools, MaxTracedPools)
		}
	}
	return nil
}
