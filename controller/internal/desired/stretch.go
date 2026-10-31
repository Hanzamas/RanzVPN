package desired

import (
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The Stretches of the L2 Networks (SDN-63 #290, intent/stretch.go): the node that is the gateway of a Stretch gets it in the
// Network object of its state. Every other node of the VRF gets the Network without one, so a node extends a Network into a
// fabric only when its own object of the Network carries a Stretch. The controller compiles none while the licence in force
// lacks EVPN and BGP (internal/controller, stretch.go): the Intent it compiles then has no Stretch.

// stretches returns the Stretches of in as their gateways get them, by gateway, then Network.
func stretches(in intent.Intent) map[string]map[string]*controlpb.Stretch {
	out := map[string]map[string]*controlpb.Stretch{}
	for _, s := range in.Stretches {
		st := &controlpb.Stretch{Vni: s.VNI, RouteTargets: slices.Clone(s.RouteTargets), BumRateLimit: s.BUMRateLimit, MacImportLimit: s.MACImportLimit,
			StaleTimer: s.StaleTimer, Irb: s.IRB}
		if s.ESI != "" {
			// Apply validated it
			st.Esi, _ = intent.ParseESI(s.ESI)
		}
		if out[s.Gateway] == nil {
			out[s.Gateway] = map[string]*controlpb.Stretch{}
		}
		out[s.Gateway][s.Network] = st
	}
	return out
}

// withStretch returns the Network nw as a node gets it: with the Stretch that binds the node to nw, which stretched holds, the
// Stretches of that node by Network name, else nw itself. The states of the nodes share nw, so the Stretch goes on a copy.
func withStretch(nw *controlpb.Network, stretched map[string]*controlpb.Stretch) *controlpb.Network {
	st, ok := stretched[nw.GetName()]
	if !ok {
		return nw
	}
	c := proto.Clone(nw).(*controlpb.Network)
	c.Stretch = st
	return c
}
