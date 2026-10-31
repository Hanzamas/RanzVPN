package capability

import (
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A Stretch needs the Capability evpn at its gateway (SDN-63 #290, ADR-0032 amendment of 2026-10-22): the gateway extends an L2
// Network into a data-centre fabric over EVPN and VXLAN, which only a Windows Server host whose VXLAN module runs does. A node
// that does not report it is refused the Stretch before the apply, and the refusal names the node, the Network and the Capability.
// Only the state of the gateway of a Stretch holds one (internal/desired, stretch.go), and none while the licence in force lacks
// EVPN and BGP (internal/controller, stretch.go), so a node that is no gateway needs nothing. The row is added here, in a file of
// its own, and not to requirements.
func init() {
	requirements = append(requirements, requirement{
		feature: func(o *controlpb.Object) string {
			if nw := o.GetNetwork(); nw.GetStretch() != nil {
				return fmt.Sprintf("Stretch of Network %q", nw.GetName())
			}
			return ""
		},
		capability: "evpn",
		has:        func(c *controlpb.Capabilities) bool { return c.GetEvpn() },
	})
}
