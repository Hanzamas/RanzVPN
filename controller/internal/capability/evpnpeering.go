package capability

import (
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// A VRF whose Nodes peer by EVPN needs a node that runs the EVPN peering (SDN-78, #358): a node of an older release reads
// PEERING_EVPN as no peering and skips the L2 VNIs of the Networks, and so does a node without ranz.exe, which holds the
// sidecar: neither starts the EVPN. The Controller gives no route of a peer in such a VRF, so that node would reach no other
// node of the VRF, and its own prefixes and MAC addresses would be gone from every other node, without an error.
func init() {
	requirements = append(requirements, requirement{
		feature: func(o *controlpb.Object) string {
			if v := o.GetVrf(); v.GetPeering() == controlpb.Peering_PEERING_EVPN {
				return fmt.Sprintf("EVPN peering of VRF %q", v.GetName())
			}
			return ""
		},
		capability: "evpnPeering",
		has:        func(c *controlpb.Capabilities) bool { return c.GetEvpnPeering() },
	})
}
