package capability

import (
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// An L3 Network that splits TCP needs the Capability tcpSplit on every node of its VRF (CORE-P2-3 #94, ADR-0033 amendment of
// 2026-11-02): a node of the VRF splits the TCP connections of its host in the Network and opens a split flow to the peer that
// the destination routes to, which must answer it. A node of an older release skips tcp_split of the Network and answers no
// split flow, so every split connection of its peers to it would time out, with no error. Every node of the VRF gets the
// Network object (internal/desired, split.go), so each one that does not report it is refused before the apply, and the
// refusal names the node, the Network and the Capability. The row is added here, in a file of its own, and not to
// requirements.
func init() {
	requirements = append(requirements, requirement{
		feature: func(o *controlpb.Object) string {
			if nw := o.GetNetwork(); nw.GetTcpSplit() {
				return fmt.Sprintf("TCP splitting of Network %q", nw.GetName())
			}
			return ""
		},
		capability: "tcpSplit",
		has:        func(c *controlpb.Capabilities) bool { return c.GetTcpSplit() },
	})
}
