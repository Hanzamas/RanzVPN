package capability

import (
	"fmt"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The internet exit of a VRF (SDN-12 #188, ADR-0025 decisions 13 to 15) is a gateway feature: it
// needs a node that reports its Egress tier, how it takes the traffic of the VRF to the outside.
// Tier 3, the proxy on the Windows TCP/IP stack, runs on every host (ADR-0033), so any node of this
// release can be an exit, and only a node of an older release, which knows no tier, is refused.
func init() {
	requirements = append(requirements, requirement{
		feature: func(o *controlpb.Object) string {
			if ids := o.GetNode().GetEgressVrfIds(); len(ids) > 0 {
				return egressFeature(ids)
			}
			return ""
		},
		capability: "egressTier",
		has: func(c *controlpb.Capabilities) bool {
			return c.GetEgressTier() != controlpb.EgressTier_EGRESS_TIER_UNSPECIFIED
		},
	})
}

// egressFeature names the internet exit of the VRFs of ids, as a NodeConfig holds them.
func egressFeature(ids []uint32) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = fmt.Sprint(id)
	}
	if len(ids) == 1 {
		return "the internet exit of the VRF of id " + s[0]
	}
	return "the internet exit of the VRFs of ids " + strings.Join(s, ", ")
}
