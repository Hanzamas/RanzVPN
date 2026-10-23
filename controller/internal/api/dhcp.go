package api

import (
	"context"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// LeaseList is the answer of GET /api/v1/ipam/leases: the leases of the DHCP responders of the L2
// Networks (SDN-43 #236), ordered by Network, then address.
type LeaseList struct {
	Leases []store.DHCPLease `json:"leases"`
}

// GET /api/v1/ipam/leases answers with a LeaseList: the leases that the node answering DHCP for
// each L2 Network reported last and that have not expired (controller.DHCPLeases). It needs the
// role viewer, as every read does.
func init() {
	register(
		route{http.MethodGet, "/api/v1/ipam/leases", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			leases, err := d.Controller.DHCPLeases(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, LeaseList{Leases: leases})
		}},
	)
}

// DHCPLeases returns the leases of the DHCP responders of the L2 Networks.
func (c *Client) DHCPLeases(ctx context.Context) ([]store.DHCPLease, error) {
	var l LeaseList
	err := c.do(ctx, http.MethodGet, "/api/v1/ipam/leases", nil, &l)
	return l.Leases, err
}
