package api

import (
	"context"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// GET /api/v1/ipam answers with a controller.IPAM (ADR-0028, SDN-10 #186): how full each pool of
// each Network is, and the routes that the LAN subnets behind gateway Nodes make. It needs the
// role viewer, as every read does.
func init() {
	register(
		route{http.MethodGet, "/api/v1/ipam", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, d.Controller.IPAM())
		}},
	)
}

// IPAM returns how full each pool is and the routes of the LAN subnets.
func (c *Client) IPAM(ctx context.Context) (controller.IPAM, error) {
	var ipam controller.IPAM
	err := c.do(ctx, http.MethodGet, "/api/v1/ipam", nil, &ipam)
	return ipam, err
}
