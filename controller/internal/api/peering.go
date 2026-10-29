package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// peeringPath is the path of the BGP peering of the Nodes (SDN-77, #357).
const peeringPath = "/api/v1/peering"

// GET /api/v1/peering/{node} answers with the controller.PeeringStatus of a Node: the Nodes that the
// intent names as its peers in the VRFs that peer by BGP, and the peers of its sidecar as the Node
// reported them last, with the state of each session and the prefixes learned from each, which
// `ranz explain NODE` prints. It reads only, so it needs viewer.
func init() {
	register(route{http.MethodGet, peeringPath + "/{node}", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		st, err := d.Controller.Peering(r.PathValue("node"))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	}})
}

// Peering returns the BGP peering of the Node node.
func (c *Client) Peering(ctx context.Context, node string) (controller.PeeringStatus, error) {
	var st controller.PeeringStatus
	err := c.do(ctx, http.MethodGet, peeringPath+"/"+url.PathEscape(node), nil, &st)
	return st, err
}
