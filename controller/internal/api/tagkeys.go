package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The rotation of the key of the tag mode hmac of a VRF (SDN-88 #387):
//
//	POST /api/v1/vrfs/{name}/tagkey   a controller.TagKeyRotation   operator
//
// The Nodes of the VRF get a new key beside the one that they send with, and send with it once each of
// them acknowledged it; the answer names the new key by its ID and the Nodes that the switch waits for,
// and holds no key. A VRF that the intent does not hold answers 404 Not Found; one in another tag mode,
// one without a key and one whose last rotation is not done answer 409 Conflict.
func init() {
	register(
		route{http.MethodPost, "/api/v1/vrfs/{name}/tagkey", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			res, err := d.Controller.RotateTagKey(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
	)
}

// RotateTagKey rotates the key of the tag mode hmac of the VRF vrf.
func (c *Client) RotateTagKey(ctx context.Context, vrf string) (controller.TagKeyRotation, error) {
	var out controller.TagKeyRotation
	err := c.do(ctx, http.MethodPost, "/api/v1/vrfs/"+url.PathEscape(vrf)+"/tagkey", nil, &out)
	return out, err
}
