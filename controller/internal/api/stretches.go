package api

import (
	"context"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The Stretches of the L2 Networks (SDN-63 #290). GET /api/v1/stretches answers with a StretchList: every Stretch of the
// intent with its values, the defaults that the controller filled in among them, and whether the controller puts it into the
// desired state of its gateway. The role it needs is viewer, as every read does. A Stretch is made, changed and deleted as any
// resource is, with POST /api/v1/apply and DELETE /api/v1/resources/Stretch/{name}.
func init() {
	register(
		route{http.MethodGet, "/api/v1/stretches", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, StretchList{Stretches: d.Controller.Stretches()})
		}},
	)
}

// StretchList is the answer of GET /api/v1/stretches.
type StretchList struct {
	Stretches []controller.StretchStatus `json:"stretches"`
}

// Stretches returns the status of every Stretch.
func (c *Client) Stretches(ctx context.Context) ([]controller.StretchStatus, error) {
	var l StretchList
	err := c.do(ctx, http.MethodGet, "/api/v1/stretches", nil, &l)
	return l.Stretches, err
}
