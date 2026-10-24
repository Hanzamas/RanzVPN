package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// ConnectRequest is the body of POST /api/v1/connect, the "connect VRF" shortcut (ADR-0025
// decision 9, SDN-7 #183): the two VRFs whose routes leak into each other.
type ConnectRequest struct {
	VRFs []string `json:"vrfs"`
}

// POST /api/v1/connect applies, as one revision, the two route-target edits that make a two-way
// leak between the VRFs of a ConnectRequest (intent.Connect), and answers the
// controller.ApplyResult of the apply. It needs operator, as an apply does.
func init() {
	register(route{http.MethodPost, "/api/v1/connect", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		var req ConnectRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || len(req.VRFs) != 2 {
			reply(w, http.StatusBadRequest, Problem{Error: `the body is not the two VRFs to connect, {"vrfs": ["A", "B"]}`})
			return
		}
		in, err := intent.FromResources(d.Controller.Resources())
		if err != nil {
			replyError(w, err)
			return
		}
		doc, err := in.Connect(req.VRFs[0], req.VRFs[1])
		if err != nil {
			replyError(w, err)
			return
		}
		res, err := d.Controller.ApplyConfirm(r.Context(), doc, 0)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	}})
}

// Connect connects the VRFs a and b: the routes of each leak into the other, as one revision.
func (c *Client) Connect(ctx context.Context, a, b string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, "/api/v1/connect", ConnectRequest{VRFs: []string{a, b}}, &res)
	return res, err
}
