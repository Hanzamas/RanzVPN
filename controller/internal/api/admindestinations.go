package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// adminDestinationsPath is the admin destination lists, which only an admin reads or changes: where
// an operator may point the Controller and the Nodes is part of who may reach what from the
// controller's host.
const adminDestinationsPath = "/api/v1/admin-destinations"

// The admin destination lists (AUD1-DT-9, #457, ADR-0031 amendment of 2026-10-27), beside the calls
// of Handler:
//
//	GET /api/v1/admin-destinations  an intent.Destinations                                  admin
//	PUT /api/v1/admin-destinations  an intent.Destinations, which replaces the lists;
//	                                the intent.Destinations stored                          admin
//
// The lists are the target hosts (hosts and prefixes that an export or audit target may name although
// they are loopback, link-local or the store of the controller), the sensor prefixes (that the
// sensor of every Mirror must be inside) and the UNC servers (that a UNC path of a Listener may
// name). An entry that is not valid is answered with 400 Bad Request.
func init() {
	register(
		route{http.MethodGet, adminDestinationsPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			list, err := d.Controller.AdminDestinations(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, list)
		}},
		route{http.MethodPut, adminDestinationsPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req intent.Destinations
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSourcesBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not the admin destination lists, {"targets": [...], "sensors": [...], "uncServers": [...]}: ` + err.Error()})
				return
			}
			tok, _ := Caller(r.Context())
			list, err := d.Controller.SetAdminDestinations(r.Context(), req, tok.Name)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, list)
		}},
	)
}

// AdminDestinations returns the admin destination lists.
func (c *Client) AdminDestinations(ctx context.Context) (intent.Destinations, error) {
	var d intent.Destinations
	err := c.do(ctx, http.MethodGet, adminDestinationsPath, nil, &d)
	return d, err
}

// SetAdminDestinations replaces the admin destination lists with d and returns them as the controller
// keeps them. A list that is left empty is emptied.
func (c *Client) SetAdminDestinations(ctx context.Context, d intent.Destinations) (intent.Destinations, error) {
	if d.Targets == nil {
		d.Targets = []string{}
	}
	if d.Sensors == nil {
		d.Sensors = []string{}
	}
	if d.UNCServers == nil {
		d.UNCServers = []string{}
	}
	var out intent.Destinations
	err := c.do(ctx, http.MethodPut, adminDestinationsPath, d, &out)
	return out, err
}
