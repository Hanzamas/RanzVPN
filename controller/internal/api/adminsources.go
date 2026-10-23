package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// adminSourcesPath is the admin source allowlist, which only an admin reads or changes: from where
// the API and the web UI may be reached is part of who may manage the controller.
const adminSourcesPath = "/api/v1/admin-sources"

// maxSourcesBody bounds the body of a change of the admin source allowlist.
const maxSourcesBody = 64 << 10

// AdminSourceList is the body of PUT /api/v1/admin-sources and the answer of it and of GET: the
// source prefixes, each as text, ordered. An empty list means no restriction.
type AdminSourceList struct {
	Prefixes []string `json:"prefixes"`
}

// The admin source allowlist (SDN-39, #232), the source prefixes that the API and the web UI
// accept connections from (Sources), beside the calls of Handler:
//
//	GET /api/v1/admin-sources  an AdminSourceList                                         admin
//	PUT /api/v1/admin-sources  an AdminSourceList, which replaces the allowlist;
//	                           the AdminSourceList stored                                  admin
//
// An entry is a prefix such as 203.0.113.0/24 or 2001:db8::/32, or one address. A list that would
// lock the caller out, because it does not hold the address that the call came from, is refused
// with 409 Conflict; a loopback address is always allowed.
func init() {
	register(
		route{http.MethodGet, adminSourcesPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			list, err := d.Controller.AdminSources(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, AdminSourceList{Prefixes: list})
		}},
		route{http.MethodPut, adminSourcesPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req AdminSourceList
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSourcesBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a list of source prefixes: " + err.Error()})
				return
			}
			prefixes, err := intent.ParseSources(req.Prefixes)
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the admin source allowlist: " + err.Error()})
				return
			}
			from, _ := intent.SourceAddr(r.RemoteAddr)
			if len(prefixes) > 0 && !adminAllows(prefixes, from) {
				reply(w, http.StatusConflict, Problem{Error: fmt.Sprintf("the list does not hold the address %s that this call came from, so it would lock you out of the API and the web UI: add the address, or make the change from the host of the controller, where loopback is always allowed", from)})
				return
			}
			tok, _ := Caller(r.Context())
			list, err := d.Controller.SetAdminSources(r.Context(), prefixes, tok.Name)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, AdminSourceList{Prefixes: list})
		}},
	)
}

// AdminSources returns the admin source allowlist, the prefixes that the API and the web UI accept
// connections from; empty when any address may reach them.
func (c *Client) AdminSources(ctx context.Context) ([]string, error) {
	var l AdminSourceList
	err := c.do(ctx, http.MethodGet, adminSourcesPath, nil, &l)
	return l.Prefixes, err
}

// SetAdminSources replaces the admin source allowlist with prefixes and returns it as the
// controller keeps it. No prefix removes the restriction.
func (c *Client) SetAdminSources(ctx context.Context, prefixes []string) ([]string, error) {
	if prefixes == nil {
		prefixes = []string{}
	}
	var l AdminSourceList
	err := c.do(ctx, http.MethodPut, adminSourcesPath, AdminSourceList{Prefixes: prefixes}, &l)
	return l.Prefixes, err
}
