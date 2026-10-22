package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The export and the import of the whole intent (SDN-52, #245), beside the calls of Handler:
//
//	GET  /api/v1/export  the whole intent as an intent.Document                     viewer
//	POST /api/v1/import  an intent.Document, made the whole intent as the next revision;
//	                     a controller.ApplyResult                                     operator
//
// An import is checked and refused as an apply is.
func init() {
	register(
		route{http.MethodGet, "/api/v1/export", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, d.Controller.Export())
		}},
		route{http.MethodPost, "/api/v1/import", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var doc intent.Document
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&doc); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not an intent document: " + err.Error()})
				return
			}
			res, err := d.Controller.Import(r.Context(), doc)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
	)
}

// Export returns the whole intent as one document, which Import takes.
func (c *Client) Export(ctx context.Context) (intent.Document, error) {
	var doc intent.Document
	err := c.do(ctx, http.MethodGet, "/api/v1/export", nil, &doc)
	return doc, err
}

// Import makes doc the whole intent, as the next revision: the resources that doc leaves out are
// deleted.
func (c *Client) Import(ctx context.Context, doc intent.Document) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, "/api/v1/import", doc, &res)
	return res, err
}
