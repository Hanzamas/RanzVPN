package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// ResourceList is the answer of GET /api/v1/resources: the intent.
type ResourceList struct {
	Resources []intent.Resource `json:"resources"`
}

// NodeList is the answer of GET /api/v1/nodes: for each node its generations and the
// Capabilities it reported (ADR-0033).
type NodeList struct {
	Nodes []controller.NodeStatus `json:"nodes"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/resources", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			rs := d.Controller.Resources()
			if rs == nil {
				rs = []intent.Resource{}
			}
			reply(w, http.StatusOK, ResourceList{Resources: rs})
		}},
		route{http.MethodGet, "/api/v1/nodes", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, NodeList{Nodes: d.Controller.Nodes()})
		}},
		route{http.MethodPost, "/api/v1/apply", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			confirm, err := confirmParam(r.URL.Query().Get("confirm"))
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
				return
			}
			var doc intent.Document
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&doc); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not an intent document: " + err.Error()})
				return
			}
			res, err := d.Controller.ApplyConfirm(r.Context(), doc, confirm)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodDelete, "/api/v1/resources/{kind}/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			res, err := d.Controller.Delete(r.Context(), r.PathValue("kind"), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
	)
}

// confirmParam parses the confirmation time of an apply, for example 5m; empty is none.
func confirmParam(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("confirm %q is not a duration above 0, for example 5m", s)
	}
	return d, nil
}

// Resources returns the intent.
func (c *Client) Resources(ctx context.Context) ([]intent.Resource, error) {
	var l ResourceList
	err := c.do(ctx, http.MethodGet, "/api/v1/resources", nil, &l)
	return l.Resources, err
}

// Nodes returns the status of every node, with the Capabilities it reported.
func (c *Client) Nodes(ctx context.Context) ([]controller.NodeStatus, error) {
	var l NodeList
	err := c.do(ctx, http.MethodGet, "/api/v1/nodes", nil, &l)
	return l.Nodes, err
}

// Apply applies doc.
func (c *Client) Apply(ctx context.Context, doc intent.Document) (controller.ApplyResult, error) {
	return c.ApplyConfirm(ctx, doc, 0)
}

// ApplyConfirm applies doc. With a confirm other than 0, the controller rolls the apply back
// after confirm unless Confirm confirms it first.
func (c *Client) ApplyConfirm(ctx context.Context, doc intent.Document, confirm time.Duration) (controller.ApplyResult, error) {
	path := "/api/v1/apply"
	if confirm != 0 {
		path += "?confirm=" + url.QueryEscape(confirm.String())
	}
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, path, doc, &res)
	return res, err
}

// Delete deletes the resource kind/name.
func (c *Client) Delete(ctx context.Context, kind, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, "/api/v1/resources/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &res)
	return res, err
}
