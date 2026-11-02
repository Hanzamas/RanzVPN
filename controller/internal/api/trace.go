package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// tracePath is the path of the traced packets (SDN-89, #388).
const tracePath = "/api/v1/traces"

// TraceList is the answer of the traces: the traces that the controller holds, or those of one trace ID, the newest
// first, each as the path of its packet (controller.Trace).
type TraceList struct {
	Traces []controller.Trace `json:"traces"`
}

// GET /api/v1/traces answers with the traces of the packets that the Nodes traced and reported, as the controller holds
// them, and GET /api/v1/traces/{id} with the traces of the trace ID id, a decimal number from 1 to 4294967295, one for
// each ingress Node that gave a packet that ID, 404 for none, which `ranz explain -trace` prints. They read only, so they
// need viewer.
func init() {
	register(route{http.MethodGet, tracePath, rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, TraceList{Traces: d.Controller.Traces()})
	}})
	register(route{http.MethodGet, tracePath + "/{id}", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
		if err != nil || id == 0 {
			replyError(w, fmt.Errorf("%w: a trace ID is a decimal number from 1 to 4294967295, not %q", intent.ErrInvalid, r.PathValue("id")))
			return
		}
		traces, err := d.Controller.TraceOf(uint32(id))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, TraceList{Traces: traces})
	}})
}

// Traces returns the traces that the controller holds, the newest first.
func (c *Client) Traces(ctx context.Context) ([]controller.Trace, error) {
	var list TraceList
	err := c.do(ctx, http.MethodGet, tracePath, nil, &list)
	return list.Traces, err
}

// TraceOf returns the traces of the trace ID id, the newest first.
func (c *Client) TraceOf(ctx context.Context, id uint32) ([]controller.Trace, error) {
	var list TraceList
	err := c.do(ctx, http.MethodGet, tracePath+"/"+strconv.FormatUint(uint64(id), 10), nil, &list)
	return list.Traces, err
}
