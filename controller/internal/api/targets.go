package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The targets that the controller sends its events, metrics and flow records to (SDN-16 #192,
// ADR-0030), beside the calls of Handler:
//
//	GET    /api/v1/targets         TargetList, without the secrets and the paths of the URLs   viewer
//	PUT    /api/v1/targets/{name}  an export.Target, which replaces the one of that name;
//	                               an export.Info                                              operator
//	DELETE /api/v1/targets/{name}  the export.Info of the target that was deleted              operator
//
// A target is a webhook (every event as a JSON POST), an OTLP endpoint (the metrics) or an IPFIX
// collector (the flow records). An invalid target is answered with 400 Bad Request.

// TargetList is the answer of GET /api/v1/targets.
type TargetList struct {
	Targets []export.Info `json:"targets"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/targets", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ts, err := d.Controller.Targets(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			infos := make([]export.Info, len(ts))
			for i, t := range ts {
				infos[i] = t.Info()
			}
			reply(w, http.StatusOK, TargetList{Targets: infos})
		}},
		route{http.MethodPut, "/api/v1/targets/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var t export.Target
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&t); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not an export target: " + err.Error()})
				return
			}
			if name := r.PathValue("name"); t.Name != "" && t.Name != name {
				reply(w, http.StatusBadRequest, Problem{Error: "the name of the target in the body is " + t.Name + ", and the path names " + name})
				return
			}
			t.Name = r.PathValue("name")
			if err := d.Controller.PutTarget(r.Context(), t); err != nil {
				replyTarget(w, err)
				return
			}
			reply(w, http.StatusOK, t.Info())
		}},
		route{http.MethodDelete, "/api/v1/targets/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			t, err := d.Controller.DeleteTarget(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, t.Info())
		}},
	)
}

// replyTarget answers an error of a change of a target: 400 for a target that is not valid, and
// what replyError makes of any other.
func replyTarget(w http.ResponseWriter, err error) {
	if errors.Is(err, export.ErrInvalid) {
		reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
		return
	}
	replyError(w, err)
}

// Targets returns the export targets, as the API shows them.
func (c *Client) Targets(ctx context.Context) ([]export.Info, error) {
	var l TargetList
	err := c.do(ctx, http.MethodGet, "/api/v1/targets", nil, &l)
	return l.Targets, err
}

// PutTarget stores t, which replaces the target of its name, and returns it as the API shows it.
func (c *Client) PutTarget(ctx context.Context, t export.Target) (export.Info, error) {
	var info export.Info
	err := c.do(ctx, http.MethodPut, "/api/v1/targets/"+url.PathEscape(t.Name), t, &info)
	return info, err
}

// DeleteTarget deletes the target name and returns it as the API shows it.
func (c *Client) DeleteTarget(ctx context.Context, name string) (export.Info, error) {
	var info export.Info
	err := c.do(ctx, http.MethodDelete, "/api/v1/targets/"+url.PathEscape(name), nil, &info)
	return info, err
}
