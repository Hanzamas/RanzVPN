package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// RevisionList is the answer of GET /api/v1/revisions: every revision, oldest first, without
// their resources.
type RevisionList struct {
	Revisions []intent.Revision `json:"revisions"`
}

// RollbackRequest is the body of POST /api/v1/rollback.
type RollbackRequest struct {
	// Revision is the revision whose intent becomes the intent again; 0 is the empty intent.
	// It must be given.
	Revision *uint64 `json:"revision"`
}

// DiffResult is the answer of GET /api/v1/diff: how the intent of revision To differs from the
// intent of revision From.
type DiffResult struct {
	From    uint64          `json:"from"`
	To      uint64          `json:"to"`
	Changes []intent.Change `json:"changes"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/revisions", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			revs, err := d.Controller.Revisions(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, RevisionList{Revisions: revs})
		}},
		route{http.MethodGet, "/api/v1/revisions/{id}", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			id, err := revisionNumber(r.PathValue("id"))
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
				return
			}
			rev, err := d.Controller.Revision(r.Context(), id)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, rev)
		}},
		route{http.MethodPost, "/api/v1/revisions/{id}/confirm", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			id, err := revisionNumber(r.PathValue("id"))
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
				return
			}
			rev, err := d.Controller.Confirm(r.Context(), id)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, rev)
		}},
		route{http.MethodPost, "/api/v1/rollback", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req RollbackRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil || req.Revision == nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body must be {"revision": N}, with N the revision to return to`})
				return
			}
			res, err := d.Controller.Rollback(r.Context(), *req.Revision)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodGet, "/api/v1/diff", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			to := d.Controller.LatestRevision()
			if s := q.Get("to"); s != "" {
				var err error
				if to, err = revisionNumber(s); err != nil {
					reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
					return
				}
			}
			var from uint64
			if to > 0 {
				from = to - 1
			}
			if s := q.Get("from"); s != "" {
				var err error
				if from, err = revisionNumber(s); err != nil {
					reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
					return
				}
			}
			changes, err := d.Controller.Diff(r.Context(), from, to)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, DiffResult{From: from, To: to, Changes: changes})
		}},
	)
}

func revisionNumber(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a revision number", s)
	}
	return id, nil
}

// Revisions returns every revision, oldest first, without their resources.
func (c *Client) Revisions(ctx context.Context) ([]intent.Revision, error) {
	var l RevisionList
	err := c.do(ctx, http.MethodGet, "/api/v1/revisions", nil, &l)
	return l.Revisions, err
}

// Revision returns revision id with its resources.
func (c *Client) Revision(ctx context.Context, id uint64) (intent.Revision, error) {
	var r intent.Revision
	err := c.do(ctx, http.MethodGet, "/api/v1/revisions/"+strconv.FormatUint(id, 10), nil, &r)
	return r, err
}

// Confirm confirms revision id, which an apply with a confirmation time made.
func (c *Client) Confirm(ctx context.Context, id uint64) (intent.Revision, error) {
	var r intent.Revision
	err := c.do(ctx, http.MethodPost, "/api/v1/revisions/"+strconv.FormatUint(id, 10)+"/confirm", nil, &r)
	return r, err
}

// Rollback makes the intent of revision id the intent again, as a new revision.
func (c *Client) Rollback(ctx context.Context, id uint64) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, "/api/v1/rollback", RollbackRequest{Revision: &id}, &res)
	return res, err
}

// Diff returns how the intent differs between two revisions: with no revision given, the change
// that the latest revision made; with one, from it to the latest revision; with two, from the
// first to the second.
func (c *Client) Diff(ctx context.Context, revisions ...uint64) (DiffResult, error) {
	q := url.Values{}
	switch len(revisions) {
	case 0:
	case 1:
		q.Set("from", strconv.FormatUint(revisions[0], 10))
	case 2:
		q.Set("from", strconv.FormatUint(revisions[0], 10))
		q.Set("to", strconv.FormatUint(revisions[1], 10))
	default:
		return DiffResult{}, errors.New("a diff is between two revisions")
	}
	path := "/api/v1/diff"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var dr DiffResult
	err := c.do(ctx, http.MethodGet, path, nil, &dr)
	return dr, err
}
