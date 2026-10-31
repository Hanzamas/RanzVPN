package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The audit log (SDN-49 #242, ADR-0030), beside the calls of Handler:
//
//	GET    /api/v1/audit                  AuditList: the records that match the query, oldest first      viewer
//	                                      kind, actor, since and until (RFC 3339), after (a record id)
//	                                      and limit (1 to 1000, 100 when left out)
//	GET    /api/v1/audit/targets          AuditTargetList, without the secrets and the paths of the URLs  admin
//	PUT    /api/v1/audit/targets/{name}   an export.Target of the kind webhook or syslog, which
//	                                      replaces the one of that name; an export.Info                   admin
//	DELETE /api/v1/audit/targets/{name}   the export.Info of the target that was deleted                  admin
//	GET    /api/v1/audit/retention        the audit.Retention in force                                    viewer
//	PUT    /api/v1/audit/retention        an audit.Retention, which becomes the one in force              admin
//
// A viewer reads the audit log because the API gives every read the role viewer (Needs). The audit
// targets are where the audit log is sent: a webhook receives each record as a JSON POST, a syslog
// receiver as an RFC 5424 message. An operator must not send the audit log where he pleases, nor
// shorten it, so the audit targets and the retention need admin (AUD1-DT-9, #457). A target must not
// name an address that the admin destination lists keep from it (export.Guard). A request that is
// not valid is answered with 400 Bad Request.
//
// The log names the API tokens that acted (token:NAME), and a call with a token after its expiry is
// recorded under that token (auditexpired.go), so a viewer reads the names of tokens, though
// GET /api/v1/tokens needs admin. That is the decision of AUD1-DT-15-R1 (#561), written in AP-5 and
// AP-8 of docs/threat-model.md and held by TestAViewerReadsTheNamesOfTheTokensInTheAuditLog.

// auditTargetsPath is the root of the audit targets and auditRetentionPath the retention of the audit
// log, which only an admin changes (Needs).
const (
	auditTargetsPath   = "/api/v1/audit/targets"
	auditRetentionPath = "/api/v1/audit/retention"
)

// AuditList is the answer of GET /api/v1/audit.
type AuditList struct {
	Records []audit.Record `json:"records"`
	// Next is the id to pass as after to get the records that follow, when this answer holds as many
	// records as the limit allows, and left out otherwise.
	Next uint64 `json:"next,omitempty"`
}

// AuditTargetList is the answer of GET /api/v1/audit/targets.
type AuditTargetList struct {
	Targets []export.Info `json:"targets"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/audit", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			f, err := audit.ParseFilter(r.URL.Query())
			if err != nil {
				replyAudit(w, err)
				return
			}
			recs, err := d.Controller.AuditRecords(r.Context(), f)
			if err != nil {
				replyError(w, err)
				return
			}
			list := AuditList{Records: recs}
			if len(recs) == f.Limit {
				list.Next = recs[len(recs)-1].ID
			}
			reply(w, http.StatusOK, list)
		}},
		route{http.MethodGet, auditTargetsPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ts, err := d.Controller.AuditTargets(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			infos := make([]export.Info, len(ts))
			for i, t := range ts {
				infos[i] = t.Info()
			}
			reply(w, http.StatusOK, AuditTargetList{Targets: infos})
		}},
		route{http.MethodPut, auditTargetsPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var t export.Target
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&t); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not an audit target: " + err.Error()})
				return
			}
			if name := r.PathValue("name"); t.Name != "" && t.Name != name {
				reply(w, http.StatusBadRequest, Problem{Error: "the name of the target in the body is " + t.Name + ", and the path names " + name})
				return
			}
			t.Name = r.PathValue("name")
			if err := d.Controller.PutAuditTarget(r.Context(), t); err != nil {
				replyTarget(w, err)
				return
			}
			reply(w, http.StatusOK, t.Info())
		}},
		route{http.MethodDelete, auditTargetsPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			t, err := d.Controller.DeleteAuditTarget(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, t.Info())
		}},
		route{http.MethodGet, "/api/v1/audit/retention", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ret, err := d.Controller.AuditRetention(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, ret)
		}},
		route{http.MethodPut, auditRetentionPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var ret audit.Retention
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&ret); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not an audit retention, {"days": N, "maxRecords": N}: ` + err.Error()})
				return
			}
			if err := d.Controller.SetAuditRetention(r.Context(), ret); err != nil {
				replyAudit(w, err)
				return
			}
			reply(w, http.StatusOK, ret)
		}},
	)
}

// replyAudit answers an error of the audit log: 400 for a request that is not valid, and what
// replyError makes of any other.
func replyAudit(w http.ResponseWriter, err error) {
	if errors.Is(err, audit.ErrInvalid) {
		reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
		return
	}
	replyError(w, err)
}

// Audit returns the records of the audit log that match f, the oldest first.
func (c *Client) Audit(ctx context.Context, f audit.Filter) (AuditList, error) {
	p := "/api/v1/audit"
	if q := f.Query(); len(q) > 0 {
		p += "?" + q.Encode()
	}
	var l AuditList
	err := c.do(ctx, http.MethodGet, p, nil, &l)
	return l, err
}

// AuditTargets returns the audit targets, as the API shows them.
func (c *Client) AuditTargets(ctx context.Context) ([]export.Info, error) {
	var l AuditTargetList
	err := c.do(ctx, http.MethodGet, "/api/v1/audit/targets", nil, &l)
	return l.Targets, err
}

// PutAuditTarget stores t, which replaces the audit target of its name, and returns it as the API
// shows it.
func (c *Client) PutAuditTarget(ctx context.Context, t export.Target) (export.Info, error) {
	var info export.Info
	err := c.do(ctx, http.MethodPut, "/api/v1/audit/targets/"+url.PathEscape(t.Name), t, &info)
	return info, err
}

// DeleteAuditTarget deletes the audit target name and returns it as the API shows it.
func (c *Client) DeleteAuditTarget(ctx context.Context, name string) (export.Info, error) {
	var info export.Info
	err := c.do(ctx, http.MethodDelete, "/api/v1/audit/targets/"+url.PathEscape(name), nil, &info)
	return info, err
}

// AuditRetention returns the retention policy of the audit log.
func (c *Client) AuditRetention(ctx context.Context) (audit.Retention, error) {
	var r audit.Retention
	err := c.do(ctx, http.MethodGet, "/api/v1/audit/retention", nil, &r)
	return r, err
}

// SetAuditRetention sets the retention policy of the audit log and returns it.
func (c *Client) SetAuditRetention(ctx context.Context, r audit.Retention) (audit.Retention, error) {
	var out audit.Retention
	err := c.do(ctx, http.MethodPut, "/api/v1/audit/retention", r, &out)
	return out, err
}

// Auditor is what records the calls of the API in the audit log: the controller.
type Auditor interface {
	RecordAudit(ctx context.Context, r audit.Record) error
}

// AuditRefusals returns h, the API behind its Guard, with the audit log of l on it: each call that
// the Guard refuses with 401 Unauthorized, because its bearer token is missing or is not one of the
// controller's, is recorded as a failed authentication (audit.AuthFailed) from the address of the
// caller, with the actor unknown. A call whose token has expired is recorded under that token, with
// the word expired (auditexpired.go). A source that fails again within a few seconds is not recorded
// again (audit.Log). Every member of a controller cluster has it on its own Guard, since it is the
// member that refuses the call that records it.
func AuditRefusals(l *audit.Log, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		ctx, note := withRefusalNote(r.Context())
		h.ServeHTTP(sw, r.WithContext(ctx))
		if sw.code() != http.StatusUnauthorized {
			return
		}
		actor := audit.ActorUnknown
		message := "the request has no bearer token"
		if strings.Contains(sw.Header().Get("WWW-Authenticate"), "invalid_token") {
			message = "the bearer token is not a token of this controller, or it was deleted"
		}
		if note.expired.Name != "" {
			actor, message = audit.ActorToken(note.expired.Name), expiredMessage(note.expired)
		}
		_ = l.Record(r.Context(), audit.Record{Kind: audit.AuthFailed, Actor: actor, Source: audit.Host(r.RemoteAddr),
			Outcome: audit.Failure, Message: message})
	})
}

// AuditCalls returns h, the API behind its Guard, with the audit log of a on it: the context of
// each call carries its origin, the API token and the address of the caller (audit.NewContext), so
// that what the call makes the controller do is recorded under that actor; and each call that
// changes something (any method but GET and HEAD) is recorded when it ends. An apply, a delete, a
// rollback and an import that succeed are recorded by the controller with the revision that they
// make, so only the ones that fail are recorded here (audit.IntentChange, outcome failure, with the
// reason). Any other change is an audit.Operation, with the call as its action. A read is recorded
// only when it is one of the three that auditedReads names, as an audit.Access. Only the member of a
// cluster that leads serves the calls, so each one is recorded once. The live operations of
// /api/v1/operations (SDN-50, #243) are recorded by the controller itself, each with what it did to
// whom, so they get the origin here and no record (selfAudited).
func AuditCalls(a Auditor, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := audit.ActorUnknown
		if tok, ok := Caller(r.Context()); ok {
			// The API token, or the User of a user token (SDN-32)
			actor = tok.Actor()
		}
		r = r.WithContext(audit.NewContext(r.Context(), audit.Origin{Actor: actor, Source: audit.Host(r.RemoteAddr)}))
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			auditRead(a, h, w, r)
			return
		}
		if selfAudited(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		h.ServeHTTP(sw, r)
		kind, action := callKind(r.Method, r.URL.Path)
		rec := audit.Record{Kind: kind, Action: action, Outcome: audit.Success}
		if code := sw.code(); code < 200 || code > 299 {
			rec.Outcome = audit.Failure
			rec.Message = sw.problem()
		} else if kind == audit.IntentChange {
			return
		}
		_ = a.RecordAudit(r.Context(), rec)
	})
}

// callKind returns the kind of audit record that a call with the method to the path makes, and its
// action: the calls that change the intent are audit.IntentChange, with the name of the operation
// that makes the revision, and any other is an audit.Operation, with the method and the path.
func callKind(method, urlPath string) (kind, action string) {
	p := path.Clean("/" + urlPath)
	switch {
	case method == http.MethodPost && p == "/api/v1/apply":
		return audit.IntentChange, "apply"
	case method == http.MethodPost && p == "/api/v1/import":
		return audit.IntentChange, "import"
	case method == http.MethodPost && p == "/api/v1/rollback":
		return audit.IntentChange, "rollback"
	case method == http.MethodDelete && strings.HasPrefix(p, "/api/v1/resources/"):
		return audit.IntentChange, "delete"
	}
	return audit.Operation, method + " " + p
}

// maxProblem bounds how much of the answer of a failed call statusWriter keeps for its message.
const maxProblem = 1024

// statusWriter passes an answer through and remembers its status code, and the start of its body
// when the call failed, for the audit record.
type statusWriter struct {
	http.ResponseWriter
	status int
	body   []byte
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.status >= 400 && len(w.body) < maxProblem {
		w.body = append(w.body, b[:min(len(b), maxProblem-len(w.body))]...)
	}
	return w.ResponseWriter.Write(b)
}

// Flush passes a flush on, so that an answer that streams still does.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// code returns the status code of the answer: 200 when the handler wrote none.
func (w *statusWriter) code() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// problem returns what a failed call said: the message of its Problem when it sent one, and the
// status text otherwise.
func (w *statusWriter) problem() string {
	var p Problem
	if json.Unmarshal(w.body, &p) == nil && p.Error != "" {
		return p.Error
	}
	return http.StatusText(w.code())
}
