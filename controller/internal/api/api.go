// Package api is the controller's HTTP API (JSON): the only way into the controller for the
// `ranz` CLI and later the web UI (#176 "Intent API, explain and RBAC"). It runs on the
// controller's TLS port beside the control stream (internal/port) and answers clients on any
// host. Every call needs the bearer token of a role (internal/rbac, SDN-14 #190): a read needs
// viewer, a change of the Intent operator, and the tokens themselves admin (Needs). The roles are
// checked here only, so every client of the API gets the same answers.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// maxBody bounds the body of an apply.
const maxBody = 16 << 20

// tokensPath is the root of the API tokens, which only an admin may read or change.
const tokensPath = "/api/v1/tokens"

// challenge is the WWW-Authenticate header of a refusal (RFC 6750), which names the controller.
const challenge = `Bearer realm="ranz-controller"`

// Status is the answer of GET /api/v1/status.
type Status struct {
	PublicKey      string       `json:"publicKey"`      // base64 of the controller's Noise static key
	ControlAddress string       `json:"controlAddress"` // where the controller listens for control streams
	TLSFingerprint string       `json:"tlsFingerprint"` // hex SHA-256 of the public key of the TLS certificate
	Capabilities   Capabilities `json:"capabilities"`
	// Cluster tells which member of the controller cluster answers and which one leads
	// (internal/cluster). Every member answers the status itself.
	Cluster *ClusterStatus `json:"cluster,omitempty"`
}

// ClusterStatus is the cluster part of Status.
type ClusterStatus struct {
	Member string `json:"member"` // the name of the member that answers
	Role   string `json:"role"`   // RoleLeader or RoleStandby
	Leader string `json:"leader"` // the name of the member that holds the lease, empty while none does
	Epoch  int64  `json:"epoch"`  // the lease epoch of the leader
	// SchemaVersion is the control schema version the member runs as (controller.Config.Schema).
	SchemaVersion int32 `json:"schemaVersion"`
}

// The roles of a member of a controller cluster.
const (
	RoleLeader  = "leader"
	RoleStandby = "standby"
)

// Capabilities is what the controller runs with on its host.
type Capabilities struct {
	// TLSPort is the TCP port of the control stream and the API: 443, or 5555 after a fallback.
	TLSPort int `json:"tlsPort"`
	// TLSPortFallback is true when 443 could not be bound, at this start or an earlier one, and
	// the controller listens on 5555 instead (ADR-0020).
	TLSPortFallback bool `json:"tlsPortFallback"`
	// PlainHTTP tells where the plain-HTTP port (redirect and ACME) runs, empty when it is off:
	// a TCP address, or the HTTP.sys URL prefixes on Windows.
	PlainHTTP string `json:"plainHttp,omitempty"`
}

// ResourceList is the answer of GET /api/v1/resources: the intent.
type ResourceList struct {
	Resources []intent.Resource `json:"resources"`
}

// NodeList is the answer of GET /api/v1/nodes.
type NodeList struct {
	Nodes []controller.NodeStatus `json:"nodes"`
}

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

// EventList is the answer of GET /api/v1/events: every event, oldest first.
type EventList struct {
	Events []event.Event `json:"events"`
}

// TokenList is the answer of GET /api/v1/tokens.
type TokenList struct {
	Tokens []rbac.Token `json:"tokens"`
}

// TokenRequest is the body of POST /api/v1/tokens.
type TokenRequest struct {
	Name string    `json:"name"`
	Role rbac.Role `json:"role"`
}

// Problem is the body of every answer that is not 200 OK.
type Problem struct {
	Error string `json:"error"`
}

// Handler returns the API of c, guarded by the roles of tokens (Guard). The role each call
// needs at least is on its right:
//
//	GET    /api/v1/status                  Status                                       viewer
//	GET    /api/v1/whoami                  the caller's rbac.Token                      viewer
//	GET    /api/v1/resources               ResourceList                                 viewer
//	GET    /api/v1/nodes                   NodeList                                     viewer
//	POST   /api/v1/apply                   an intent.Document; a controller.ApplyResult operator
//	                                       ?confirm=DURATION: roll back after DURATION unless confirmed
//	DELETE /api/v1/resources/{kind}/{name} a controller.ApplyResult                     operator
//	GET    /api/v1/revisions               RevisionList                                 viewer
//	GET    /api/v1/revisions/{id}          an intent.Revision with its resources        viewer
//	POST   /api/v1/revisions/{id}/confirm  the intent.Revision, confirmed               operator
//	POST   /api/v1/rollback                a RollbackRequest; a controller.ApplyResult  operator
//	GET    /api/v1/diff?from=A&to=B        DiffResult                                   viewer
//	                                       to is the latest revision when left out, from the one before to
//	GET    /api/v1/events                  EventList                                    viewer
//	GET    /api/v1/tokens                  TokenList                                    admin
//	POST   /api/v1/tokens                  a TokenRequest; an rbac.NewToken             admin
//	DELETE /api/v1/tokens/{name}           the rbac.Token deleted                       admin
//
// status holds the control address and the TLS fingerprint that the status call reports;
// Handler fills in the public key.
func Handler(c *controller.Controller, tokens *rbac.Tokens, status Status) http.Handler {
	return Guard(tokens, Routes(c, tokens, status))
}

// Routes returns the calls of Handler without the Guard in front of them, for a handler that
// guards them itself: a member of a controller cluster guards its own calls and the ones it
// forwards to the leader alike (internal/cluster).
func Routes(c *controller.Controller, tokens *rbac.Tokens, status Status) *http.ServeMux {
	status.PublicKey = base64.StdEncoding.EncodeToString(c.PublicKey())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, status)
	})
	mux.HandleFunc("GET /api/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		tok, _ := Caller(r.Context())
		reply(w, http.StatusOK, tok)
	})
	mux.HandleFunc("GET /api/v1/resources", func(w http.ResponseWriter, r *http.Request) {
		rs := c.Resources()
		if rs == nil {
			rs = []intent.Resource{}
		}
		reply(w, http.StatusOK, ResourceList{Resources: rs})
	})
	mux.HandleFunc("GET /api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, NodeList{Nodes: c.Nodes()})
	})
	mux.HandleFunc("POST /api/v1/apply", func(w http.ResponseWriter, r *http.Request) {
		confirm, err := confirmParam(r.URL.Query().Get("confirm"))
		if err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
			return
		}
		var doc intent.Document
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		d.DisallowUnknownFields()
		if err := d.Decode(&doc); err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: "the body is not an intent document: " + err.Error()})
			return
		}
		res, err := c.ApplyConfirm(r.Context(), doc, confirm)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /api/v1/resources/{kind}/{name}", func(w http.ResponseWriter, r *http.Request) {
		res, err := c.Delete(r.Context(), r.PathValue("kind"), r.PathValue("name"))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /api/v1/revisions", func(w http.ResponseWriter, r *http.Request) {
		revs, err := c.Revisions(r.Context())
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, RevisionList{Revisions: revs})
	})
	mux.HandleFunc("GET /api/v1/revisions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := revisionNumber(r.PathValue("id"))
		if err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
			return
		}
		rev, err := c.Revision(r.Context(), id)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, rev)
	})
	mux.HandleFunc("POST /api/v1/revisions/{id}/confirm", func(w http.ResponseWriter, r *http.Request) {
		id, err := revisionNumber(r.PathValue("id"))
		if err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
			return
		}
		rev, err := c.Confirm(r.Context(), id)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, rev)
	})
	mux.HandleFunc("POST /api/v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		var req RollbackRequest
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		d.DisallowUnknownFields()
		if err := d.Decode(&req); err != nil || req.Revision == nil {
			reply(w, http.StatusBadRequest, Problem{Error: `the body must be {"revision": N}, with N the revision to return to`})
			return
		}
		res, err := c.Rollback(r.Context(), *req.Revision)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /api/v1/diff", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		to := c.LatestRevision()
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
		changes, err := c.Diff(r.Context(), from, to)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, DiffResult{From: from, To: to, Changes: changes})
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		evs, err := c.Events(r.Context())
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, EventList{Events: evs})
	})
	mux.HandleFunc("GET "+tokensPath, func(w http.ResponseWriter, r *http.Request) {
		ts, err := tokens.List(r.Context())
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, TokenList{Tokens: ts})
	})
	mux.HandleFunc("POST "+tokensPath, func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		d.DisallowUnknownFields()
		if err := d.Decode(&req); err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: "the body is not a token request: " + err.Error()})
			return
		}
		tok, err := tokens.Create(r.Context(), req.Name, req.Role)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, tok)
	})
	mux.HandleFunc("DELETE "+tokensPath+"/{name}", func(w http.ResponseWriter, r *http.Request) {
		tok, err := tokens.Delete(r.Context(), r.PathValue("name"))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, tok)
	})
	return mux
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

func revisionNumber(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a revision number", s)
	}
	return id, nil
}

// Needs returns the least role that may make a request with method to urlPath. Everything under
// /api/v1/tokens, which says who holds which role, needs admin; any other read (GET or HEAD)
// needs viewer; every other request changes the Intent and needs operator. An endpoint added
// later is so guarded from the start, by what its method does.
func Needs(method, urlPath string) rbac.Role {
	p := path.Clean("/" + urlPath)
	switch {
	case p == tokensPath || strings.HasPrefix(p, tokensPath+"/"):
		return rbac.Admin
	case method == http.MethodGet || method == http.MethodHead:
		return rbac.Viewer
	}
	return rbac.Operator
}

// Guard passes each request whose bearer token has a role that allows what the request Needs
// to h, with the token in its context (Caller). It answers 401 Unauthorized to a request with no
// token or with one the controller does not know, and 403 Forbidden to one whose role is too
// low (RFC 6750, section 3).
func Guard(tokens *rbac.Tokens, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", challenge)
			reply(w, http.StatusUnauthorized, Problem{Error: "the request has no bearer token: every call of the API needs the token of a role (viewer, operator or admin)"})
			return
		}
		tok, err := tokens.Authenticate(r.Context(), secret)
		if errors.Is(err, rbac.ErrUnauthenticated) {
			w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
			reply(w, http.StatusUnauthorized, Problem{Error: "the bearer token is not a token of this controller, or it was deleted"})
			return
		}
		if err != nil {
			replyError(w, err)
			return
		}
		if need := Needs(r.Method, r.URL.Path); !tok.Role.Allows(need) {
			w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
			reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the call needs the role %s or one above it, and the token %q has the role %s",
				need, tok.Name, tok.Role)})
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, tok)))
	})
}

type callerKey struct{}

// Caller returns the token of the caller of a request with the context ctx, as Guard put it
// there.
func Caller(ctx context.Context) (rbac.Token, bool) {
	tok, ok := ctx.Value(callerKey{}).(rbac.Token)
	return tok, ok
}

// bearer returns the bearer token of the Authorization header of r (RFC 6750, section 2.1).
func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

// Reply writes v as the JSON answer with the status code code, as every answer of the API.
func Reply(w http.ResponseWriter, code int, v any) {
	reply(w, code, v)
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	_ = e.Encode(v)
}

func replyError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, intent.ErrNotFound), errors.Is(err, controller.ErrNoRevision), errors.Is(err, rbac.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, intent.ErrInvalid), errors.Is(err, controller.ErrBadConfirm), errors.Is(err, rbac.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, controller.ErrConflict), errors.Is(err, rbac.ErrExists), errors.Is(err, rbac.ErrLastAdmin):
		code = http.StatusConflict
	case errors.Is(err, store.ErrNotLeader):
		// The member lost the lease during the request; the next leader serves it again.
		code = http.StatusServiceUnavailable
	}
	reply(w, code, Problem{Error: err.Error()})
}

// Client calls the API of a controller.
type Client struct {
	URL   string       // the base URL, for example https://127.0.0.1
	Token string       // the bearer token the calls carry, none when empty
	HTTP  *http.Client // http.DefaultClient when nil
}

// Error is an answer of the API that is not 200 OK.
type Error struct {
	Method, Path string
	Status       int    // the HTTP status code
	Message      string // the error of the Problem, or the status line when there is none
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s: %s", e.Method, e.Path, e.Message)
}

// NewClient returns a client of the API at base. The controller's certificate is self-signed
// until ACME, so for a loopback host the client does not check the certificate (nothing outside
// the host can sit between the two ends); for any other host it checks the certificate as
// usual, or the fingerprint that Pin sets.
func NewClient(base string) *Client {
	c := &Client{URL: base}
	if u, err := url.Parse(base); err == nil && u.Scheme == "https" && loopbackHost(u.Hostname()) {
		c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	return c
}

// Pin makes c accept only a certificate whose public key has the fingerprint fp, the
// tlsFingerprint of the controller's Status, in place of the usual certificate check. A client
// on another host so reaches a controller whose certificate is self-signed.
func (c *Client) Pin(fp string) error {
	want, err := hex.DecodeString(fp)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("the TLS fingerprint %q is not the hex of a SHA-256", fp)
	}
	c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		// VerifyConnection checks the certificate, against the fingerprint.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the controller sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], want) {
				return fmt.Errorf("the controller's certificate has the TLS fingerprint %x, not %s", sum, fp)
			}
			return nil
		},
	}}}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// Status returns the controller's static key, its control address and its TLS fingerprint.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &s)
	return s, err
}

// Whoami returns the token the client calls with: its name and its role.
func (c *Client) Whoami(ctx context.Context) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodGet, "/api/v1/whoami", nil, &t)
	return t, err
}

// Resources returns the intent.
func (c *Client) Resources(ctx context.Context) ([]intent.Resource, error) {
	var l ResourceList
	err := c.do(ctx, http.MethodGet, "/api/v1/resources", nil, &l)
	return l.Resources, err
}

// Nodes returns the status of every node.
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
	var d DiffResult
	err := c.do(ctx, http.MethodGet, path, nil, &d)
	return d, err
}

// Events returns every event, oldest first.
func (c *Client) Events(ctx context.Context) ([]event.Event, error) {
	var l EventList
	err := c.do(ctx, http.MethodGet, "/api/v1/events", nil, &l)
	return l.Events, err
}

// Tokens returns every API token, without the secrets.
func (c *Client) Tokens(ctx context.Context) ([]rbac.Token, error) {
	var l TokenList
	err := c.do(ctx, http.MethodGet, tokensPath, nil, &l)
	return l.Tokens, err
}

// CreateToken creates the API token name with role and returns it with its secret.
func (c *Client) CreateToken(ctx context.Context, name string, role rbac.Role) (rbac.NewToken, error) {
	var t rbac.NewToken
	err := c.do(ctx, http.MethodPost, tokensPath, TokenRequest{Name: name, Role: role}, &t)
	return t, err
}

// DeleteToken deletes the API token name and returns it.
func (c *Client) DeleteToken(ctx context.Context, name string) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodDelete, tokensPath+"/"+url.PathEscape(name), nil, &t)
	return t, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Method: method, Path: path, Status: resp.StatusCode, Message: resp.Status}
		var p Problem
		if json.Unmarshal(data, &p) == nil && p.Error != "" {
			e.Message = p.Error
		}
		return e
	}
	return json.Unmarshal(data, out)
}
