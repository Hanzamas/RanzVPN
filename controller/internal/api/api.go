// Package api is the controller's HTTP API (JSON): the only way into the controller for the
// `ranz` CLI and later the web UI (#176 "Intent API, explain and RBAC"). It runs on the
// controller's TLS port beside the control stream (internal/port) and answers clients on any
// host. Every call needs the bearer token of a role (internal/rbac, SDN-14 #190): a read needs
// viewer, a change of the Intent operator, and the tokens themselves admin (Needs). The roles are
// checked here only, so every client of the API gets the same answers.
//
// Each feature contributes its routes from its own file: the file's init() calls register with
// the route's method, path, the least role it needs and its handler, and Routes builds the mux
// from what is registered. Adding an endpoint is a new file, not an edit of this one, and the
// Guard stays the one place that turns a request into the role it needs (Needs). See CONTEXT.md,
// "Controller API registries".
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
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// maxBody bounds the body of an apply.
const maxBody = 16 << 20

// tokensPath is the root of the API tokens, which only an admin may read or change.
const tokensPath = "/api/v1/tokens"

// challenge is the WWW-Authenticate header of a refusal (RFC 6750), which names the controller.
const challenge = `Bearer realm="ranz-controller"`

// Problem is the body of every answer that is not 200 OK.
type Problem struct {
	Error string `json:"error"`
}

// routeDeps is what a route's handler needs to serve a request: the controller the member leads,
// the API tokens and the static part of GET /api/v1/status. Routes fills one in and passes it to
// every handler.
type routeDeps struct {
	Controller *controller.Controller
	Tokens     *rbac.Tokens
	Status     Status
}

// route is one registered API endpoint: its method and its path pattern (an http.ServeMux
// pattern), the least role it needs, and the handler. Role must be the role Needs returns for the
// method and a path that matches the pattern, so the role a feature declares in its own file can
// never drift from the one place the Guard decides roles (TestRegisteredRolesMatchNeeds checks
// it).
type route struct {
	Method  string
	Pattern string
	Role    rbac.Role
	Handle  func(d routeDeps, w http.ResponseWriter, r *http.Request)
}

// routes holds every registered API route. Each feature file appends to it from its own init()
// through register.
var routes []route

// register adds rs to the API. A feature file calls it once from its init(), so adding an
// endpoint is a new file, not an edit of Routes.
func register(rs ...route) {
	routes = append(routes, rs...)
}

// Handler returns the API of c, guarded by the roles of tokens (Guard). The role each call needs
// at least is on its right:
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
//	GET    /api/v1/licence                 licence.Status, the licence in force         viewer
//	PUT    /api/v1/licence                 a LicenceKey; licence.Status                 operator
//	DELETE /api/v1/licence                 removes the licence key; licence.Status      operator
//	GET    /api/v1/tokens                  TokenList                                    admin
//	POST   /api/v1/tokens                  a TokenRequest; an rbac.NewToken             admin
//	DELETE /api/v1/tokens/{name}           the rbac.Token deleted                       admin
//
// Each call is registered from its feature file (register); the table above is the overview.
// An apply or a rollback that a node cannot honour answers 409 Conflict, naming the node and the
// Capability it lacks. What the licence in force does not allow is answered with 403 Forbidden,
// and a licence key that does not verify with 400 Bad Request. status holds the control address
// and the TLS fingerprint that the status call reports; Handler fills in the public key.
func Handler(c *controller.Controller, tokens *rbac.Tokens, status Status) http.Handler {
	return Guard(tokens, Routes(c, tokens, status))
}

// Routes returns the calls of Handler without the Guard in front of them, for a handler that
// guards them itself: a member of a controller cluster guards its own calls and the ones it
// forwards to the leader alike (internal/cluster). It builds the mux from the registered routes.
func Routes(c *controller.Controller, tokens *rbac.Tokens, status Status) *http.ServeMux {
	status.PublicKey = base64.StdEncoding.EncodeToString(c.PublicKey())
	deps := routeDeps{Controller: c, Tokens: tokens, Status: status}
	mux := http.NewServeMux()
	for _, rt := range routes {
		handle := rt.Handle
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
			handle(deps, w, r)
		})
	}
	return mux
}

// Needs returns the least role that may make a request with method to urlPath. Everything under
// /api/v1/tokens, which says who holds which role, the admin source allowlist, which says where
// the console may be reached from, and the admin destination lists, which say where an operator
// may point the controller and the nodes, need admin; so do everything under /api/v1/audit/targets,
// which says where the audit log goes, and the change of /api/v1/audit/retention, which says how
// long it is kept (AUD1-DT-9, #457). Everything under /api/v1/operations, the live operations of an
// operator, needs operator, the reads too, since they show who is connected and what the nodes learnt
// of their members (SDN-50, #243). Any other read (GET or HEAD) needs viewer; every other request
// changes the Intent and needs operator. An endpoint added later is so guarded from the start, by
// what its method does.
func Needs(method, urlPath string) rbac.Role {
	p := path.Clean("/" + urlPath)
	read := method == http.MethodGet || method == http.MethodHead
	switch {
	case p == tokensPath || strings.HasPrefix(p, tokensPath+"/") || p == adminSourcesPath || p == adminDestinationsPath:
		return rbac.Admin
	case p == auditTargetsPath || strings.HasPrefix(p, auditTargetsPath+"/"), p == auditRetentionPath && !read:
		return rbac.Admin
	case p == operationsPath || strings.HasPrefix(p, operationsPath+"/"):
		return rbac.Operator
	case read:
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
	case errors.Is(err, intent.ErrInvalid), errors.Is(err, controller.ErrBadConfirm), errors.Is(err, rbac.ErrInvalid),
		errors.Is(err, licence.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, licence.ErrRefused):
		code = http.StatusForbidden
	case errors.Is(err, capability.ErrMissing), errors.Is(err, controller.ErrConflict), errors.Is(err, rbac.ErrExists),
		errors.Is(err, rbac.ErrLastAdmin):
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
