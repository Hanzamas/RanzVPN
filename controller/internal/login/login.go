// Package login is the logins of users at the controller (SDN-32 #226, ADR-0031 amendment of
// 2026-10-28). A User of the intent proves its password, and the login gives it a user token for the
// API, with the API role that an admin gave the User (internal/rbac), or enrols the device that asked
// for the login as a Node owned by the User (controller.EnrolDevice). There are three ways in, each the
// standard one of its case:
//
//   - The password login (POST /api/v1/login): the name and the password in the body, a user token in
//     the answer, for a client that has a person at it.
//   - The browser login, the authorization code grant of OAuth 2.0 (RFC 6749 section 4.1) with PKCE
//     (RFC 7636) for a native client (RFC 8252): the client opens the browser at the authorization
//     page of the controller with a loopback redirect, the user signs in on that page, and the client
//     exchanges the code that the redirect brings for the user token or the enrolment, with the
//     verifier that only it holds.
//   - The device code login (RFC 8628): a device without a browser asks for a code, the user types it
//     into the device page of the controller on any other device and signs in there, and the device
//     polls the token endpoint until the answer is there.
//
// No call of a login carries a bearer token, so the API serves them in front of its Guard
// (api.WithLogins). A login with a wrong password is refused and recorded in the audit log
// (audit.AuthFailed, with the name it gave and its source), and the throttle refuses the next ones of
// that name and of that source at once, without a check of the password, once they failed a few times
// in a row (throttle.go). A login that succeeds is an audit.Login of the User, and the revision of an
// enrolment is recorded under the User. Multi-factor login is not here: #226 postponed it.
package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The paths of the logins.
const (
	// Root is the root of the logins and the path of the password login.
	Root = "/api/v1/login"
	// AuthorizePath is the authorization page of a browser login (GET) and its form (POST).
	AuthorizePath = Root + "/authorize"
	// TokenPath is the token endpoint (RFC 6749 section 3.2).
	TokenPath = Root + "/token"
	// DeviceCodePath is the device authorization endpoint of a device code login (RFC 8628 section 3.1).
	DeviceCodePath = Root + "/device/code"
	// DevicePath is the device page, where a user types the user code of a device (GET), and its form
	// (POST): the verification URI of RFC 8628.
	DevicePath = Root + "/device"
	// LogoutPath ends the user token that the call carries as its bearer token.
	LogoutPath = Root + "/logout"
)

const (
	// ClientID is the client_id of the one client of the logins: the public client ranz (RFC 6749
	// section 2.1), which ranz login, ranz node login and the tray are.
	ClientID = "ranz"
	// DeviceGrant is the grant_type of the poll of a device code (RFC 8628 section 3.4).
	DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"
	// DefaultTokenLife is how long a user token lasts when the Config gives no other life.
	DefaultTokenLife = 12 * time.Hour
	// DefaultInterval is the least time between two polls of a device code (RFC 8628 section 3.5)
	// when the Config gives no other.
	DefaultInterval = 5 * time.Second
	// codeLife is how long an authorization code waits for its exchange.
	codeLife = time.Minute
	// deviceLife is how long a device code waits for its user.
	deviceLife = 10 * time.Minute
	// maxGrants bounds the authorization codes and the device codes that wait, and maxGrantsPerSource
	// the device codes that one source asked for.
	maxGrants          = 1024
	maxGrantsPerSource = 16
	// maxBody bounds the body of a call of a login.
	maxBody = 16 << 10
)

// challenge is the WWW-Authenticate header of a refused login, the one of the API (RFC 6750).
const challenge = `Bearer realm="ranz-controller"`

// nameRule is the rule of resource names (internal/intent), which the name of a User follows.
var nameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Controller is what the logins ask of the controller (internal/controller).
type Controller interface {
	// AuthenticateUser checks the password of a User.
	AuthenticateUser(ctx context.Context, l controller.Login) (controller.Account, error)
	// EnrolDevice makes the Node resource of a device of a User.
	EnrolDevice(ctx context.Context, user, name string, key []byte) (controller.Enrolment, error)
	// RecordAudit adds a record to the audit log.
	RecordAudit(ctx context.Context, r audit.Record) error
	// PublicKey returns the Noise static key of the controller.
	PublicKey() []byte
}

// Tokens are the user tokens and the API roles of the users (internal/rbac).
type Tokens interface {
	UserRole(ctx context.Context, name string) (rbac.Role, bool, error)
	IssueUserToken(ctx context.Context, name string, expires time.Time) (rbac.UserToken, error)
	RevokeUserToken(ctx context.Context, secret string) (rbac.Token, error)
}

// Config is what the logins run with.
type Config struct {
	Controller Controller
	Tokens     Tokens
	// Fingerprint returns the TLS fingerprint of the certificate that the port of the controller
	// serves now, which the Node of an enrolment pins; nil gives none.
	Fingerprint func() string
	// TokenLife is how long a user token lasts, DefaultTokenLife when it is 0; a token never outlives
	// the expiry of its User.
	TokenLife time.Duration
	// Interval is the least time between two polls of a device code, DefaultInterval when it is 0.
	Interval time.Duration
}

// Server serves the logins. Its grants wait in memory, on the member of a controller cluster that
// leads: a login that waits when the leader changes is started again.
type Server struct {
	cfg   Config
	mux   *http.ServeMux
	fails *limiter
	now   func() time.Time

	mu      sync.Mutex
	codes   map[string]*grant // the authorization codes, by the SHA-256 of the code
	devices map[string]*grant // the device codes, by the SHA-256 of the device code
}

// New returns the logins of cfg.
func New(cfg Config) *Server {
	if cfg.TokenLife <= 0 {
		cfg.TokenLife = DefaultTokenLife
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	s := &Server{cfg: cfg, fails: newLimiter(), now: time.Now, codes: map[string]*grant{}, devices: map[string]*grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+Root, s.signIn)
	mux.HandleFunc("GET "+AuthorizePath, s.authorizePage)
	mux.HandleFunc("POST "+AuthorizePath, s.authorize)
	mux.HandleFunc("POST "+TokenPath, s.token)
	mux.HandleFunc("POST "+DeviceCodePath, s.deviceCode)
	mux.HandleFunc("GET "+DevicePath, s.devicePage)
	mux.HandleFunc("POST "+DevicePath, s.approveDevice)
	mux.HandleFunc("POST "+LogoutPath, s.logout)
	// The join of a device with a join token of the portal (portal.go; SDN-58)
	mux.HandleFunc("POST "+JoinPath, s.join)
	s.mux = mux
	return s
}

// ServeHTTP serves a call of the logins.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// SignInRequest is the body of a password login (POST /api/v1/login).
type SignInRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
	// Saved says that the client took the password from its own storage, which a User that may not
	// save its password refuses (intent.User.NoSavedPassword).
	Saved bool `json:"saved,omitempty"`
	// Scope asks for a token that does less than the API role of the User allows: ScopeSelf gives a token
	// of the self scope, for the portal, which needs no API role (portal.go; SDN-58). Left out, the login
	// gives the user token of the API role of the User.
	Scope string `json:"scope,omitempty"`
}

// SignedIn is the answer of a password login: the user token with its secret and its end, and whether
// the client must not keep the password of the User.
type SignedIn struct {
	rbac.UserToken
	// NoSavedPassword tells the client not to keep the password (intent.User.NoSavedPassword).
	NoSavedPassword bool `json:"noSavedPassword,omitempty"`
}

// Problem is the answer of a call that failed, as of every call of the API (api.Problem).
type Problem struct {
	Error string `json:"error"`
}

// signIn serves a password login.
func (s *Server) signIn(w http.ResponseWriter, r *http.Request) {
	var req SignInRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		reply(w, http.StatusBadRequest, Problem{Error: `the body is not a login, {"user": "...", "password": "..."}: ` + err.Error()})
		return
	}
	acct, err := s.authenticate(r, req.User, req.Password, req.Saved)
	if err != nil {
		refuse(w, err)
		return
	}
	if req.Scope != "" {
		// A login for the portal: a token of the self scope (portal.go; SDN-58)
		s.signInScoped(w, r, req.Scope, acct)
		return
	}
	tok, err := s.issue(r, acct)
	if err != nil {
		refuse(w, err)
		return
	}
	reply(w, http.StatusOK, SignedIn{UserToken: tok, NoSavedPassword: acct.NoSavedPassword})
}

// logout ends the user token that the call carries as its bearer token, and records the logout.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	secret = strings.TrimSpace(secret)
	if !ok || !strings.EqualFold(scheme, "Bearer") || secret == "" {
		w.Header().Set("WWW-Authenticate", challenge)
		reply(w, http.StatusUnauthorized, Problem{Error: "the request has no bearer token: a logout ends the user token that it carries"})
		return
	}
	tok, err := s.cfg.Tokens.RevokeUserToken(r.Context(), secret)
	if errors.Is(err, rbac.ErrUnauthenticated) {
		w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
		reply(w, http.StatusUnauthorized, Problem{Error: "the bearer token is no user token of this controller, or it ended"})
		return
	}
	if err != nil {
		refuse(w, err)
		return
	}
	s.record(r, audit.Logout, tok.User, audit.Success, "the user token ended at the logout of its user")
	reply(w, http.StatusOK, tok)
}

// authenticate checks the login of the User name with the password secret, from the source of r: the
// throttle first, then the password (controller.AuthenticateUser). Each refusal is recorded in the
// audit log, and a wrong password takes a try from the name and from the source (throttle.go).
func (s *Server) authenticate(r *http.Request, name, secret string, saved bool) (controller.Account, error) {
	now := s.now()
	keys := []string{nameKey(name), sourceKey(sourceOf(r))}
	if wait := s.fails.wait(now, keys...); wait > 0 {
		err := &throttled{wait: wait}
		s.record(r, audit.AuthFailed, name, audit.Failure, err.Error()+"; the password was not checked")
		return controller.Account{}, err
	}
	acct, err := s.cfg.Controller.AuthenticateUser(r.Context(), controller.Login{User: name, Password: secret, Saved: saved})
	switch {
	case err == nil:
		return acct, nil
	case errors.Is(err, controller.ErrBadCredentials):
		s.fails.fail(now, keys...)
		s.record(r, audit.AuthFailed, name, audit.Failure, err.Error())
	case errors.Is(err, controller.ErrUserExpired), errors.Is(err, controller.ErrUserBanned), errors.Is(err, controller.ErrSavedPassword):
		s.record(r, audit.AuthFailed, name, audit.Failure, err.Error())
	}
	return controller.Account{}, err
}

// issue gives the User of acct, which just logged in, a user token that lasts the life of the Config,
// and no longer than the User, and records the login. A User that holds no API role gets none
// (rbac.ErrNoRole), and that is recorded too.
func (s *Server) issue(r *http.Request, acct controller.Account) (rbac.UserToken, error) {
	end := s.now().Add(s.cfg.TokenLife)
	if !acct.Expires.IsZero() && acct.Expires.Before(end) {
		end = acct.Expires
	}
	tok, err := s.cfg.Tokens.IssueUserToken(r.Context(), acct.Name, end)
	if errors.Is(err, rbac.ErrNoRole) {
		s.record(r, audit.Login, acct.Name, audit.Failure, "the user holds no API role, so the login gives it no user token")
		return rbac.UserToken{}, err
	}
	if err != nil {
		return rbac.UserToken{}, err
	}
	s.record(r, audit.Login, acct.Name, audit.Success, fmt.Sprintf("a user token with the role %s until %s", tok.Grant(), tok.Expires.Format(time.RFC3339)))
	return tok, nil
}

// record adds a record of the kind kind about the User name, which a login gave, from the source of r,
// to the audit log. A name that no User can have names no actor: the record has the actor unknown.
func (s *Server) record(r *http.Request, kind, name, outcome, message string) {
	actor := audit.ActorUnknown
	if nameRule.MatchString(name) {
		actor = audit.ActorUser(name)
	}
	// RecordAudit logs a record that it could not store: the answer of the login stands
	_ = s.cfg.Controller.RecordAudit(r.Context(), audit.Record{Kind: kind, Actor: actor, Source: sourceOf(r), Outcome: outcome, Message: message})
}

// sourceOf returns the address that r came from, without its port.
func sourceOf(r *http.Request) string {
	return audit.Host(r.RemoteAddr)
}

// throttled is the refusal of a login that the throttle holds back for wait.
type throttled struct {
	wait time.Duration
}

func (t *throttled) Error() string {
	return fmt.Sprintf("too many failed logins for this user name or from this address: try again in %d s", seconds(t.wait))
}

// seconds returns d in whole seconds, rounded up.
func seconds(d time.Duration) int64 {
	return int64((d + time.Second - 1) / time.Second)
}

// statusOf returns the HTTP status of the refusal err of a login.
func statusOf(err error) int {
	var t *throttled
	switch {
	case errors.As(err, &t):
		return http.StatusTooManyRequests
	case errors.Is(err, controller.ErrBadCredentials), errors.Is(err, controller.ErrBadJoinToken):
		return http.StatusUnauthorized
	case errors.Is(err, controller.ErrUserExpired), errors.Is(err, controller.ErrUserBanned), errors.Is(err, controller.ErrSavedPassword),
		errors.Is(err, rbac.ErrNoRole), errors.Is(err, licence.ErrRefused):
		return http.StatusForbidden
	case errors.Is(err, intent.ErrInvalid), errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	case errors.Is(err, intent.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, controller.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, store.ErrNotLeader):
		// The member lost the lease during the login; the next leader serves it again
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// refuse answers the refusal err of a call of the logins as the API answers a refusal: its status and
// the Problem. A login that the throttle holds back says when to try again (Retry-After), and one with
// a wrong password asks for credentials (WWW-Authenticate).
func refuse(w http.ResponseWriter, err error) {
	code := statusOf(err)
	retryAfter(w, err)
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	reply(w, code, Problem{Error: err.Error()})
}

// retryAfter sets the Retry-After header of the answer to a login that the throttle holds back.
func retryAfter(w http.ResponseWriter, err error) {
	var t *throttled
	if errors.As(err, &t) {
		w.Header().Set("Retry-After", strconv.FormatInt(seconds(t.wait), 10))
	}
}

// reply writes v as the JSON answer with the status code code. Nothing of a login is kept in a cache
// (RFC 6749 section 5.1).
func reply(w http.ResponseWriter, code int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	_ = e.Encode(v)
}

// digest returns the key under which a code waits: its SHA-256, so that the codes themselves are kept
// nowhere.
func digest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// keyText returns the static key of a device as the publicKey of its Node resource and ranz node key
// show it.
func keyText(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
