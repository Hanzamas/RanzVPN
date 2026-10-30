package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The two ways in that the self-service portal adds (SDN-58 #251, ADR-0031 amendment of 2026-10-29):
//
//   - A password login that asks for the scope self (SignInRequest.Scope) gives the User a token of the self
//     scope, which holds no API role: the web UI of the portal signs a User in with it, and the token may make
//     the self calls of that User and no other call of the API. It needs no API role of the User.
//   - The join of a device with a join token (POST /api/v1/login/join): a User made the join token in the
//     portal for a device of its own, and the device presents the secret with its static key. The Controller
//     enrols the device as a Node of that User (controller.JoinDevice) and answers with the keys that its Node
//     pins, as a login that enrols a device does. The call carries no bearer token, so it is a call of the
//     logins; the secret is checked by the Controller, and a secret that is none counts against the source
//     that presented it, as a wrong password does.
//
// Both ask more of the controller and of the token store than the interfaces of login.go name, so that the
// fakes of a test that does not run the portal need neither (selfIssuer, joiner): the Controller and the
// Tokens of ranz-controller have them.

const (
	// JoinPath is the join of a device with a join token (POST).
	JoinPath = Root + "/join"
	// ScopeSelf is the scope of the token that a login for the portal gives.
	ScopeSelf = "self"
)

// selfIssuer is what a login for the portal asks of the token store: a token of the self scope.
type selfIssuer interface {
	IssueSelfToken(ctx context.Context, name string, expires time.Time) (rbac.UserToken, error)
}

// joiner is what the join of a device asks of the controller.
type joiner interface {
	JoinDevice(ctx context.Context, secret, name string, key []byte) (controller.Enrolment, error)
}

// JoinRequest is the join of a device with a join token: the secret of the token and the device to enrol.
type JoinRequest struct {
	Token  string
	Device Device
}

// ParseJoin parses the form of the join of a device with a join token and checks it: the secret of a join
// token (controller.ValidJoinToken), the static key of the device in base64, and the name that it asks for,
// which may be left out. No parameter may be given twice. An error wraps ErrInvalid.
func ParseJoin(f url.Values) (JoinRequest, error) {
	if err := once(f, "token", "node_key", "node_name"); err != nil {
		return JoinRequest{}, err
	}
	token := f.Get("token")
	if !controller.ValidJoinToken(token) {
		return JoinRequest{}, fmt.Errorf("%w: the token is not the secret of a join token", ErrInvalid)
	}
	if f.Get("node_key") == "" {
		return JoinRequest{}, fmt.Errorf("%w: the node_key of the device is missing", ErrInvalid)
	}
	d, err := parseDevice(f)
	if err != nil {
		return JoinRequest{}, err
	}
	return JoinRequest{Token: token, Device: *d}, nil
}

// signInScoped answers a password login that asked for a scope, once its password checked out: a token of
// the self scope for ScopeSelf, and a refusal for any other scope.
func (s *Server) signInScoped(w http.ResponseWriter, r *http.Request, scope string, acct controller.Account) {
	if scope != ScopeSelf {
		reply(w, http.StatusBadRequest, Problem{Error: fmt.Sprintf("the scope is %q, and the controller takes %q only", clipped(scope), ScopeSelf)})
		return
	}
	issuer, ok := s.cfg.Tokens.(selfIssuer)
	if !ok {
		reply(w, http.StatusNotImplemented, Problem{Error: "this controller gives no token of the scope " + ScopeSelf})
		return
	}
	end := s.now().Add(s.cfg.TokenLife)
	if !acct.Expires.IsZero() && acct.Expires.Before(end) {
		end = acct.Expires
	}
	tok, err := issuer.IssueSelfToken(r.Context(), acct.Name, end)
	if err != nil {
		refuse(w, err)
		return
	}
	s.record(r, audit.Login, acct.Name, audit.Success, fmt.Sprintf("a token of the scope %s until %s", ScopeSelf, tok.Expires.Format(time.RFC3339)))
	reply(w, http.StatusOK, SignedIn{UserToken: tok, NoSavedPassword: acct.NoSavedPassword})
}

// join serves the join of a device with a join token.
func (s *Server) join(w http.ResponseWriter, r *http.Request) {
	j, ok := s.cfg.Controller.(joiner)
	if !ok {
		reply(w, http.StatusNotImplemented, Problem{Error: "this controller takes no join of a device with a join token"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		reply(w, http.StatusBadRequest, Problem{Error: "the body is not a form: " + err.Error()})
		return
	}
	req, err := ParseJoin(r.PostForm)
	if err != nil {
		refuse(w, err)
		return
	}
	now := s.now()
	key := joinKey(r)
	if wait := s.fails.wait(now, key); wait > 0 {
		err := &throttled{wait: wait}
		s.record(r, audit.AuthFailed, "", audit.Failure, err.Error()+"; the join token was not checked")
		refuse(w, err)
		return
	}
	// The Controller replaces the actor with the User of the token once it knows it
	ctx := audit.NewContext(r.Context(), audit.Origin{Actor: audit.ActorUnknown, Source: sourceOf(r)})
	e, err := j.JoinDevice(ctx, req.Token, req.Device.Name, req.Device.Key)
	switch {
	case err == nil:
		s.record(r, audit.Enrolment, e.User, audit.Success, fmt.Sprintf("Node %q enrolled with a join token for the device with the static key %s, revision %d",
			e.Node, keyText(req.Device.Key), e.Revision))
		reply(w, http.StatusOK, Result{User: e.User, Node: e.Node, Revision: e.Revision, Controller: s.keys()})
	case errors.Is(err, controller.ErrBadJoinToken):
		s.fails.fail(now, key)
		s.record(r, audit.AuthFailed, "", audit.Failure, err.Error())
		refuse(w, err)
	default:
		if code := statusOf(err); code != http.StatusInternalServerError && code != http.StatusServiceUnavailable {
			// A device that the intent or the User refuses: the failure of the token's User
			s.record(r, audit.Enrolment, e.User, audit.Failure, "the device was not enrolled with the join token: "+err.Error())
		}
		refuse(w, err)
	}
}

// joinKey returns the key of the throttle of the join tokens that the source of r presented and that no
// join token is.
func joinKey(r *http.Request) string {
	return "join " + sourceKey(sourceOf(r))
}

// SignInSelf makes a password login of the User user for the portal and returns its token of the self scope.
func (c *Client) SignInSelf(ctx context.Context, user, password string) (SignedIn, error) {
	b, err := json.Marshal(SignInRequest{User: user, Password: password, Scope: ScopeSelf})
	if err != nil {
		return SignedIn{}, err
	}
	var in SignedIn
	err = c.call(ctx, Root, "application/json", bytes.NewReader(b), "", &in)
	return in, err
}

// Join presents the join token with the secret secret for the device d, which a User made in the portal,
// and returns the enrolment of the device with the keys of the controller that its Node pins.
func (c *Client) Join(ctx context.Context, secret string, d Device) (Result, error) {
	f := url.Values{"token": {secret}, "node_key": {keyText(d.Key)}}
	if d.Name != "" {
		f.Set("node_name", d.Name)
	}
	var res Result
	err := c.post(ctx, JoinPath, f, &res)
	return res, err
}
