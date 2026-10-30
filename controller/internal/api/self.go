package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The self calls of the portal (SDN-58 #251, ADR-0031 amendment of 2026-10-29), beside the calls of Handler.
// A User signs in to the web UI of the portal with a login for the scope self (internal/login), and its token
// may make these calls and no other. They are about the User that holds the token and about nothing else: its
// devices, the resources that name it as their owner, and its join tokens. A device of another User, or of
// none, is not found, whatever its name. Every call needs the role Self (Needs), which every token of a User
// has, whatever its API role; an API token names no User and is refused (selfUser).
//
//	GET    /api/v1/self                          controller.SelfInfo: the User, and how many devices it has
//	GET    /api/v1/self/devices                  SelfDeviceList: its devices, each with how it stands
//	POST   /api/v1/self/devices                  a SelfDeviceRequest: the static key of the device and the
//	                                             name it takes; a controller.Enrolment
//	DELETE /api/v1/self/devices/{kind}/{name}    a controller.ApplyResult; kind is Node or Device
//	GET    /api/v1/self/join-tokens              JoinTokenList: the join tokens that wait, without secrets
//	POST   /api/v1/self/join-tokens              a JoinTokenRequest; a controller.NewJoinToken, whose secret
//	                                             shows once
//	DELETE /api/v1/self/join-tokens/{id}         the controller.JoinTokenInfo revoked
//
// Adding and removing a device are revisions of the intent under the actor user:NAME, as the enrolment of a
// login is, so the maximum devices of the User holds for them as it holds for `ranz apply` (400 Bad Request).
// A body that is not what a call takes, and a static key that is none, are 400. A User that expired or that
// an operator banned has no token, and is refused with 403 Forbidden when its token reaches a call anyway.

// selfPath is the root of the self calls, which Needs gives the role Self.
const selfPath = "/api/v1/self"

// maxSelfBody bounds the body of a self call: a static key, a name and the JSON around them.
const maxSelfBody = 4 << 10

// SelfDeviceList is the answer of GET /api/v1/self/devices.
type SelfDeviceList struct {
	Devices []controller.SelfDevice `json:"devices"`
}

// SelfDeviceRequest is the body of POST /api/v1/self/devices: the public half of the static key of the
// device, in base64, as ranz node key shows it, and the name that the Node of the device takes, which the
// controller draws when it is left out.
type SelfDeviceRequest struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name,omitempty"`
}

// JoinTokenRequest is the body of POST /api/v1/self/join-tokens: the name that the Node of the device takes
// when it joins with the token, which the controller draws when it is left out.
type JoinTokenRequest struct {
	Name string `json:"name,omitempty"`
}

// JoinTokenList is the answer of GET /api/v1/self/join-tokens.
type JoinTokenList struct {
	Tokens []controller.JoinTokenInfo `json:"tokens"`
}

func init() {
	register(
		route{http.MethodGet, selfPath, rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			info, err := d.Controller.SelfInfo(user)
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
		route{http.MethodGet, selfPath + "/devices", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			devices, err := d.Controller.SelfDevices(user)
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, SelfDeviceList{Devices: devices})
		}},
		route{http.MethodPost, selfPath + "/devices", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			var req SelfDeviceRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSelfBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a device, {"publicKey": "...", "name": "..."}: ` + err.Error()})
				return
			}
			key, err := intent.ParseKey(req.PublicKey)
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
				return
			}
			e, err := d.Controller.AddSelfDevice(r.Context(), user, req.Name, key)
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, e)
		}},
		route{http.MethodDelete, selfPath + "/devices/{kind}/{name}", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			res, err := d.Controller.RemoveSelfDevice(r.Context(), user, r.PathValue("kind"), r.PathValue("name"))
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodGet, selfPath + "/join-tokens", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			tokens, err := d.Controller.JoinTokens(r.Context(), user)
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, JoinTokenList{Tokens: tokens})
		}},
		route{http.MethodPost, selfPath + "/join-tokens", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			var req JoinTokenRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSelfBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a join token request, {"name": "..."}: ` + err.Error()})
				return
			}
			tok, err := d.Controller.MakeJoinToken(r.Context(), user, req.Name)
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, tok)
		}},
		route{http.MethodDelete, selfPath + "/join-tokens/{id}", rbac.Self, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			user, ok := selfUser(w, r)
			if !ok {
				return
			}
			tok, err := d.Controller.RevokeJoinToken(r.Context(), user, r.PathValue("id"))
			if err != nil {
				replySelf(w, err)
				return
			}
			reply(w, http.StatusOK, tok)
		}},
	)
}

// selfUser returns the User that holds the token of the call r, for a self call. The Guard lets every token
// of a role through to the calls that ask for Self, and an API token names no User, so a call with one gets
// 403 Forbidden here and the handler stops: it reports false.
func selfUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, _ := Caller(r.Context())
	if tok.User == "" {
		w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
		reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("a self call is made for the User of a token of a login, and the token %q is an API token, which names no User: "+
			"a User signs in with POST /api/v1/login", tok.Name)})
		return "", false
	}
	return tok.User, true
}

// replySelf answers an error of a self call: 403 Forbidden for a User that expired or that an operator banned,
// and what replyError makes of any other.
func replySelf(w http.ResponseWriter, err error) {
	if errors.Is(err, controller.ErrUserExpired) || errors.Is(err, controller.ErrUserBanned) {
		reply(w, http.StatusForbidden, Problem{Error: err.Error()})
		return
	}
	replyError(w, err)
}

// Self returns the User of the token of the client, as the portal shows it to the User.
func (c *Client) Self(ctx context.Context) (controller.SelfInfo, error) {
	var info controller.SelfInfo
	err := c.do(ctx, http.MethodGet, selfPath, nil, &info)
	return info, err
}

// SelfDevices returns the devices of the User of the token of the client, each with how it stands.
func (c *Client) SelfDevices(ctx context.Context) ([]controller.SelfDevice, error) {
	var l SelfDeviceList
	err := c.do(ctx, http.MethodGet, selfPath+"/devices", nil, &l)
	return l.Devices, err
}

// AddSelfDevice makes the Node of the device whose static key is publicKey, the base64 that ranz node key
// prints, a device of the User of the token of the client, named name or, when name is empty, by the
// controller.
func (c *Client) AddSelfDevice(ctx context.Context, name, publicKey string) (controller.Enrolment, error) {
	var e controller.Enrolment
	err := c.do(ctx, http.MethodPost, selfPath+"/devices", SelfDeviceRequest{PublicKey: publicKey, Name: name}, &e)
	return e, err
}

// RemoveSelfDevice deletes the device of the User of the token of the client that has the kind kind, Node or
// Device, and the name name.
func (c *Client) RemoveSelfDevice(ctx context.Context, kind, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, selfPath+"/devices/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &res)
	return res, err
}

// JoinTokens returns the join tokens of the User of the token of the client that wait for a device, without
// their secrets.
func (c *Client) JoinTokens(ctx context.Context) ([]controller.JoinTokenInfo, error) {
	var l JoinTokenList
	err := c.do(ctx, http.MethodGet, selfPath+"/join-tokens", nil, &l)
	return l.Tokens, err
}

// MakeJoinToken makes a join token for a device of the User of the token of the client, which takes the name
// name when it joins, or a name that the controller draws when name is empty. The secret of the answer shows
// this once.
func (c *Client) MakeJoinToken(ctx context.Context, name string) (controller.NewJoinToken, error) {
	var tok controller.NewJoinToken
	err := c.do(ctx, http.MethodPost, selfPath+"/join-tokens", JoinTokenRequest{Name: name}, &tok)
	return tok, err
}

// RevokeJoinToken deletes the join token of the User of the token of the client that has the id id.
func (c *Client) RevokeJoinToken(ctx context.Context, id string) (controller.JoinTokenInfo, error) {
	var tok controller.JoinTokenInfo
	err := c.do(ctx, http.MethodDelete, selfPath+"/join-tokens/"+url.PathEscape(id), nil, &tok)
	return tok, err
}
