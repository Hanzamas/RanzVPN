package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/password"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The users and the groups (SDN-31 #225, ADR-0031 amendment of 2026-10-25), beside the calls of
// Handler. They are resources of the intent like the others, so a change makes a revision, and the
// same change can be made with an apply; these calls give each of them a name and a place of its own,
// and the password of a user, which the intent never holds, its call:
//
//	GET    /api/v1/users                  UserList: each user, its devices and whether it has a password   viewer
//	PUT    /api/v1/users/{name}           an intent.User, which makes the user or replaces it;
//	                                      a controller.ApplyResult                                          operator
//	DELETE /api/v1/users/{name}           a controller.ApplyResult; the password goes with the user         operator
//	PUT    /api/v1/users/{name}/password  a PasswordRequest; a PasswordResult                               operator
//	GET    /api/v1/groups                 GroupList: each group and its members                             viewer
//	PUT    /api/v1/groups/{name}          an intent.Group; a controller.ApplyResult                         operator
//	DELETE /api/v1/groups/{name}          a controller.ApplyResult                                          operator
//
// A user that names a group that does not exist, a group that a user belongs to or a user that owns
// a Node cannot be deleted, and a user with more devices than its maximum is refused with 400 Bad
// Request, as an apply refuses them. A password that is too short or too long is 400 too. Setting a
// password needs the role operator, as making the user does, and never depends on whether the user may
// change its own password.

// maxPasswordBody bounds the body of a password: the longest password and the JSON around it fit.
const maxPasswordBody = 4 << 10

// UserList is the answer of GET /api/v1/users.
type UserList struct {
	Users []controller.UserInfo `json:"users"`
}

// GroupList is the answer of GET /api/v1/groups.
type GroupList struct {
	Groups []controller.GroupInfo `json:"groups"`
}

// PasswordRequest is the body of PUT /api/v1/users/{name}/password.
type PasswordRequest struct {
	Password string `json:"password"`
}

// PasswordResult is the answer of PUT /api/v1/users/{name}/password: the user, and that it has a
// password now. The password and its hash are never sent back.
type PasswordResult struct {
	User string `json:"user"`
	Set  bool   `json:"passwordSet"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/users", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			users, err := d.Controller.Users(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, UserList{Users: users})
		}},
		route{http.MethodPut, "/api/v1/users/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var u intent.User
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&u); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a user: " + err.Error()})
				return
			}
			applyOne(d, w, r, intent.KindUser, r.PathValue("name"), u)
		}},
		route{http.MethodDelete, "/api/v1/users/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			deleteOne(d, w, r, intent.KindUser, r.PathValue("name"))
		}},
		route{http.MethodPut, "/api/v1/users/{name}/password", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req PasswordRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasswordBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a password, {"password": "..."}: ` + err.Error()})
				return
			}
			name := r.PathValue("name")
			if err := d.Controller.SetUserPassword(r.Context(), name, req.Password); err != nil {
				if errors.Is(err, password.ErrInvalid) {
					reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
					return
				}
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, PasswordResult{User: name, Set: true})
		}},
		route{http.MethodGet, "/api/v1/groups", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, GroupList{Groups: d.Controller.Groups()})
		}},
		route{http.MethodPut, "/api/v1/groups/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var g intent.Group
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&g); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a group: " + err.Error()})
				return
			}
			applyOne(d, w, r, intent.KindGroup, r.PathValue("name"), g)
		}},
		route{http.MethodDelete, "/api/v1/groups/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			deleteOne(d, w, r, intent.KindGroup, r.PathValue("name"))
		}},
	)
}

// applyOne applies the one resource kind/name with the spec spec as an apply of the intent does, and
// answers with the result of the apply.
func applyOne(d routeDeps, w http.ResponseWriter, r *http.Request, kind, name string, spec any) {
	b, err := json.Marshal(spec)
	if err != nil {
		replyError(w, err)
		return
	}
	res, err := d.Controller.Apply(r.Context(), intent.Document{Resources: []intent.Resource{{Kind: kind, Name: name, Spec: b}}})
	if err != nil {
		replyError(w, err)
		return
	}
	reply(w, http.StatusOK, res)
}

// deleteOne deletes the resource kind/name as a delete of the intent does, and answers with the
// result of the delete.
func deleteOne(d routeDeps, w http.ResponseWriter, r *http.Request, kind, name string) {
	res, err := d.Controller.Delete(r.Context(), kind, name)
	if err != nil {
		replyError(w, err)
		return
	}
	reply(w, http.StatusOK, res)
}

// Users returns the users of the intent with their devices and whether each has a password.
func (c *Client) Users(ctx context.Context) ([]controller.UserInfo, error) {
	var l UserList
	err := c.do(ctx, http.MethodGet, "/api/v1/users", nil, &l)
	return l.Users, err
}

// PutUser makes the user name with the spec u, or replaces it.
func (c *Client) PutUser(ctx context.Context, name string, u intent.User) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPut, "/api/v1/users/"+url.PathEscape(name), u, &res)
	return res, err
}

// DeleteUser deletes the user name and its password.
func (c *Client) DeleteUser(ctx context.Context, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, "/api/v1/users/"+url.PathEscape(name), nil, &res)
	return res, err
}

// SetUserPassword sets the password of the user name, which the controller keeps as a hash.
func (c *Client) SetUserPassword(ctx context.Context, name, secret string) (PasswordResult, error) {
	var res PasswordResult
	err := c.do(ctx, http.MethodPut, "/api/v1/users/"+url.PathEscape(name)+"/password", PasswordRequest{Password: secret}, &res)
	return res, err
}

// Groups returns the groups of the intent with their members.
func (c *Client) Groups(ctx context.Context) ([]controller.GroupInfo, error) {
	var l GroupList
	err := c.do(ctx, http.MethodGet, "/api/v1/groups", nil, &l)
	return l.Groups, err
}

// PutGroup makes the group name with the spec g, or replaces it.
func (c *Client) PutGroup(ctx context.Context, name string, g intent.Group) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPut, "/api/v1/groups/"+url.PathEscape(name), g, &res)
	return res, err
}

// DeleteGroup deletes the group name.
func (c *Client) DeleteGroup(ctx context.Context, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, "/api/v1/groups/"+url.PathEscape(name), nil, &res)
	return res, err
}
