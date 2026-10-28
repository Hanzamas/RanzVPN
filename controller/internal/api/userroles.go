package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The API roles of users (SDN-32 #226, ADR-0031 amendment of 2026-10-28), beside the calls of
// Handler. A User that holds a role logs in to the API (internal/login), and the user tokens of its
// logins carry the role that it holds when they are used. Which User holds which role says who may
// manage the controller, as the API tokens do, so the calls are under /api/v1/tokens and need admin
// (Needs):
//
//	GET    /api/v1/tokens/users          UserRoleList: each User that holds a role, with the role       admin
//	PUT    /api/v1/tokens/users/{name}   a UserRoleRequest, which gives the User the role in place of
//	                                     the one it held; the rbac.UserRole                              admin
//	DELETE /api/v1/tokens/users/{name}   the rbac.UserRole that the User held; its user tokens end      admin
//
// A User that the intent does not hold gets no role (404). Setting the password of a User that holds a
// role needs admin too, since whoever knows the password may manage the controller with the role
// (adminForPassword, which the password call of users.go asks).

// userRolesPath is the root of the API roles of users.
const userRolesPath = tokensPath + "/users"

// UserRoleList is the answer of GET /api/v1/tokens/users.
type UserRoleList struct {
	Roles []rbac.UserRole `json:"roles"`
}

// UserRoleRequest is the body of PUT /api/v1/tokens/users/{name}.
type UserRoleRequest struct {
	Role rbac.Role `json:"role"`
}

func init() {
	register(
		route{http.MethodGet, userRolesPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			rs, err := d.Tokens.UserRoles(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, UserRoleList{Roles: rs})
		}},
		route{http.MethodPut, userRolesPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req UserRoleRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasswordBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not an API role, {"role": "viewer|operator|admin"}: ` + err.Error()})
				return
			}
			name := r.PathValue("name")
			if !d.Controller.HoldsUser(name) {
				replyError(w, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, name))
				return
			}
			ur, err := d.Tokens.SetUserRole(r.Context(), name, req.Role)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, ur)
		}},
		route{http.MethodDelete, userRolesPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ur, err := d.Tokens.DeleteUserRole(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, ur)
		}},
	)
}

// adminForPassword answers 403 Forbidden and reports true when the User name holds an API role and the
// caller is no admin: the password of such a User is a way to the role, so only an admin sets it (the
// ADR-0031 amendment of 2026-10-25 asked for it once a User could hold a role). It reports false, and
// answers nothing, for a User that holds none, whose password an operator sets as before.
func adminForPassword(d routeDeps, w http.ResponseWriter, r *http.Request, name string) bool {
	role, ok, err := d.Tokens.UserRole(r.Context(), name)
	if err != nil {
		replyError(w, err)
		return true
	}
	if !ok {
		return false
	}
	if tok, _ := Caller(r.Context()); tok.Role.Allows(rbac.Admin) {
		return false
	}
	w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
	reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the user %q holds the API role %s, so setting its password needs the role %s", name, role, rbac.Admin)})
	return true
}

// UserRoles returns the API role of every User that holds one.
func (c *Client) UserRoles(ctx context.Context) ([]rbac.UserRole, error) {
	var l UserRoleList
	err := c.do(ctx, http.MethodGet, userRolesPath, nil, &l)
	return l.Roles, err
}

// SetUserRole gives the User name the API role role and returns it.
func (c *Client) SetUserRole(ctx context.Context, name string, role rbac.Role) (rbac.UserRole, error) {
	var ur rbac.UserRole
	err := c.do(ctx, http.MethodPut, userRolesPath+"/"+url.PathEscape(name), UserRoleRequest{Role: role}, &ur)
	return ur, err
}

// DeleteUserRole takes the API role of the User name away and returns the role that it held.
func (c *Client) DeleteUserRole(ctx context.Context, name string) (rbac.UserRole, error) {
	var ur rbac.UserRole
	err := c.do(ctx, http.MethodDelete, userRolesPath+"/"+url.PathEscape(name), nil, &ur)
	return ur, err
}
