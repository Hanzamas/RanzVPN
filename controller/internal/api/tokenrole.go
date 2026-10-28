package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The role of an API token changes in place (SDN-32 #226, the decision of 2026-10-22 that ties it to the
// logins of users), beside the calls of the tokens in tokens.go:
//
//	PATCH /api/v1/tokens/{name}   a TokenPatch; the rbac.Token with its new role   admin
//
// The secret of the token stays, so whoever holds it keeps it and calls with the new role from the next
// call on. The last admin token cannot lose the role admin (409), as it cannot be deleted.

// TokenPatch is the body of PATCH /api/v1/tokens/{name}: the role that the token gets.
type TokenPatch struct {
	Role rbac.Role `json:"role"`
}

func init() {
	register(route{http.MethodPatch, tokensPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		var req TokenPatch
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasswordBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: `the body is not the role of a token, {"role": "viewer|operator|admin"}: ` + err.Error()})
			return
		}
		tok, err := d.Tokens.SetRole(r.Context(), r.PathValue("name"), req.Role)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, tok)
	}})
}

// SetTokenRole gives the API token name the role role in place and returns it.
func (c *Client) SetTokenRole(ctx context.Context, name string, role rbac.Role) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodPatch, tokensPath+"/"+url.PathEscape(name), TokenPatch{Role: role}, &t)
	return t, err
}
