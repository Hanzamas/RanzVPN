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

// TokenPatch is the body of PATCH /api/v1/tokens/{name}: the role that the token gets. A token that is held for
// one Network (SDN-38, scoped.go) stays so, unless Network says otherwise: the Network that it is held for from
// now on, which must exist, or the empty string for the whole API, which is the one way to widen a scoped token.
type TokenPatch struct {
	Role    rbac.Role `json:"role"`
	Network *string   `json:"network,omitempty"`
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
		var tok rbac.Token
		var err error
		if req.Network == nil {
			// The scope of the token stays (rbac.Tokens.SetRole)
			tok, err = d.Tokens.SetRole(r.Context(), r.PathValue("name"), req.Role)
		} else {
			if !holdsNetworkOrNone(d, w, *req.Network) {
				return
			}
			tok, err = d.Tokens.SetGrant(r.Context(), r.PathValue("name"), rbac.Grant{Role: req.Role, Network: *req.Network})
		}
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, tok)
	}})
}

// SetTokenRole gives the API token name the role role in place and returns it. A token that is held for one
// Network stays so.
func (c *Client) SetTokenRole(ctx context.Context, name string, role rbac.Role) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodPatch, tokensPath+"/"+url.PathEscape(name), TokenPatch{Role: role}, &t)
	return t, err
}

// SetTokenGrant gives the API token name the role of g, held for the Network of g or, when it names none, for
// the whole API, in place, and returns it.
func (c *Client) SetTokenGrant(ctx context.Context, name string, g rbac.Grant) (rbac.Token, error) {
	var t rbac.Token
	network := g.Network
	err := c.do(ctx, http.MethodPatch, tokensPath+"/"+url.PathEscape(name), TokenPatch{Role: g.Role, Network: &network}, &t)
	return t, err
}
