package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TokenList is the answer of GET /api/v1/tokens: each token with its role, its expiry and whether
// it has expired, and when it was last used.
type TokenList struct {
	Tokens []rbac.Token `json:"tokens"`
}

// TokenRequest is the body of POST /api/v1/tokens.
type TokenRequest struct {
	Name string    `json:"name"`
	Role rbac.Role `json:"role"`
	// Network is the Network that the role of the token is held for (SDN-38, scoped.go): the token calls the
	// calls of that Network and no other, and the Network must exist. Left out, the role is held for the whole
	// API.
	Network string `json:"network,omitempty"`
	// Expires is the instant, an RFC 3339 time in the future, from which the controller refuses
	// the token. Left out, the token never expires.
	Expires time.Time `json:"expires,omitzero"`
}

func init() {
	register(
		route{http.MethodGet, tokensPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ts, err := d.Tokens.List(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, TokenList{Tokens: ts})
		}},
		route{http.MethodPost, tokensPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req TokenRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a token request: " + err.Error()})
				return
			}
			if !holdsNetworkOrNone(d, w, req.Network) {
				return
			}
			tok, err := d.Tokens.CreateGrant(r.Context(), req.Name, rbac.Grant{Role: req.Role, Network: req.Network}, req.Expires)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, tok)
		}},
		route{http.MethodDelete, tokensPath + "/{name}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tok, err := d.Tokens.Delete(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, tok)
		}},
	)
}

// Tokens returns every API token, without the secrets.
func (c *Client) Tokens(ctx context.Context) ([]rbac.Token, error) {
	var l TokenList
	err := c.do(ctx, http.MethodGet, tokensPath, nil, &l)
	return l.Tokens, err
}

// CreateToken creates the API token name with role, which never expires, and returns it with its
// secret.
func (c *Client) CreateToken(ctx context.Context, name string, role rbac.Role) (rbac.NewToken, error) {
	return c.CreateTokenRequest(ctx, TokenRequest{Name: name, Role: role})
}

// CreateTokenRequest creates the API token that req asks for, with its expiry when it has one, and
// returns it with its secret.
func (c *Client) CreateTokenRequest(ctx context.Context, req TokenRequest) (rbac.NewToken, error) {
	var t rbac.NewToken
	err := c.do(ctx, http.MethodPost, tokensPath, req, &t)
	return t, err
}

// DeleteToken deletes the API token name and returns it.
func (c *Client) DeleteToken(ctx context.Context, name string) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodDelete, tokensPath+"/"+url.PathEscape(name), nil, &t)
	return t, err
}
