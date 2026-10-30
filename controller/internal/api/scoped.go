package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/password"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/scope"
)

// The roles held for one Network (SDN-38 #231, ADR-0031 amendment of 2026-10-29), beside the calls of Handler.
// A token, or a User through the tokens of its logins, holds one of the three roles for the whole API or for one
// Network (rbac.Grant). The Guard lets a role that is held for a Network call whoami and the calls under that
// Network's path, and refuses it everything else (scopeRefusal), so a scope only narrows a role and a call that
// a later ticket adds is out of its reach until it is put under a Network. The calls of a Network are for the
// roles that are held for it:
//
//	GET    /api/v1/networks/{network}                                 a controller.ScopeInfo: the Network, its delegation
//	                                                                  and what it holds                                    viewer
//	GET    /api/v1/networks/{network}/resources                       a ResourceList: the Network, and the Nodes, Policies,
//	                                                                  Groups and Users in its scope                        viewer
//	POST   /api/v1/networks/{network}/apply                           an intent.Document; a controller.ApplyResult         operator
//	DELETE /api/v1/networks/{network}/resources/{kind}/{name}         a controller.ApplyResult                             operator
//	PUT    /api/v1/networks/{network}/users/{name}/password           a PasswordRequest; a PasswordResult                  operator
//	GET    /api/v1/networks/{network}/sessions                        a SessionList: the sessions of its Nodes             operator
//	POST   /api/v1/networks/{network}/sessions/{id}/disconnect        a SessionList: the session that it ended             operator
//
// The role of a call is the one that Needs gives it (a read is viewer, any other call operator), and the list of
// the sessions needs operator all the same, as every call that shows who is connected does (SDN-50). A role of
// the whole API is refused these calls (403): it changes the intent with /api/v1/apply. What the calls may do is
// the delegation of the Network (internal/scope), which an admin sets:
//
//	GET    /api/v1/tokens/delegations              a DelegationList: the delegation of every Network that has one, with
//	                                               its usage                                                           admin
//	PUT    /api/v1/tokens/delegations/{network}    a DelegationRequest; the controller.DelegationInfo                  admin
//	DELETE /api/v1/tokens/delegations/{network}    the controller.DelegationInfo that it removed                       admin
//
// and the provider groups, the groups of an identity provider that are mapped to a role (rbac.GroupMapping):
//
//	GET    /api/v1/tokens/provider-groups                         a GroupMappingList                                   admin
//	PUT    /api/v1/tokens/provider-groups/{provider}              a GroupMappingRequest; the rbac.GroupMapping         admin
//	DELETE /api/v1/tokens/provider-groups/{provider}?group=NAME   the rbac.GroupMapping that it removed                admin
//
// All of them are under /api/v1/tokens, since who holds which role, and what it may do, is what the tokens say
// too (Needs).

const (
	// networksPath is the root of the calls of a Network.
	networksPath = "/api/v1/networks"
	// whoamiPath is the one call outside a Network's path that a role held for it makes.
	whoamiPath = "/api/v1/whoami"
	// delegationsPath is the root of the delegations of the Networks, which only an admin reads or changes.
	delegationsPath = tokensPath + "/delegations"
	// providerGroupsPath is the root of the provider groups, which only an admin reads or changes.
	providerGroupsPath = tokensPath + "/provider-groups"
	// maxScopeBody bounds the body of a delegation and of a provider group.
	maxScopeBody = 64 << 10
)

// DelegationList is the answer of GET /api/v1/tokens/delegations.
type DelegationList struct {
	Delegations []controller.DelegationInfo `json:"delegations"`
}

// DelegationRequest is the body of PUT /api/v1/tokens/delegations/{network}: the quotas and the permissions of
// the Network of the path.
type DelegationRequest struct {
	Quotas      scope.Quotas `json:"quotas"`
	Permissions []string     `json:"permissions"`
}

// GroupMappingList is the answer of GET /api/v1/tokens/provider-groups.
type GroupMappingList struct {
	Mappings []rbac.GroupMapping `json:"mappings"`
}

// GroupMappingRequest is the body of PUT /api/v1/tokens/provider-groups/{provider}: the group of the provider,
// and the role that its members get, held for the Network, which must exist, or for the whole API when none is
// named.
type GroupMappingRequest struct {
	Group   string    `json:"group"`
	Role    rbac.Role `json:"role"`
	Network string    `json:"network,omitempty"`
}

// scopeRefusal returns why the Guard refuses the request r to the token tok, or the empty string when it passes:
// a token whose role is held for one Network calls whoami and the calls under the path of that Network, and no
// other. The path is the one that Needs reads, with its dots and slashes resolved, so that a path that climbs
// out of the Network's own is the path that it climbs to. A token of the whole API passes here.
func scopeRefusal(tok rbac.Token, r *http.Request) string {
	if tok.Network == "" {
		return ""
	}
	p := path.Clean("/" + r.URL.Path)
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && p == whoamiPath {
		return ""
	}
	mine := networksPath + "/" + tok.Network
	if p == mine || strings.HasPrefix(p, mine+"/") {
		return ""
	}
	return fmt.Sprintf("the token %q holds the role %s for Network %q only: it calls %s and the calls under %s, and not %s %s", tok.Name, tok.Role, tok.Network, whoamiPath, mine, r.Method, p)
}

// scopedCaller returns the role of the caller of a call about the Network of the path, which the caller holds for
// that Network. It answers 403 Forbidden, and reports false, to a role of the whole API, which has the calls of
// the intent, and to one that is held for another Network: the Guard let the call through for its path, which
// can hold the name of another Network in a form that it did not read, and a handler never trusts that.
func scopedCaller(w http.ResponseWriter, r *http.Request) (controller.ScopedRole, bool) {
	tok, _ := Caller(r.Context())
	network := r.PathValue("network")
	switch {
	case tok.Network == "":
		w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
		reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the calls of a Network are for the roles that are held for it: the token %q holds its role for the whole API, which changes the intent with %s", tok.Name, "/api/v1/apply")})
		return controller.ScopedRole{}, false
	case tok.Network != network:
		w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
		reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the token %q holds its role for Network %q, not %q", tok.Name, tok.Network, network)})
		return controller.ScopedRole{}, false
	}
	return controller.ScopedRole{Network: network, Admin: tok.Role.Allows(rbac.Admin)}, true
}

// holdsNetworkOrNone answers 400 Bad Request, and reports false, when network is no Network name, and 404 Not Found
// when it names a Network that the intent does not hold. The empty name, the whole API, is none.
func holdsNetworkOrNone(d routeDeps, w http.ResponseWriter, network string) bool {
	if network == "" {
		return true
	}
	if _, err := rbac.NewGrant(rbac.Viewer, network); err != nil {
		replyError(w, err)
		return false
	}
	if d.Controller.HoldsNetwork(network) {
		return true
	}
	replyError(w, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, network))
	return false
}

// replyScoped answers an error of a call of a Network: 403 Forbidden for a change that the role may not make,
// with the reasons, and for one that takes the Network over a quota, 400 for a delegation that cannot be set, and
// what replyError makes of any other.
func replyScoped(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scope.ErrOutOfScope), errors.Is(err, scope.ErrQuota):
		reply(w, http.StatusForbidden, Problem{Error: err.Error()})
	case errors.Is(err, scope.ErrInvalid):
		reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
	default:
		replyError(w, err)
	}
}

// needOperator answers 403 Forbidden, and reports false, to a role that is no operator: the calls that show
// who is connected are an operator's, whichever Network they are about.
func needOperator(w http.ResponseWriter, r *http.Request) bool {
	tok, _ := Caller(r.Context())
	if tok.Role.Allows(rbac.Operator) {
		return true
	}
	w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
	reply(w, http.StatusForbidden, Problem{Error: fmt.Sprintf("the call needs the role %s or one above it, and the token %q has the role %s", rbac.Operator, tok.Name, tok.Role)})
	return false
}

func init() {
	// Who holds which role, and what it may do, is read as the tokens are (accessaudit.go)
	auditedReads = append(auditedReads, delegationsPath, providerGroupsPath)

	register(
		route{http.MethodGet, networksPath + "/{network}", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			info, err := d.Controller.ScopeInfo(role.Network)
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
		route{http.MethodGet, networksPath + "/{network}/resources", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			rs, err := d.Controller.ScopeResources(role.Network)
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, ResourceList{Resources: rs})
		}},
		route{http.MethodPost, networksPath + "/{network}/apply", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			var doc intent.Document
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&doc); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not an intent document: " + err.Error()})
				return
			}
			res, err := d.Controller.ApplyScoped(r.Context(), role, doc)
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodDelete, networksPath + "/{network}/resources/{kind}/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			res, err := d.Controller.DeleteScoped(r.Context(), role, r.PathValue("kind"), r.PathValue("name"))
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodPut, networksPath + "/{network}/users/{name}/password", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			var req PasswordRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasswordBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a password, {"password": "..."}: ` + err.Error()})
				return
			}
			name := r.PathValue("name")
			if err := d.Controller.SetScopedPassword(r.Context(), role, name, req.Password); err != nil {
				if errors.Is(err, password.ErrInvalid) {
					reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
					return
				}
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, PasswordResult{User: name, Set: true})
		}},
		route{http.MethodGet, networksPath + "/{network}/sessions", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok || !needOperator(w, r) {
				return
			}
			sessions, err := d.Controller.ScopedSessions(r.Context(), role)
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, SessionList{Sessions: sessions})
		}},
		route{http.MethodPost, networksPath + "/{network}/sessions/{id}/disconnect", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			role, ok := scopedCaller(w, r)
			if !ok {
				return
			}
			s, err := d.Controller.ScopedDisconnect(r.Context(), role, r.PathValue("id"))
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, SessionList{Sessions: []controller.Session{s}})
		}},

		route{http.MethodGet, delegationsPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, DelegationList{Delegations: d.Controller.Delegations(r.Context())})
		}},
		route{http.MethodPut, delegationsPath + "/{network}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req DelegationRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxScopeBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a delegation, {"quotas": {...}, "permissions": [...]}: ` + err.Error()})
				return
			}
			info, err := d.Controller.SetDelegation(r.Context(), scope.Delegation{Network: r.PathValue("network"), Quotas: req.Quotas, Permissions: req.Permissions})
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
		route{http.MethodDelete, delegationsPath + "/{network}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			info, err := d.Controller.DeleteDelegation(r.Context(), r.PathValue("network"))
			if err != nil {
				replyScoped(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},

		route{http.MethodGet, providerGroupsPath, rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ms, err := d.Tokens.GroupMappings(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, GroupMappingList{Mappings: ms})
		}},
		route{http.MethodPut, providerGroupsPath + "/{provider}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req GroupMappingRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxScopeBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a provider group, {"group": "...", "role": "viewer|operator|admin", "network": "..."}: ` + err.Error()})
				return
			}
			if !holdsNetworkOrNone(d, w, req.Network) {
				return
			}
			m, err := d.Tokens.SetGroupMapping(r.Context(), rbac.GroupMapping{Provider: r.PathValue("provider"), Group: req.Group, Role: req.Role, Network: req.Network})
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, m)
		}},
		route{http.MethodDelete, providerGroupsPath + "/{provider}", rbac.Admin, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			if !queryOnly(w, r, "group") {
				return
			}
			group := r.URL.Query().Get("group")
			if group == "" {
				reply(w, http.StatusBadRequest, Problem{Error: "the call needs the group to unmap, as the query ?group=NAME"})
				return
			}
			m, err := d.Tokens.DeleteGroupMapping(r.Context(), r.PathValue("provider"), group)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, m)
		}},
	)
}

// NetworkInfo returns the Network network as a role that is held for it sees it: the Network, its delegation and
// what it holds.
func (c *Client) NetworkInfo(ctx context.Context, network string) (controller.ScopeInfo, error) {
	var info controller.ScopeInfo
	err := c.do(ctx, http.MethodGet, networksPath+"/"+url.PathEscape(network), nil, &info)
	return info, err
}

// NetworkResources returns the resources in the scope of the Network network.
func (c *Client) NetworkResources(ctx context.Context, network string) ([]intent.Resource, error) {
	var l ResourceList
	err := c.do(ctx, http.MethodGet, networksPath+"/"+url.PathEscape(network)+"/resources", nil, &l)
	return l.Resources, err
}

// NetworkApply applies doc in the Network network, as a role that is held for it.
func (c *Client) NetworkApply(ctx context.Context, network string, doc intent.Document) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, networksPath+"/"+url.PathEscape(network)+"/apply", doc, &res)
	return res, err
}

// NetworkDelete deletes the resource kind/name in the Network network, as a role that is held for it.
func (c *Client) NetworkDelete(ctx context.Context, network, kind, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, networksPath+"/"+url.PathEscape(network)+"/resources/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &res)
	return res, err
}

// NetworkPassword sets the password of the User user in the Network network, as a role that is held for it.
func (c *Client) NetworkPassword(ctx context.Context, network, user, secret string) (PasswordResult, error) {
	var res PasswordResult
	err := c.do(ctx, http.MethodPut, networksPath+"/"+url.PathEscape(network)+"/users/"+url.PathEscape(user)+"/password", PasswordRequest{Password: secret}, &res)
	return res, err
}

// NetworkSessions returns the sessions of the Nodes in the scope of the Network network.
func (c *Client) NetworkSessions(ctx context.Context, network string) ([]controller.Session, error) {
	var l SessionList
	err := c.do(ctx, http.MethodGet, networksPath+"/"+url.PathEscape(network)+"/sessions", nil, &l)
	return l.Sessions, err
}

// NetworkDisconnect ends the session id of a Node in the scope of the Network network and returns it.
func (c *Client) NetworkDisconnect(ctx context.Context, network, id string) (controller.Session, error) {
	var l SessionList
	if err := c.do(ctx, http.MethodPost, networksPath+"/"+url.PathEscape(network)+"/sessions/"+url.PathEscape(id)+"/disconnect", nil, &l); err != nil {
		return controller.Session{}, err
	}
	if len(l.Sessions) != 1 {
		return controller.Session{}, fmt.Errorf("the controller ended %d sessions, not the one that was named", len(l.Sessions))
	}
	return l.Sessions[0], nil
}

// Delegations returns the delegation of every Network that has one, with its usage.
func (c *Client) Delegations(ctx context.Context) ([]controller.DelegationInfo, error) {
	var l DelegationList
	err := c.do(ctx, http.MethodGet, delegationsPath, nil, &l)
	return l.Delegations, err
}

// SetDelegation sets the delegation of the Network network and returns it.
func (c *Client) SetDelegation(ctx context.Context, network string, quotas scope.Quotas, permissions []string) (controller.DelegationInfo, error) {
	if permissions == nil {
		permissions = []string{}
	}
	var info controller.DelegationInfo
	err := c.do(ctx, http.MethodPut, delegationsPath+"/"+url.PathEscape(network), DelegationRequest{Quotas: quotas, Permissions: permissions}, &info)
	return info, err
}

// DeleteDelegation removes the delegation of the Network network and returns it.
func (c *Client) DeleteDelegation(ctx context.Context, network string) (controller.DelegationInfo, error) {
	var info controller.DelegationInfo
	err := c.do(ctx, http.MethodDelete, delegationsPath+"/"+url.PathEscape(network), nil, &info)
	return info, err
}

// GroupMappings returns the provider groups that are mapped to a role.
func (c *Client) GroupMappings(ctx context.Context) ([]rbac.GroupMapping, error) {
	var l GroupMappingList
	err := c.do(ctx, http.MethodGet, providerGroupsPath, nil, &l)
	return l.Mappings, err
}

// SetGroupMapping maps the group of the provider of m to its role and Network, and returns it.
func (c *Client) SetGroupMapping(ctx context.Context, m rbac.GroupMapping) (rbac.GroupMapping, error) {
	var out rbac.GroupMapping
	err := c.do(ctx, http.MethodPut, providerGroupsPath+"/"+url.PathEscape(m.Provider), GroupMappingRequest{Group: m.Group, Role: m.Role, Network: m.Network}, &out)
	return out, err
}

// DeleteGroupMapping removes the mapping of the group of the provider and returns it.
func (c *Client) DeleteGroupMapping(ctx context.Context, provider, group string) (rbac.GroupMapping, error) {
	var out rbac.GroupMapping
	err := c.do(ctx, http.MethodDelete, providerGroupsPath+"/"+url.PathEscape(provider)+"?group="+url.QueryEscape(group), nil, &out)
	return out, err
}
