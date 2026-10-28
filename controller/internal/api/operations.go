package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The live operations (SDN-50 #243, ADR-0031 amendment of 2026-10-27), beside the calls of Handler. They
// are what an operator asks of the controller at the moment he asks it, and the intent never holds them:
//
//	GET    /api/v1/operations/sessions                          SessionList: the control streams of the nodes, with
//	                                                            the user, the addresses and the traffic of each;
//	                                                            user and node narrow the list                        operator
//	POST   /api/v1/operations/sessions/{id}/disconnect          SessionList: the session that it ended                operator
//	POST   /api/v1/operations/users/{name}/disconnect           SessionList: the sessions of the user that it ended   operator
//	GET    /api/v1/operations/bans                              BanList                                               operator
//	PUT    /api/v1/operations/bans/{name}                       a BanRequest, which may be empty; a controller.BanResult:
//	                                                            the ban, and the sessions that it ended               operator
//	DELETE /api/v1/operations/bans/{name}                       the store.Ban that it lifted                          operator
//	GET    /api/v1/operations/networks/{network}/mac-table      a controller.TableResult: the MAC table of the L2
//	                                                            Network on each node that holds it; node narrows it   operator
//	DELETE /api/v1/operations/networks/{network}/mac-table      a controller.TableResult: the entries that it removed;
//	                                                            node and mac narrow it                                operator
//	GET    /api/v1/operations/networks/{network}/ip-table       the same for the IP table                             operator
//	DELETE /api/v1/operations/networks/{network}/ip-table       the same; node and address narrow it                  operator
//
// Every call needs the role operator, the reads too: they show who is connected from where, and what the
// nodes learnt of their members (Needs). The controller records each call in the audit log by itself,
// with what it did to whom (kind operation), and so AuditCalls does not (selfAudited). A user, a session,
// a Network or a node that does not exist is 404, a Network that is no L2 Network or a node that does not
// hold it 400, as is a query that names a parameter that the call does not take or an address that is none.
// A call on the tables answers 200 with the result of every node, also of the ones that were down or did
// not answer: each has its status (controller.NodeTable).

// operationsPath is the root of the live operations. Every call below it needs the role operator (Needs),
// and is recorded in the audit log by the controller (selfAudited).
const operationsPath = "/api/v1/operations"

// maxBanBody bounds the body of a ban: its longest reason and the JSON around it fit.
const maxBanBody = 4 << 10

// SessionList is the answer of GET /api/v1/operations/sessions, and of the calls that end sessions.
type SessionList struct {
	Sessions []controller.Session `json:"sessions"`
}

// BanList is the answer of GET /api/v1/operations/bans.
type BanList struct {
	Bans []store.Ban `json:"bans"`
}

// BanRequest is the body of PUT /api/v1/operations/bans/{name}: why the user is banned. Without a body, a
// ban has no reason.
type BanRequest struct {
	Reason string `json:"reason,omitempty"`
}

// selfAudited reports whether the controller records the calls to urlPath in the audit log by itself,
// so that AuditCalls does not record them again: the live operations.
func selfAudited(urlPath string) bool {
	return strings.HasPrefix(path.Clean("/"+urlPath), operationsPath+"/")
}

// queryOnly answers 400 Bad Request, and reports false, when the query of r holds a parameter that is not
// one of allowed, so that a misspelt narrowing does not widen the call.
func queryOnly(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, key := range slices.Sorted(maps.Keys(r.URL.Query())) {
		if !slices.Contains(allowed, key) {
			takes := "none"
			if len(allowed) > 0 {
				takes = strings.Join(allowed, ", ")
			}
			reply(w, http.StatusBadRequest, Problem{Error: fmt.Sprintf("the query has the parameter %q, which this call does not take (it takes: %s)", key, takes)})
			return false
		}
	}
	return true
}

func init() {
	register(
		route{http.MethodGet, operationsPath + "/sessions", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			if !queryOnly(w, r, "user", "node") {
				return
			}
			q := r.URL.Query()
			reply(w, http.StatusOK, SessionList{Sessions: d.Controller.Sessions(r.Context(), q.Get("user"), q.Get("node"))})
		}},
		route{http.MethodPost, operationsPath + "/sessions/{id}/disconnect", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			s, err := d.Controller.Disconnect(r.Context(), r.PathValue("id"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, SessionList{Sessions: []controller.Session{s}})
		}},
		route{http.MethodPost, operationsPath + "/users/{name}/disconnect", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			sessions, err := d.Controller.DisconnectUser(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, SessionList{Sessions: sessions})
		}},
		route{http.MethodGet, operationsPath + "/bans", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			if !queryOnly(w, r) {
				return
			}
			reply(w, http.StatusOK, BanList{Bans: d.Controller.Bans(r.Context())})
		}},
		route{http.MethodPut, operationsPath + "/bans/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req BanRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBanBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				reply(w, http.StatusBadRequest, Problem{Error: `the body is not a ban, {"reason": "..."}: ` + err.Error()})
				return
			}
			res, err := d.Controller.BanUser(r.Context(), r.PathValue("name"), req.Reason)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodDelete, operationsPath + "/bans/{name}", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			ban, err := d.Controller.UnbanUser(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, ban)
		}},
		route{http.MethodGet, operationsPath + "/networks/{network}/mac-table", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tableCall(d, w, r, controller.TableMAC, false)
		}},
		route{http.MethodDelete, operationsPath + "/networks/{network}/mac-table", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tableCall(d, w, r, controller.TableMAC, true)
		}},
		route{http.MethodGet, operationsPath + "/networks/{network}/ip-table", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tableCall(d, w, r, controller.TableIP, false)
		}},
		route{http.MethodDelete, operationsPath + "/networks/{network}/ip-table", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tableCall(d, w, r, controller.TableIP, true)
		}},
	)
}

// tableCall answers a call on the table of an L2 Network: it reads the table, or with remove removes its
// entries, on the node that the query names or else on every node that holds the Network. A removal takes
// the entry to remove in the query too: mac for the MAC table, address for the IP table.
func tableCall(d routeDeps, w http.ResponseWriter, r *http.Request, table controller.TableKind, remove bool) {
	allowed := []string{"node"}
	if remove && table == controller.TableMAC {
		allowed = append(allowed, "mac")
	}
	if remove && table == controller.TableIP {
		allowed = append(allowed, "address")
	}
	if !queryOnly(w, r, allowed...) {
		return
	}
	q := r.URL.Query()
	req := controller.TableRequest{Network: r.PathValue("network"), Node: q.Get("node"), Table: table, Clear: remove}
	if s := q.Get("mac"); s != "" {
		mac, err := net.ParseMAC(s)
		if err != nil || len(mac) != 6 {
			reply(w, http.StatusBadRequest, Problem{Error: fmt.Sprintf("the mac %q is no MAC address of 6 bytes, such as 02:00:5e:10:00:01", s)})
			return
		}
		req.MAC = mac
	}
	if s := q.Get("address"); s != "" {
		a, err := netip.ParseAddr(s)
		if err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: fmt.Sprintf("the address %q is no IP address", s)})
			return
		}
		req.Address = a.Unmap()
	}
	res, err := d.Controller.TableOperation(r.Context(), req)
	if err != nil {
		replyError(w, err)
		return
	}
	reply(w, http.StatusOK, res)
}

// Sessions returns the sessions of the controller, the ones of the user and the node that are given
// (the empty string for any).
func (c *Client) Sessions(ctx context.Context, user, node string) ([]controller.Session, error) {
	q := url.Values{}
	if user != "" {
		q.Set("user", user)
	}
	if node != "" {
		q.Set("node", node)
	}
	p := operationsPath + "/sessions"
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	var l SessionList
	err := c.do(ctx, http.MethodGet, p, nil, &l)
	return l.Sessions, err
}

// Disconnect ends the session id and returns it.
func (c *Client) Disconnect(ctx context.Context, id string) (controller.Session, error) {
	var l SessionList
	if err := c.do(ctx, http.MethodPost, operationsPath+"/sessions/"+url.PathEscape(id)+"/disconnect", nil, &l); err != nil {
		return controller.Session{}, err
	}
	if len(l.Sessions) != 1 {
		return controller.Session{}, fmt.Errorf("the controller ended %d sessions, not the one that was named", len(l.Sessions))
	}
	return l.Sessions[0], nil
}

// DisconnectUser ends every session of the user user and returns them.
func (c *Client) DisconnectUser(ctx context.Context, user string) ([]controller.Session, error) {
	var l SessionList
	err := c.do(ctx, http.MethodPost, operationsPath+"/users/"+url.PathEscape(user)+"/disconnect", nil, &l)
	return l.Sessions, err
}

// Bans returns the banned users.
func (c *Client) Bans(ctx context.Context) ([]store.Ban, error) {
	var l BanList
	err := c.do(ctx, http.MethodGet, operationsPath+"/bans", nil, &l)
	return l.Bans, err
}

// Ban bans the user user for reason, which may be empty, and returns the ban with the sessions that it
// ended.
func (c *Client) Ban(ctx context.Context, user, reason string) (controller.BanResult, error) {
	var res controller.BanResult
	err := c.do(ctx, http.MethodPut, operationsPath+"/bans/"+url.PathEscape(user), BanRequest{Reason: reason}, &res)
	return res, err
}

// Unban lifts the ban of the user user and returns it.
func (c *Client) Unban(ctx context.Context, user string) (store.Ban, error) {
	var ban store.Ban
	err := c.do(ctx, http.MethodDelete, operationsPath+"/bans/"+url.PathEscape(user), nil, &ban)
	return ban, err
}

// MACTable reads the MAC table of the L2 Network network on the node node, or on every node that holds
// the Network when node is empty.
func (c *Client) MACTable(ctx context.Context, network, node string) (controller.TableResult, error) {
	return c.table(ctx, http.MethodGet, network, "mac-table", node, "", "")
}

// ClearMACTable removes the entry of the MAC address mac from the MAC table of the L2 Network network
// on the node node, or every entry when mac is empty, on every node that holds the Network when node is
// empty.
func (c *Client) ClearMACTable(ctx context.Context, network, node, mac string) (controller.TableResult, error) {
	return c.table(ctx, http.MethodDelete, network, "mac-table", node, "mac", mac)
}

// IPTable reads the IP table of the L2 Network network on the node node, or on every node that holds
// the Network when node is empty.
func (c *Client) IPTable(ctx context.Context, network, node string) (controller.TableResult, error) {
	return c.table(ctx, http.MethodGet, network, "ip-table", node, "", "")
}

// ClearIPTable removes the entry of the address address from the IP table of the L2 Network network on
// the node node, or every entry when address is empty, on every node that holds the Network when node
// is empty.
func (c *Client) ClearIPTable(ctx context.Context, network, node, address string) (controller.TableResult, error) {
	return c.table(ctx, http.MethodDelete, network, "ip-table", node, "address", address)
}

// table makes a call on a table: the method, the Network, the table's path segment, the node and the
// entry, with the name of its parameter, each when it is not empty.
func (c *Client) table(ctx context.Context, method, network, segment, node, param, entry string) (controller.TableResult, error) {
	q := url.Values{}
	if node != "" {
		q.Set("node", node)
	}
	if entry != "" {
		q.Set(param, entry)
	}
	p := operationsPath + "/networks/" + url.PathEscape(network) + "/" + segment
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	var res controller.TableResult
	err := c.do(ctx, method, p, nil, &res)
	return res, err
}
