package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The keys of the Nodes (SDN-56 #249, ADR-0031 amendment of 2026-10-28), under the path of the live operations
// (operations.go), whose role and audit they share: an operator reads who is connected and whose key ends when, and
// decides who is admitted, at the moment that he asks, and the intent holds neither:
//
//	GET  /api/v1/operations/node-keys                   NodeKeyList: the key of every Node, with its state (valid, expired or
//	                                                    pending), when it last authenticated, when it ends and whether the
//	                                                    Node was approved                                                       operator
//	POST /api/v1/operations/node-keys/{name}/approve    the controller.NodeKeyInfo of the Node that it approved: the Network
//	                                                    that held it admits it, and its key lives from now                      operator
//	POST /api/v1/operations/node-keys/{name}/refresh    the controller.NodeKeyInfo of the Node whose key it refreshed, a Node
//	                                                    that has no owner; a device is refreshed by the login of its user       operator
//
// The controller records each call in the audit log by itself (selfAudited). A Node that the intent does not hold is 404,
// the refresh of a Node that has an owner 409, and a query on a call that takes none 400.

// NodeKeyList is the answer of GET /api/v1/operations/node-keys.
type NodeKeyList struct {
	NodeKeys []controller.NodeKeyInfo `json:"nodeKeys"`
}

func init() {
	register(
		route{http.MethodGet, operationsPath + "/node-keys", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			if !queryOnly(w, r) {
				return
			}
			reply(w, http.StatusOK, NodeKeyList{NodeKeys: d.Controller.NodeKeys(r.Context())})
		}},
		route{http.MethodPost, operationsPath + "/node-keys/{name}/approve", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			info, err := d.Controller.ApproveNode(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
		route{http.MethodPost, operationsPath + "/node-keys/{name}/refresh", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			info, err := d.Controller.RefreshNodeKey(r.Context(), r.PathValue("name"))
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
	)
}

// NodeKeys returns the key of every Node.
func (c *Client) NodeKeys(ctx context.Context) ([]controller.NodeKeyInfo, error) {
	var l NodeKeyList
	err := c.do(ctx, http.MethodGet, operationsPath+"/node-keys", nil, &l)
	return l.NodeKeys, err
}

// ApproveNode approves the Node name and returns its key.
func (c *Client) ApproveNode(ctx context.Context, name string) (controller.NodeKeyInfo, error) {
	var info controller.NodeKeyInfo
	err := c.do(ctx, http.MethodPost, operationsPath+"/node-keys/"+url.PathEscape(name)+"/approve", nil, &info)
	return info, err
}

// RefreshNodeKey refreshes the key of the Node name, which has no owner, and returns it.
func (c *Client) RefreshNodeKey(ctx context.Context, name string) (controller.NodeKeyInfo, error) {
	var info controller.NodeKeyInfo
	err := c.do(ctx, http.MethodPost, operationsPath+"/node-keys/"+url.PathEscape(name)+"/refresh", nil, &info)
	return info, err
}
