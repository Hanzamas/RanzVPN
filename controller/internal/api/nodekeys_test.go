package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// The Client makes each call of the keys of the nodes (SDN-56) with the method and the path that the routes expect,
// escapes the name of the node, and gives the answer of the API.
func TestNodeKeysClientCalls(t *testing.T) {
	type call struct{ method, path, query, body string }
	calls := make(chan call, 1)
	ends := time.Date(2026, time.October, 28, 9, 10, 11, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- call{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, ""}
		if r.Method == http.MethodGet {
			reply(w, http.StatusOK, NodeKeyList{NodeKeys: []controller.NodeKeyInfo{
				{Node: "alice-laptop", Owner: "alice", State: controller.KeyExpired, Expires: ends, Approved: true},
				{Node: "newcomer", State: controller.KeyPending, Network: "corp-lan"},
			}})
			return
		}
		reply(w, http.StatusOK, controller.NodeKeyInfo{Node: "files", State: controller.KeyValid, Expires: ends, Approved: true})
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	ctx := context.Background()
	expect := func(what, method, path string) {
		t.Helper()
		if got := <-calls; got != (call{method, path, "", ""}) {
			t.Errorf("%s called %+v, want %+v", what, got, call{method, path, "", ""})
		}
	}

	keys, err := c.NodeKeys(ctx)
	if err != nil || len(keys) != 2 || keys[0].State != controller.KeyExpired || keys[0].Owner != "alice" || !keys[0].Expires.Equal(ends) || keys[1].Network != "corp-lan" {
		t.Errorf("NodeKeys gave %+v, %v", keys, err)
	}
	expect("NodeKeys", http.MethodGet, "/api/v1/operations/node-keys")
	if info, err := c.ApproveNode(ctx, "files"); err != nil || info.Node != "files" || info.State != controller.KeyValid {
		t.Errorf("ApproveNode gave %+v, %v", info, err)
	}
	expect("ApproveNode", http.MethodPost, "/api/v1/operations/node-keys/files/approve")
	if info, err := c.RefreshNodeKey(ctx, "files"); err != nil || info.Node != "files" || !info.Expires.Equal(ends) {
		t.Errorf("RefreshNodeKey gave %+v, %v", info, err)
	}
	expect("RefreshNodeKey", http.MethodPost, "/api/v1/operations/node-keys/files/refresh")
	if _, err := c.ApproveNode(ctx, "a/b"); err != nil {
		t.Error(err)
	}
	expect("ApproveNode of a name that needs escaping", http.MethodPost, "/api/v1/operations/node-keys/a%2Fb/approve")
	if _, err := c.RefreshNodeKey(ctx, "a b"); err != nil {
		t.Error(err)
	}
	expect("RefreshNodeKey of a name that needs escaping", http.MethodPost, "/api/v1/operations/node-keys/a%20b/refresh")
}

// Each call of the keys takes no parameter, the list, the approval and the refresh, and refuses one with 400 Bad Request
// before it asks the controller, so that a misspelt narrowing does not widen the call.
func TestNodeKeysRoutesRefuseAQuery(t *testing.T) {
	mux := http.NewServeMux()
	for _, rt := range routes {
		handle := rt.Handle
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
			handle(routeDeps{}, w, r)
		})
	}
	for _, c := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/operations/node-keys?node=files"},
		{http.MethodPost, "/api/v1/operations/node-keys/files/approve?node=files"},
		{http.MethodPost, "/api/v1/operations/node-keys/files/refresh?node=files"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(c.method, c.target, nil))
		var p Problem
		if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &p) != nil || !strings.Contains(p.Error, `the query has the parameter "node"`) || !strings.Contains(p.Error, "(it takes: none)") {
			t.Errorf("%s %s answered %d %s, want 400 that names the parameter and says that the call takes none", c.method, c.target, w.Code, w.Body.String())
		}
	}
}
