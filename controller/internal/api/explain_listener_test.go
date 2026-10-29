package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The Client asks for the explanation of a Listener at GET /api/v1/explain/listeners/{name}, with the name escaped as a segment
// of the path, and gives the answer of the API; the route is a read, which a viewer may make (SDN-94, #423).
func TestExplainListenerClient(t *testing.T) {
	calls := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Method + " " + r.URL.EscapedPath()
		reply(w, http.StatusOK, explain.ListenerResult{Listener: "edge hub/1", Node: "hub", KeyReported: true,
			Links: []explain.ListenerLink{{Node: "gw-1", Address: "hub.example.com:8443", ServerName: "www.example.com"}}})
	}))
	defer srv.Close()

	res, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).ExplainListener(context.Background(), "edge hub/1")
	if err != nil || res.Node != "hub" || !res.KeyReported || len(res.Links) != 1 || res.Links[0].Node != "gw-1" {
		t.Fatalf("ExplainListener gave %+v, %v", res, err)
	}
	if got, want := <-calls, "GET /api/v1/explain/listeners/edge%20hub%2F1"; got != want {
		t.Errorf("ExplainListener called %q, want %q", got, want)
	}

	if got := Needs(http.MethodGet, explainListenerPath+"edge-hub"); got != rbac.Viewer {
		t.Errorf("the explanation of a Listener needs %s, want viewer", got)
	}
	var found bool
	for _, rt := range routes {
		if rt.Method == http.MethodGet && rt.Pattern == explainListenerPath+"{name}" {
			found = true
		}
	}
	if !found {
		t.Error("GET /api/v1/explain/listeners/{name} is not registered")
	}
}
