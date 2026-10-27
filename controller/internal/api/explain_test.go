package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// The Client asks for the walk with the fields of the query as the parameters of GET /api/v1/explain and gives the
// answer of the API; the route refuses parameters that are no query with 400 Bad Request, naming the parameter,
// before it asks the controller.
func TestExplainClient(t *testing.T) {
	calls := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		reply(w, http.StatusOK, explain.Result{Verdict: explain.Verdict{Delivered: true, Node: "app-1", VRF: "corp"}})
	}))
	defer srv.Close()

	res, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).Explain(context.Background(), explain.Query{From: "web-1", To: "app-1", VRF: "corp", Protocol: "tcp", SourcePort: 40000, Port: 8080})
	if err != nil || !res.Verdict.Delivered || res.Verdict.Node != "app-1" {
		t.Fatalf("Explain gave %+v, %v", res, err)
	}
	if got, want := <-calls, "GET /api/v1/explain?from=web-1&port=8080&protocol=tcp&sourcePort=40000&to=app-1&vrf=corp"; got != want {
		t.Errorf("Explain called %q, want %q", got, want)
	}
	if _, err := (&Client{URL: srv.URL}).Explain(context.Background(), explain.Query{From: "web-1", To: "10.10.0.20"}); err != nil {
		t.Fatal(err)
	}
	if got, want := <-calls, "GET /api/v1/explain?from=web-1&to=10.10.0.20"; got != want {
		t.Errorf("Explain called %q, want %q", got, want)
	}

	var handle func(routeDeps, http.ResponseWriter, *http.Request)
	for _, rt := range routes {
		if rt.Method == http.MethodGet && rt.Pattern == explainPath {
			handle = rt.Handle
		}
	}
	if handle == nil {
		t.Fatal("GET /api/v1/explain is not registered")
	}
	for _, c := range []struct{ query, want string }{
		{"to=app-1", "the parameters from and to"},
		{"from=web-1", "the parameters from and to"},
		{"from=web-1&to=app-1&port=70000", "the parameter port is not a port"},
		{"from=web-1&to=app-1&sourcePort=x", "the parameter sourcePort is not a port"},
		{"from=web-1&to=app-1&protocol=gre", "the parameter protocol"},
	} {
		w := httptest.NewRecorder()
		handle(routeDeps{}, w, httptest.NewRequest(http.MethodGet, explainPath+"?"+c.query, nil))
		var p Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusBadRequest || err != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("?%s: %d %s, want 400 Bad Request with %q", c.query, w.Code, w.Body.Bytes(), c.want)
		}
	}
}
