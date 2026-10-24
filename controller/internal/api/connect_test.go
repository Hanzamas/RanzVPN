package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// The Client calls the shortcut with the two VRFs in the body and gives the answer of the API; the
// route refuses a body that is not two VRFs with 400 Bad Request before it asks the controller.
func TestConnectClient(t *testing.T) {
	type call struct{ method, path, body string }
	calls := make(chan call, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.Path, string(body)}
		reply(w, http.StatusOK, controller.ApplyResult{Revision: 7, Nodes: []controller.NodeGeneration{{Name: "branch-1", Generation: 3}}})
	}))
	defer srv.Close()

	res, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).Connect(context.Background(), "corp", "lab")
	if err != nil || res.Revision != 7 || len(res.Nodes) != 1 {
		t.Fatalf("Connect gave %+v, %v", res, err)
	}
	if got := <-calls; got.method != http.MethodPost || got.path != "/api/v1/connect" || got.body != `{"vrfs":["corp","lab"]}` {
		t.Errorf("Connect called %+v", got)
	}

	var handle func(routeDeps, http.ResponseWriter, *http.Request)
	for _, rt := range routes {
		if rt.Method == http.MethodPost && rt.Pattern == "/api/v1/connect" {
			handle = rt.Handle
		}
	}
	if handle == nil {
		t.Fatal("POST /api/v1/connect is not registered")
	}
	for _, body := range []string{`{"vrfs": ["corp"]}`, `{"vrfs": ["corp", "lab", "dmz"]}`, `{"a": "corp"}`, `not json`} {
		w := httptest.NewRecorder()
		handle(routeDeps{}, w, httptest.NewRequest(http.MethodPost, "/api/v1/connect", strings.NewReader(body)))
		var p Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusBadRequest || err != nil || !strings.Contains(p.Error, "two VRFs to connect") {
			t.Errorf("the body %s: %d %s, want 400 Bad Request", body, w.Code, w.Body.Bytes())
		}
	}
}
