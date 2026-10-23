package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The calls of the Client for the targets send the token, the name of the target escaped in the
// path and the target as JSON, give what the API answers, and give an answer that is not 200 OK as
// an Error with the message of the API.
func TestTargetsClient(t *testing.T) {
	type call struct{ method, path, auth, body string }
	calls := make(chan call, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), string(body)}
		switch {
		case r.Method == http.MethodGet:
			reply(w, http.StatusOK, TargetList{Targets: []export.Info{{Name: "slack", Kind: export.KindWebhook, URL: "https://hooks.example.com/...", HasSecret: true}}})
		case strings.HasSuffix(r.URL.Path, "/gone"):
			reply(w, http.StatusNotFound, Problem{Error: `export target "gone" was not found`})
		default:
			reply(w, http.StatusOK, export.Info{Name: "slack", Kind: export.KindWebhook, URL: "https://hooks.example.com/..."})
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	ctx := context.Background()

	infos, err := c.Targets(ctx)
	if err != nil || len(infos) != 1 || infos[0].Name != "slack" || !infos[0].HasSecret {
		t.Fatalf("Targets gave %+v, %v", infos, err)
	}
	if got := <-calls; got.method != http.MethodGet || got.path != "/api/v1/targets" || got.auth != "Bearer ranz_secret" {
		t.Errorf("Targets called %+v", got)
	}

	info, err := c.PutTarget(ctx, export.Target{Name: "slack", Kind: export.KindWebhook, URL: "https://hooks.example.com/services/T0/B0", Secret: "hmac-key"})
	if err != nil || info.Name != "slack" {
		t.Fatalf("PutTarget gave %+v, %v", info, err)
	}
	if got := <-calls; got.method != http.MethodPut || got.path != "/api/v1/targets/slack" || !strings.Contains(got.body, `"secret":"hmac-key"`) {
		t.Errorf("PutTarget called %+v", got)
	}

	if _, err := c.DeleteTarget(ctx, "slack"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if got := <-calls; got.method != http.MethodDelete || got.path != "/api/v1/targets/slack" {
		t.Errorf("DeleteTarget called %+v", got)
	}

	if _, err := c.DeleteTarget(ctx, "a/b"); err != nil {
		t.Fatalf("DeleteTarget of a name with a slash: %v", err)
	}
	if got := <-calls; got.path != "/api/v1/targets/a%2Fb" {
		t.Errorf("a name with a slash went to the path %s, want it escaped", got.path)
	}

	_, err = c.DeleteTarget(ctx, "gone")
	<-calls
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusNotFound || !strings.Contains(e.Message, "was not found") {
		t.Errorf("deleting a target that is gone gave %v, want a 404 with the message of the API", err)
	}
}

// A change of a target is refused with 400 Bad Request and the problem named before the controller
// is asked: a body that is no export target, and a name in the body other than the one in the path.
func TestPutTargetRefusesWhatIsNoTarget(t *testing.T) {
	mux := http.NewServeMux()
	for _, rt := range routes {
		handle := rt.Handle
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
			handle(routeDeps{}, w, r)
		})
	}
	for _, c := range []struct{ name, body, want string }{
		{"a body that is no JSON", `{"name":`, "the body is not an export target"},
		{"a field that a target has not", `{"name":"slack","colour":"red"}`, "the body is not an export target"},
		{"a name other than the path", `{"name":"other","kind":"webhook"}`, "the name of the target in the body is other, and the path names slack"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/targets/slack", strings.NewReader(c.body)))
		var p Problem
		if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &p) != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("%s: the answer is %d %s, want 400 that says %q", c.name, w.Code, w.Body.String(), c.want)
		}
	}
}

// A target that is not valid is answered with 400 Bad Request and its problems; any other error
// as replyError answers it.
func TestReplyTarget(t *testing.T) {
	invalid := export.Target{Name: "Bad Name", Kind: "email"}.Validate()
	for _, c := range []struct {
		err  error
		want int
	}{
		{invalid, http.StatusBadRequest},
		{fmt.Errorf("%w: export target %q", intent.ErrNotFound, "slack"), http.StatusNotFound},
		{errors.New("the store is gone"), http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		replyTarget(w, c.err)
		var p Problem
		if w.Code != c.want || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Error != c.err.Error() {
			t.Errorf("%v is answered with %d %s, want %d and the error as the problem", c.err, w.Code, w.Body.String(), c.want)
		}
	}
}
