package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// AuditCalls records a read of the API tokens, the audit log and the licence that succeeded as an
// access, with the call as its action and the token and the address of its caller as its origin
// (AUD1-DT-13, #461); it records no other read, no read that failed, and it passes every answer on.
func TestAuditCallsRecordsTheReadsOfTheTokensTheAuditLogAndTheLicence(t *testing.T) {
	for _, c := range []struct {
		name, method, path, query string
		status                    int
		action                    string // of the record, none when the read is not recorded
	}{
		{"the tokens", http.MethodGet, "/api/v1/tokens", "", http.StatusOK, "GET /api/v1/tokens"},
		{"the audit log", http.MethodGet, "/api/v1/audit", "", http.StatusOK, "GET /api/v1/audit"},
		{"the licence", http.MethodGet, "/api/v1/licence", "", http.StatusOK, "GET /api/v1/licence"},
		{"a head of the licence", http.MethodHead, "/api/v1/licence", "", http.StatusOK, "HEAD /api/v1/licence"},
		{"a path that is not clean", http.MethodGet, "//api/v1/./x/../tokens", "", http.StatusOK, "GET /api/v1/tokens"},
		{"a filter of the audit log, which the record leaves out", http.MethodGet, "/api/v1/audit", "kind=login&actor=token%3Aadmin", http.StatusOK, "GET /api/v1/audit"},
		{"the tokens, which could not be read", http.MethodGet, "/api/v1/tokens", "", http.StatusInternalServerError, ""},
		{"the audit log, with a filter that is not valid", http.MethodGet, "/api/v1/audit", "kind=reboot", http.StatusBadRequest, ""},
		{"the status", http.MethodGet, "/api/v1/status", "", http.StatusOK, ""},
		{"the whoami", http.MethodGet, "/api/v1/whoami", "", http.StatusOK, ""},
		{"the intent", http.MethodGet, "/api/v1/resources", "", http.StatusOK, ""},
		{"the audit targets", http.MethodGet, "/api/v1/audit/targets", "", http.StatusOK, ""},
		{"the audit retention", http.MethodGet, "/api/v1/audit/retention", "", http.StatusOK, ""},
		{"a name under the tokens", http.MethodGet, "/api/v1/tokens/ci", "", http.StatusOK, ""},
	} {
		f := &fakeAuditor{}
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, `{"answer":true}`)
		})
		req := httptest.NewRequest(c.method, "/", nil)
		req.URL.Path, req.URL.RawQuery = c.path, c.query
		req.RemoteAddr = "192.0.2.7:51234"
		req = req.WithContext(context.WithValue(req.Context(), callerKey{}, rbac.Token{Name: "ci", Role: rbac.Admin}))
		w := httptest.NewRecorder()
		AuditCalls(f, inner).ServeHTTP(w, req)

		if w.Code != c.status || w.Body.String() != `{"answer":true}` {
			t.Errorf("%s: the answer is %d %q, want the one of the call, passed on", c.name, w.Code, w.Body.String())
		}
		if c.action == "" {
			if len(f.recs) != 0 {
				t.Errorf("%s: recorded %+v, want nothing", c.name, f.recs)
			}
			continue
		}
		if len(f.recs) != 1 {
			t.Errorf("%s: recorded %+v, want one record", c.name, f.recs)
			continue
		}
		r, want := f.recs[0], audit.Origin{Actor: "token:ci", Source: "192.0.2.7"}
		if r.Kind != audit.Access || r.Action != c.action || r.Outcome != audit.Success || r.Message != "" || r.Subject != "" || f.origins[0] != want {
			t.Errorf("%s: recorded %+v with the origin %+v, want the kind %q, the action %q, success, and the origin %+v",
				c.name, r, f.origins[0], audit.Access, c.action, want)
		}
	}
}

// A read that nothing authenticated, as in a test of a handler with no Guard, is an access of an actor
// that is not known.
func TestAuditCallsRecordsTheReadOfAnUnknownCaller(t *testing.T) {
	f := &fakeAuditor{}
	AuditCalls(f, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/licence", nil))
	if len(f.recs) != 1 || f.origins[0].Actor != audit.ActorUnknown || f.recs[0].Kind != audit.Access {
		t.Errorf("recorded %+v with the origins %+v, want one access of the actor %q", f.recs, f.origins, audit.ActorUnknown)
	}
}
