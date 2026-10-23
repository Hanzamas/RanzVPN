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
	"sync"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

func TestCallKind(t *testing.T) {
	for _, c := range []struct{ method, target, kind, action string }{
		{http.MethodPost, "/api/v1/apply", audit.IntentChange, "apply"},
		{http.MethodPost, "/api/v1/import", audit.IntentChange, "import"},
		{http.MethodPost, "/api/v1/rollback", audit.IntentChange, "rollback"},
		{http.MethodDelete, "/api/v1/resources/VRF/corp", audit.IntentChange, "delete"},
		{http.MethodPost, "//api/v1//apply", audit.IntentChange, "apply"},
		{http.MethodGet, "/api/v1/apply", audit.Operation, "GET /api/v1/apply"},
		{http.MethodPut, "/api/v1/targets/slack", audit.Operation, "PUT /api/v1/targets/slack"},
		{http.MethodPost, "/api/v1/revisions/2/confirm", audit.Operation, "POST /api/v1/revisions/2/confirm"},
		{http.MethodDelete, "/api/v1/x/../tokens/ci", audit.Operation, "DELETE /api/v1/tokens/ci"},
		{http.MethodPost, "/api/v1/tokens", audit.Operation, "POST /api/v1/tokens"},
	} {
		if kind, action := callKind(c.method, c.target); kind != c.kind || action != c.action {
			t.Errorf("%s %s is the kind %q with the action %q, want %q and %q", c.method, c.target, kind, action, c.kind, c.action)
		}
	}
}

// fakeAuditor keeps what AuditCalls records, with the origin that the context of each record carried.
type fakeAuditor struct {
	recs    []audit.Record
	origins []audit.Origin
}

func (f *fakeAuditor) RecordAudit(ctx context.Context, r audit.Record) error {
	o, _ := audit.FromContext(ctx)
	f.origins = append(f.origins, o)
	f.recs = append(f.recs, r)
	return nil
}

// AuditCalls records the calls that change something, each with the token and the address of its
// caller: an intent change that succeeded is left to the controller, which knows its revision, and
// every other call is a record, a failure with what the API said.
func TestAuditCallsRecordsWhatChanges(t *testing.T) {
	for _, c := range []struct {
		method, target string
		status         int
		body           string
		kind, action   string
		outcome        string
		message        string
	}{
		{http.MethodGet, "/api/v1/status", http.StatusOK, `{}`, "", "", "", ""},
		{http.MethodHead, "/api/v1/status", http.StatusOK, ``, "", "", "", ""},
		{http.MethodPut, "/api/v1/targets/slack", http.StatusOK, `{"name":"slack"}`, audit.Operation, "PUT /api/v1/targets/slack", audit.Success, ""},
		{http.MethodPost, "/api/v1/licence", 0, ``, audit.Operation, "POST /api/v1/licence", audit.Success, ""},
		{http.MethodPost, "/api/v1/apply", http.StatusOK, `{"revision":1}`, "", "", "", ""},
		{http.MethodPost, "/api/v1/apply", http.StatusBadRequest, `{"error":"Node \"Bad_Name\": the name must be a DNS label"}`, audit.IntentChange, "apply", audit.Failure,
			`Node "Bad_Name": the name must be a DNS label`},
		{http.MethodDelete, "/api/v1/resources/VRF/corp", http.StatusNotFound, `not json`, audit.IntentChange, "delete", audit.Failure, "Not Found"},
		{http.MethodPost, "/api/v1/rollback", http.StatusConflict, `{"error":"conflict: revision 2 waits for confirmation"}`, audit.IntentChange, "rollback", audit.Failure,
			"conflict: revision 2 waits for confirmation"},
		{http.MethodPut, "/api/v1/licence", http.StatusForbidden, `{"error":"the licence in force does not allow it"}`, audit.Operation, "PUT /api/v1/licence", audit.Failure,
			"the licence in force does not allow it"},
	} {
		f := &fakeAuditor{}
		var seen audit.Origin
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = audit.FromContext(r.Context())
			if c.status != 0 {
				w.WriteHeader(c.status)
			}
			_, _ = io.WriteString(w, c.body)
		})
		req := httptest.NewRequest(c.method, c.target, nil)
		req.RemoteAddr = "192.0.2.7:51234"
		req = req.WithContext(context.WithValue(req.Context(), callerKey{}, rbac.Token{Name: "ci", Role: rbac.Operator}))
		AuditCalls(f, inner).ServeHTTP(httptest.NewRecorder(), req)

		if want := (audit.Origin{Actor: "token:ci", Source: "192.0.2.7"}); seen != want {
			t.Errorf("%s %s: the call carried the origin %+v, want %+v", c.method, c.target, seen, want)
		}
		if c.kind == "" {
			if len(f.recs) != 0 {
				t.Errorf("%s %s answered %d: recorded %+v, want nothing", c.method, c.target, c.status, f.recs)
			}
			continue
		}
		if len(f.recs) != 1 {
			t.Errorf("%s %s answered %d: recorded %+v, want one record", c.method, c.target, c.status, f.recs)
			continue
		}
		if r := f.recs[0]; r.Kind != c.kind || r.Action != c.action || r.Outcome != c.outcome || r.Message != c.message || f.origins[0] != seen {
			t.Errorf("%s %s answered %d: recorded %+v with the origin %+v, want the kind %q, the action %q, the outcome %q and the message %q",
				c.method, c.target, c.status, r, f.origins[0], c.kind, c.action, c.outcome, c.message)
		}
	}

	// A call that has no token in its context is from an actor that is unknown
	f := &fakeAuditor{}
	var seen audit.Origin
	AuditCalls(f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = audit.FromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if seen.Actor != audit.ActorUnknown {
		t.Errorf("a call with no token carried the actor %q, want %q", seen.Actor, audit.ActorUnknown)
	}
}

// auditStore is an audit.Store that keeps the records it is given and no more.
type auditStore struct {
	audit.Store
	mu   sync.Mutex
	recs []audit.Record
}

func (s *auditStore) AddAudit(_ context.Context, r audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	return nil
}

func (s *auditStore) records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.recs...)
}

// AuditRefusals records the calls that the Guard refuses as unauthenticated, with the reason and the
// address of the caller, and nothing else: not a call that is refused for its role, not a call that
// goes through. A source that fails again at once is recorded once.
func TestAuditRefusalsRecordsFailedAuthentications(t *testing.T) {
	st := &auditStore{}
	l := audit.NewLog(st, nil)
	refuse := func(status int, wwwAuthenticate string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if wwwAuthenticate != "" {
				w.Header().Set("WWW-Authenticate", wwwAuthenticate)
			}
			reply(w, status, Problem{Error: "no"})
		})
	}
	serve := func(h http.Handler, remote string) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	serve(AuditRefusals(l, refuse(http.StatusUnauthorized, challenge)), "192.0.2.7:1000")
	serve(AuditRefusals(l, refuse(http.StatusUnauthorized, challenge+`, error="invalid_token"`)), "192.0.2.8:1000")
	serve(AuditRefusals(l, refuse(http.StatusForbidden, challenge+`, error="insufficient_scope"`)), "192.0.2.9:1000")
	serve(AuditRefusals(l, refuse(http.StatusOK, "")), "192.0.2.10:1000")
	serve(AuditRefusals(l, refuse(http.StatusUnauthorized, challenge)), "192.0.2.7:2000")

	recs := st.records()
	if len(recs) != 2 {
		t.Fatalf("%d records were made, want one for each of the two sources that were refused as unauthenticated: %+v", len(recs), recs)
	}
	for i, c := range []struct{ source, message string }{
		{"192.0.2.7", "the request has no bearer token"},
		{"192.0.2.8", "the bearer token is not a token of this controller, or it was deleted"},
	} {
		if r := recs[i]; r.Kind != audit.AuthFailed || r.Actor != audit.ActorUnknown || r.Source != c.source || r.Outcome != audit.Failure || r.Message != c.message {
			t.Errorf("record %d is %+v, want a failed authentication of %s that says %q", i+1, r, c.source, c.message)
		}
	}
}

// statusWriter passes everything on, keeps the status code and the start of the body of an answer that
// is not a success, and makes the message of a failed call from it.
func TestStatusWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &statusWriter{ResponseWriter: rec}
	if w.code() != http.StatusOK || w.Unwrap() != rec {
		t.Errorf("a writer that wrote nothing has the code %d, or does not unwrap", w.code())
	}
	_, _ = w.Write([]byte("fine"))
	w.Flush()
	if w.code() != http.StatusOK || len(w.body) != 0 || !rec.Flushed || rec.Body.String() != "fine" {
		t.Errorf("a success is kept as code %d with a body of %d bytes, flushed %v: %q", w.code(), len(w.body), rec.Flushed, rec.Body.String())
	}

	failed := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	failed.WriteHeader(http.StatusInternalServerError)
	failed.WriteHeader(http.StatusNotFound)
	_, _ = failed.Write([]byte(strings.Repeat("x", 3000)))
	if failed.code() != http.StatusInternalServerError || len(failed.body) != maxProblem {
		t.Errorf("a failure has the code %d and keeps %d bytes of its body, want 500 and %d", failed.code(), len(failed.body), maxProblem)
	}
	if got := failed.problem(); got != "Internal Server Error" {
		t.Errorf("the message of a failure whose body is no Problem is %q, want the status text", got)
	}

	problem := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	problem.WriteHeader(http.StatusBadRequest)
	_, _ = problem.Write([]byte(`{"error":"boom"}`))
	if got := problem.problem(); got != "boom" {
		t.Errorf("the message of a failure that sent a Problem is %q, want boom", got)
	}
}

// The Client reads the audit log with the query of its filter, and the calls for the audit targets
// and the retention send the token, the name of the target escaped in the path and the body as JSON.
func TestAuditClient(t *testing.T) {
	type call struct{ method, path, query, body string }
	calls := make(chan call, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(body)}
		switch {
		case r.URL.Path == "/api/v1/audit":
			reply(w, http.StatusOK, AuditList{Records: []audit.Record{{ID: 7, Kind: audit.Login, Actor: "node:a"}}, Next: 7})
		case strings.HasSuffix(r.URL.Path, "/retention"):
			reply(w, http.StatusOK, audit.Retention{Days: 30, MaxRecords: 5000})
		case r.URL.Path == "/api/v1/audit/targets":
			reply(w, http.StatusOK, AuditTargetList{Targets: []export.Info{{Name: "siem", Kind: export.KindWebhook}}})
		case strings.HasSuffix(r.URL.Path, "/gone"):
			reply(w, http.StatusNotFound, Problem{Error: `audit target "gone" was not found`})
		default:
			reply(w, http.StatusOK, export.Info{Name: "siem", Kind: export.KindWebhook})
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	ctx := context.Background()

	list, err := c.Audit(ctx, audit.Filter{})
	if err != nil || len(list.Records) != 1 || list.Records[0].ID != 7 || list.Next != 7 {
		t.Fatalf("Audit gave %+v, %v", list, err)
	}
	if got := <-calls; got.method != http.MethodGet || got.path != "/api/v1/audit" || got.query != "" {
		t.Errorf("Audit with no filter called %+v", got)
	}
	if _, err := c.Audit(ctx, audit.Filter{Kind: audit.Login, After: 3, Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if got := <-calls; got.query != "after=3&kind=login&limit=5" {
		t.Errorf("Audit with a filter sent the query %q", got.query)
	}

	if infos, err := c.AuditTargets(ctx); err != nil || len(infos) != 1 || infos[0].Name != "siem" {
		t.Errorf("AuditTargets gave %+v, %v", infos, err)
	}
	if got := <-calls; got.method != http.MethodGet || got.path != "/api/v1/audit/targets" {
		t.Errorf("AuditTargets called %+v", got)
	}
	if info, err := c.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "hmac-key"}); err != nil || info.Name != "siem" {
		t.Errorf("PutAuditTarget gave %+v, %v", info, err)
	}
	if got := <-calls; got.method != http.MethodPut || got.path != "/api/v1/audit/targets/siem" || !strings.Contains(got.body, `"secret":"hmac-key"`) {
		t.Errorf("PutAuditTarget called %+v", got)
	}
	if _, err := c.DeleteAuditTarget(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}
	if got := <-calls; got.method != http.MethodDelete || got.path != "/api/v1/audit/targets/a%2Fb" {
		t.Errorf("DeleteAuditTarget called %+v, want the name escaped", got)
	}
	_, err = c.DeleteAuditTarget(ctx, "gone")
	<-calls
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusNotFound || !strings.Contains(e.Message, "was not found") {
		t.Errorf("deleting an audit target that is gone gave %v, want a 404 with the message of the API", err)
	}

	if r, err := c.AuditRetention(ctx); err != nil || r != (audit.Retention{Days: 30, MaxRecords: 5000}) {
		t.Errorf("AuditRetention gave %+v, %v", r, err)
	}
	if got := <-calls; got.method != http.MethodGet || got.path != "/api/v1/audit/retention" {
		t.Errorf("AuditRetention called %+v", got)
	}
	if r, err := c.SetAuditRetention(ctx, audit.Retention{Days: 30, MaxRecords: 5000}); err != nil || r.Days != 30 {
		t.Errorf("SetAuditRetention gave %+v, %v", r, err)
	}
	if got := <-calls; got.method != http.MethodPut || got.path != "/api/v1/audit/retention" || got.body != `{"days":30,"maxRecords":5000}` {
		t.Errorf("SetAuditRetention called %+v", got)
	}
}

// A request that is not valid is refused with 400 Bad Request and the problem named before the
// controller is asked.
func TestAuditRoutesRefuseWhatIsNotValid(t *testing.T) {
	mux := http.NewServeMux()
	for _, rt := range routes {
		handle := rt.Handle
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(w http.ResponseWriter, r *http.Request) {
			handle(routeDeps{}, w, r)
		})
	}
	for _, c := range []struct{ name, method, target, body, want string }{
		{"a kind that does not exist", http.MethodGet, "/api/v1/audit?kind=reboot", "", `the kind "reboot" is none of`},
		{"a limit out of bounds", http.MethodGet, "/api/v1/audit?limit=0", "", `limit "0" is not a number from 1 to 1000`},
		{"a target that is no JSON", http.MethodPut, "/api/v1/audit/targets/siem", `{"name":`, "the body is not an audit target"},
		{"a field that a target has not", http.MethodPut, "/api/v1/audit/targets/siem", `{"colour":"red"}`, "the body is not an audit target"},
		{"a name other than the path", http.MethodPut, "/api/v1/audit/targets/siem", `{"name":"other","kind":"webhook"}`, "the name of the target in the body is other, and the path names siem"},
		{"a retention that is no JSON", http.MethodPut, "/api/v1/audit/retention", `[1]`, "the body is not an audit retention"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(c.method, c.target, strings.NewReader(c.body)))
		var p Problem
		if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &p) != nil || !strings.Contains(p.Error, c.want) {
			t.Errorf("%s: the answer is %d %s, want 400 that says %q", c.name, w.Code, w.Body.String(), c.want)
		}
	}
}

// A request of the audit log that is not valid is answered with 400 Bad Request and its problems; any
// other error as replyError answers it.
func TestReplyAudit(t *testing.T) {
	invalid := audit.Retention{}.Validate()
	for _, c := range []struct {
		err  error
		want int
	}{
		{invalid, http.StatusBadRequest},
		{fmt.Errorf("%w: something", audit.ErrInvalid), http.StatusBadRequest},
		{errors.New("the store is gone"), http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		replyAudit(w, c.err)
		var p Problem
		if w.Code != c.want || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Error != c.err.Error() {
			t.Errorf("%v is answered with %d %s, want %d and the error as the problem", c.err, w.Code, w.Body.String(), c.want)
		}
	}
}
