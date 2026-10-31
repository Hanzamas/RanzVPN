package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// AuditRefusals records the refusal of a call whose token has expired under the name of the token, with the word expired and when
// the token ended, as the Guard tells it (noteExpired), and any other refusal as before, under an actor that is unknown (AUD1-DT-15,
// #497).
func TestAuditRefusalsRecordsTheTokenThatExpired(t *testing.T) {
	st := &auditStore{}
	l := audit.NewLog(st, nil)
	expires := time.Date(2026, time.October, 30, 14, 0, 0, 0, time.UTC)
	refuse := func(expired bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expired {
				noteExpired(r.Context(), rbac.Token{Name: "ci", Role: rbac.Operator, Expires: expires, Expired: true})
				w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token", error_description="`+expiredDescription+`"`)
			} else {
				w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
			}
			reply(w, http.StatusUnauthorized, Problem{Error: "no"})
		})
	}
	serve := func(h http.Handler, remote string) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	serve(AuditRefusals(l, refuse(true)), "192.0.2.7:1000")
	serve(AuditRefusals(l, refuse(false)), "192.0.2.8:1000")

	recs := st.records()
	if len(recs) != 2 {
		t.Fatalf("%d records were made, want one for each of the two refusals: %+v", len(recs), recs)
	}
	if r := recs[0]; r.Kind != audit.AuthFailed || r.Actor != "token:ci" || r.Source != "192.0.2.7" || r.Outcome != audit.Failure ||
		r.Message != `the bearer token "ci" expired at 2026-10-30T14:00:00Z` {
		t.Errorf("the refusal of the expired token is %+v, want a failed authentication of token:ci from 192.0.2.7 that says when it expired", r)
	}
	if r := recs[1]; r.Actor != audit.ActorUnknown || strings.Contains(r.Message, "expired") || !strings.Contains(r.Message, "is not a token of this controller") {
		t.Errorf("the refusal of the other token is %+v, want an actor that is unknown and no word of an expiry", r)
	}
}

// A source that was refused a moment before, for a token that no one has, does not hide the record of its call with the token that
// expired: the throttle of the failed authentications of a source counts a token apart (audit.Log). Both come from one source and
// go to one audit log, as they do in the controller, which the test above keeps apart with a log for each call. A source that tries a
// leaked token among others must show the token in the log, not only the others. That the same token again within the window is held
// back is the test of the audit package, which moves the clock.
func TestAnExpiredTokenIsRecordedAfterAnotherRefusalOfItsSource(t *testing.T) {
	st := &auditStore{}
	h := AuditRefusals(audit.NewLog(st, nil), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Expired") != "" {
			noteExpired(r.Context(), rbac.Token{Name: "ci", Role: rbac.Operator, Expires: time.Date(2026, time.October, 30, 14, 0, 0, 0, time.UTC), Expired: true})
		}
		reply(w, http.StatusUnauthorized, Problem{Error: "no"})
	}))
	for _, expired := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "192.0.2.7:1000"
		if expired {
			req.Header.Set("X-Expired", "1")
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	recs := st.records()
	if len(recs) != 2 || recs[0].Actor != audit.ActorUnknown || recs[1].Actor != "token:ci" || !strings.Contains(recs[1].Message, "expired") {
		t.Errorf("the records are %+v, want the refusal of the unknown token and, from the same source, the one of the token that expired, under its name", recs)
	}
}

// The note of a refusal belongs to its call: one call that was refused for an expired token does not name the token in the record of
// the next, and a Guard that no AuditRefusals stands in front of, whose context has no note, tells nothing and fails nowhere.
func TestTheNoteOfARefusalBelongsToItsCall(t *testing.T) {
	st := &auditStore{}
	l := audit.NewLog(st, nil)
	expiredOnce := true
	h := AuditRefusals(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expiredOnce {
			noteExpired(r.Context(), rbac.Token{Name: "ci", Expires: time.Date(2026, time.October, 30, 14, 0, 0, 0, time.UTC), Expired: true})
			expiredOnce = false
		}
		reply(w, http.StatusUnauthorized, Problem{Error: "no"})
	}))
	for _, remote := range []string{"192.0.2.7:1000", "192.0.2.8:1000"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	recs := st.records()
	if len(recs) != 2 || recs[0].Actor != "token:ci" || recs[1].Actor != audit.ActorUnknown || strings.Contains(recs[1].Message, "expired") {
		t.Errorf("the records are %+v, want the first under token:ci and the second under an actor that is unknown", recs)
	}

	noteExpired(context.Background(), rbac.Token{Name: "ci"})
}
