// Controller conformance for the audit record of an expired token (AUD1-DT-15, #497), with the harness of conformance_test.go and
// the audit helpers of audit_test.go: the API of these tests has the audit log on it as ranz-controller serves it
// (api.AuditRefusals and api.AuditCalls), and tokens that read the time from a clock that the test moves (tokenlife_test.go).
package controller_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// auditedLifeAPI serves the API of the controller of h as ranz-controller does, behind the Guard and with the audit log on it, with
// tokens that read the time from clk. Each server has an audit log of its own, so the throttle of a source that fails again within
// a few seconds (audit.Log) is its own too.
func (h *harness) auditedLifeAPI(clk *lifeClock) *httptest.Server {
	h.t.Helper()
	tokens := rbac.New(h.st).WithClock(clk.Now)
	routes := api.AuditCalls(h.c, api.Routes(h.c, tokens, api.Status{}))
	srv := httptest.NewTLSServer(api.AuditRefusals(audit.NewLog(h.st, nil), api.Guard(tokens, routes)))
	h.t.Cleanup(srv.Close)
	return srv
}

// TestARefusalOfAnExpiredTokenIsAuditedUnderItsName is the second criterion of AUD1-DT-15 (#497): a call with a token that has expired
// is refused with 401, as before, and leaves an audit record of a failed authentication under the name of the token, with the word
// expired and when the token ended. The answer names no token. A call with a secret that no token has is still recorded as one of an
// actor that is unknown.
func TestARefusalOfAnExpiredTokenIsAuditedUnderItsName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	clk := &lifeClock{now: time.Now().UTC().Truncate(time.Second)}
	admin := clientOf(h.auditedLifeAPI(clk), h.admin)

	expires := clk.Now().Add(time.Hour)
	ci, err := admin.CreateTokenRequest(ctx, api.TokenRequest{Name: "ci", Role: rbac.Operator, Expires: expires})
	if err != nil {
		t.Fatal(err)
	}
	// Before its expiry the token works, and a call with it is no failed authentication
	if _, err := clientOf(h.auditedLifeAPI(clk), ci.Secret).Whoami(ctx); err != nil {
		t.Fatalf("the token before its expiry: %v", err)
	}

	clk.Advance(time.Hour)
	_, err = clientOf(h.auditedLifeAPI(clk), ci.Secret).Whoami(ctx)
	if httpStatus(err) != http.StatusUnauthorized || strings.Contains(err.Error(), `"ci"`) {
		t.Fatalf("a call with the expired token gave %v, want 401 that does not name the token", err)
	}
	if _, err := clientOf(h.auditedLifeAPI(clk), "ranz_NOTATOKENOFTHISCONTROLLER").Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with an unknown token gave %v, want 401", err)
	}

	recs := h.waitAudit(admin, "the two failed authentications", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.AuthFailed)) == 2 })
	failed := auditOfKind(recs, audit.AuthFailed)
	expired, unknown := failed[0], failed[1]
	if expired.Actor != audit.ActorToken("ci") || expired.Outcome != audit.Failure || expired.Source != "127.0.0.1" ||
		!strings.Contains(expired.Message, "expired") || !strings.Contains(expired.Message, `"ci"`) || !strings.Contains(expired.Message, expires.Format(time.RFC3339)) {
		t.Errorf("the record of the expired token is %+v, want a failure of token:ci from 127.0.0.1 that says the token expired, and when", expired)
	}
	if unknown.Actor != audit.ActorUnknown || unknown.Outcome != audit.Failure || !strings.Contains(unknown.Message, "is not a token of this controller") || strings.Contains(unknown.Message, "expired") {
		t.Errorf("the record of the unknown token is %+v, want a failure of an actor that is unknown, with no word of an expiry", unknown)
	}
	// The records of the actor of the token are the ones that it made, and this one
	only, err := h.client(h.admin).Audit(ctx, audit.Filter{Actor: audit.ActorToken("ci")})
	if err != nil || len(only.Records) != 1 || only.Records[0].Kind != audit.AuthFailed {
		t.Errorf("the audit log under token:ci holds %+v, %v, want the failed authentication alone", only.Records, err)
	}
}
