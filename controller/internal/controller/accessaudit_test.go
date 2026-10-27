// Controller conformance for the audit of reads (AUD1-DT-13, #461), with the harness of
// conformance_test.go and the audited API of audit_test.go: a read of the API tokens, the audit log or
// the licence leaves an access record under the name of the token that made it, and no other read, no
// read that was refused and no read that repeats one of the minute before does.
package controller_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestAReadOfTheTokensTheAuditLogOrTheLicenceLeavesAnAccessRecord is the fourth criterion of AUD1-DT-13
// (#461).
func TestAReadOfTheTokensTheAuditLogOrTheLicenceLeavesAnAccessRecord(t *testing.T) {
	h := newAuditHarness(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)
	admin := h.auditedAPI(h.admin)
	viewer := h.auditedAPI(h.token("viewer-1", rbac.Viewer))

	// The admin reads the three; the viewer reads the audit log and the licence, and is refused the tokens
	if _, err := admin.Tokens(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Audit(ctx, audit.Filter{}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Licence(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Audit(ctx, audit.Filter{Kind: audit.Login}); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Licence(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Tokens(ctx); httpStatus(err) != http.StatusForbidden {
		t.Fatalf("a viewer read the tokens: %v, want 403", err)
	}
	// What else a viewer may read is no access
	if _, err := admin.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Whoami(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Nodes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Resources(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Events(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.AuditRetention(ctx); err != nil {
		t.Fatal(err)
	}
	// The same reads again, within the minute, are the same accesses
	if _, err := admin.Tokens(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Licence(ctx); err != nil {
		t.Fatal(err)
	}
	// A call that changes something is recorded after them, so the records of the reads are in the log
	// by the time it is
	if _, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 90, MaxRecords: 100000}); err != nil {
		t.Fatal(err)
	}

	recs := h.waitAudit(admin, "the five accesses and the retention", func(rs []audit.Record) bool {
		return len(auditOfKind(rs, audit.Access)) >= 5 && len(auditOfKind(rs, audit.Operation)) >= 1
	})
	accesses := auditOfKind(recs, audit.Access)
	want := []struct{ actor, action string }{
		{audit.ActorToken(rbac.FirstAdmin), "GET /api/v1/tokens"},
		{audit.ActorToken(rbac.FirstAdmin), "GET /api/v1/audit"},
		{audit.ActorToken(rbac.FirstAdmin), "GET /api/v1/licence"},
		{audit.ActorToken("viewer-1"), "GET /api/v1/audit"},
		{audit.ActorToken("viewer-1"), "GET /api/v1/licence"},
	}
	if len(accesses) != len(want) {
		t.Fatalf("the audit log holds %d accesses, want the %d reads of the minute, once each:\n%s", len(accesses), len(want), auditLines(recs))
	}
	// The records of two calls in a row are written as the calls end, so they are found by what they say
	byRead := map[string]audit.Record{}
	for _, r := range accesses {
		byRead[r.Actor+" "+r.Action] = r
	}
	for _, w := range want {
		r, ok := byRead[w.actor+" "+w.action]
		if !ok {
			t.Errorf("the audit log has no access of %s to %s:\n%s", w.actor, w.action, auditLines(recs))
			continue
		}
		checkAuditRecord(t, r, since, w.actor, "127.0.0.1", audit.Success, w.action, 0)
	}

	// ranz get audit -kind access lists them
	listed, err := h.client(h.admin).Audit(ctx, audit.Filter{Kind: audit.Access})
	if err != nil || len(listed.Records) != len(want) {
		t.Errorf("a listing of the kind %s gave %+v, %v, want the %d accesses", audit.Access, listed.Records, err, len(want))
	}
}
