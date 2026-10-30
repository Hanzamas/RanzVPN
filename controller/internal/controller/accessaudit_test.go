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

// TestAViewerThatReadsWithGetAndHeadLeavesOneAccessRecordForEachRead is the third criterion of AUD1-DT-19 (#506): a
// HEAD is the same read as a GET for the audit of access, so a viewer that reads the audit log with both, and the
// licence the same way, leaves one access record a minute for each of the two reads, and not one for each method.
func TestAViewerThatReadsWithGetAndHeadLeavesOneAccessRecordForEachRead(t *testing.T) {
	h := newAuditHarness(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)
	admin := h.auditedAPI(h.admin)
	viewer := h.auditedAPI(h.token("viewer-1", rbac.Viewer))

	// head sends a HEAD of path with the token of the viewer, as a client does that only asks whether a read works
	head := func(path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, viewer.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+viewer.Token)
		resp, err := viewer.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a HEAD of %s gave %s, want 200", path, resp.Status)
		}
	}
	// Twice, within the minute: the audit log with a GET and then a HEAD, the licence with a HEAD and then a GET
	for range 2 {
		if _, err := viewer.Audit(ctx, audit.Filter{}); err != nil {
			t.Fatal(err)
		}
		head("/api/v1/audit")
		head("/api/v1/licence")
		if _, err := viewer.Licence(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A call that changes something is recorded after them, so the records of the reads are in the log by the time
	// it is
	if _, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 90, MaxRecords: 100000}); err != nil {
		t.Fatal(err)
	}

	recs := h.waitAudit(admin, "the retention", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Operation)) >= 1 })
	// The first read of each thing is the one that is recorded, whichever method it had
	want := []string{"GET /api/v1/audit", "HEAD /api/v1/licence"}
	accesses := auditOfKind(recs, audit.Access)
	if len(accesses) != len(want) {
		t.Fatalf("the audit log holds %d accesses, want the %d reads of the viewer, once each:\n%s", len(accesses), len(want), auditLines(recs))
	}
	byAction := map[string]audit.Record{}
	for _, r := range accesses {
		byAction[r.Action] = r
	}
	for _, action := range want {
		r, ok := byAction[action]
		if !ok {
			t.Errorf("the audit log has no access of %s to %s:\n%s", audit.ActorToken("viewer-1"), action, auditLines(recs))
			continue
		}
		checkAuditRecord(t, r, since, audit.ActorToken("viewer-1"), "127.0.0.1", audit.Success, action, 0)
	}
}

// TestAReadWithAUserTokenLeavesAnAccessRecordUnderTheUser: a read with a user token (SDN-32, #226) is an
// access of its User, user:NAME, as every call of the token is, and the user token of an admin reads the
// API roles of users too, which sit under the tokens. A user token has an end of its own, so the life of
// an API token (this ticket) does not touch it: it is no entry of the list of the tokens.
func TestAReadWithAUserTokenLeavesAnAccessRecordUnderTheUser(t *testing.T) {
	e := newLoginEnv(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)
	if _, err := e.h.api.SetUserRole(ctx, "alice", rbac.Admin); err != nil {
		t.Fatal(err)
	}
	in, err := e.client.SignIn(ctx, "alice", alicePassword)
	if err != nil {
		t.Fatal(err)
	}
	alice := e.caller(in.Secret)

	// The four reads that are audited, and two that are not
	if _, err := alice.Tokens(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.UserRoles(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Audit(ctx, audit.Filter{Kind: audit.Login}); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Licence(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Whoami(ctx); err != nil {
		t.Fatal(err)
	}

	want := []string{"GET /api/v1/tokens", "GET /api/v1/tokens/users", "GET /api/v1/audit", "GET /api/v1/licence"}
	recs := e.h.waitAudit(e.h.api, "the four accesses of alice", func(rs []audit.Record) bool {
		return len(auditOfKind(rs, audit.Access)) >= len(want)
	})
	accesses := auditOfKind(recs, audit.Access)
	if len(accesses) != len(want) {
		t.Fatalf("the audit log holds %d accesses, want the %d reads of alice, once each:\n%s", len(accesses), len(want), auditLines(recs))
	}
	byAction := map[string]audit.Record{}
	for _, r := range accesses {
		byAction[r.Action] = r
	}
	for _, action := range want {
		r, ok := byAction[action]
		if !ok {
			t.Errorf("the audit log has no access of %s to %s:\n%s", audit.ActorUser("alice"), action, auditLines(recs))
			continue
		}
		checkAuditRecord(t, r, since, audit.ActorUser("alice"), "127.0.0.1", audit.Success, action, 0)
	}

	// The list of the tokens holds API tokens only
	toks, err := e.h.api.Tokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range toks {
		if tok.User != "" {
			t.Errorf("the list of the tokens holds the user token %+v, want API tokens only", tok)
		}
	}
}
