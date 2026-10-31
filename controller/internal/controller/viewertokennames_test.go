// Controller conformance for what a viewer reads of the API tokens in the audit log (AUD1-DT-15-R1, #561), with the harness of
// conformance_test.go and the audited API of expiredaudit_test.go.
package controller_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestAViewerReadsTheNamesOfTheTokensInTheAuditLog is the second criterion of AUD1-DT-15-R1 (#561). The audit log names the API tokens:
// each call that changes something is recorded under token:NAME, and since AUD1-DT-15 (#497) so is a call with the secret of a token
// after its expiry. GET /api/v1/audit needs the role viewer, and ADR-0030 and ADR-0031 keep it so, so a viewer reads the name of a token
// that has expired, and that no record held before its secret was tried, while it cannot list the tokens (403). The decision is to say
// so, in AP-5 and AP-8 of docs/threat-model.md, and not to hide the names from a viewer, which would be a rule in the Guard that no ADR
// has; this test holds what the pages say, and the docs test of controller/cmd/ranz holds the pages.
func TestAViewerReadsTheNamesOfTheTokensInTheAuditLog(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	clk := &lifeClock{now: time.Now().UTC().Truncate(time.Second)}
	admin := clientOf(h.auditedLifeAPI(clk), h.admin)

	// The token leaked only reads, and makes no record of its own: its name is in no record until its secret is tried after its end
	leaked, err := admin.CreateTokenRequest(ctx, api.TokenRequest{Name: "leaked", Role: rbac.Viewer, Expires: clk.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := admin.CreateToken(ctx, "reader", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	// The viewer reads through the API of the harness, which has no audit log on it, so a read of the log makes no record
	viewer := h.client(reader.Secret)
	if before, err := viewer.Audit(ctx, audit.Filter{Actor: audit.ActorToken("leaked")}); err != nil || len(before.Records) != 0 {
		t.Fatalf("the audit log holds %+v (%v) under token:leaked before its secret is tried, want nothing", before.Records, err)
	}

	clk.Advance(time.Hour)
	if _, err := clientOf(h.auditedLifeAPI(clk), leaked.Secret).Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with the token that expired gave %v, want 401", err)
	}
	recs := h.waitAudit(viewer, "the refusal of the token that expired, and the two tokens that the admin made", func(rs []audit.Record) bool {
		return len(auditOfKind(rs, audit.AuthFailed)) == 1 && len(operationsBy(rs, audit.ActorToken(rbac.FirstAdmin))) >= 2
	})

	// The viewer reads the name of the token, that it expired, when, and where the call came from
	expired := auditOfKind(recs, audit.AuthFailed)[0]
	if expired.Actor != audit.ActorToken("leaked") || expired.Outcome != audit.Failure || expired.Source != "127.0.0.1" ||
		!strings.Contains(expired.Message, `"leaked"`) || !strings.Contains(expired.Message, "expired") || !strings.Contains(expired.Message, clk.Now().Format(time.RFC3339)) {
		t.Errorf("a viewer reads %+v, want a failed authentication of token:leaked from 127.0.0.1 that says the token expired, and when", expired)
	}
	// It may look for the name as for any actor of the log
	only, err := viewer.Audit(ctx, audit.Filter{Actor: audit.ActorToken("leaked")})
	if err != nil || len(only.Records) != 1 || only.Records[0].ID != expired.ID {
		t.Errorf("a viewer that filters the audit log by token:leaked reads %+v (%v), want the failed authentication alone", only.Records, err)
	}
	// It reads the name of the token that acted, too, as it always did: the admin made the two tokens
	for _, r := range operationsBy(recs, audit.ActorToken(rbac.FirstAdmin)) {
		if r.Action != "POST /api/v1/tokens" || r.Outcome != audit.Success {
			t.Errorf("a viewer reads the operation %+v of the admin, want the creation of one of the two tokens", r)
		}
	}

	// What stays the admin's is the list of the tokens
	if _, err := viewer.Tokens(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer that lists the tokens gave %v, want 403: the names are in the audit log, and the list is the admin's", err)
	}
	if listed, err := admin.Tokens(ctx); err != nil || len(listed) != 3 {
		t.Errorf("the admin lists %+v (%v), want the three tokens admin, leaked and reader", listed, err)
	}
}
