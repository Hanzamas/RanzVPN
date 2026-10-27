package api

import (
	"net/http"
	"path"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
)

// The reads that are audited (AUD1-DT-13, #461). A viewer reads nearly all that the API shows, and
// three of those reads are the ones whose trail matters (AP-8 of the threat model): who holds which role
// (the tokens), what happened (the audit log) and what the product may do (the licence). A read of one
// of them that succeeds is recorded as an audit.Access under the API token that made it, from the
// address that it came from, with the call as its action; the Log records it at most once a minute for
// each token and each of the three (audit.Log). A read that is refused or fails, a read of anything
// else and the query of a read are not recorded.
var auditedReads = []string{tokensPath, "/api/v1/audit", "/api/v1/licence"}

// auditRead serves the read r with h, and records it as an audit.Access through a when it is one of
// auditedReads and the call succeeded. The origin of the call is in the context of r (AuditCalls).
func auditRead(a Auditor, h http.Handler, w http.ResponseWriter, r *http.Request) {
	p := path.Clean("/" + r.URL.Path)
	if !slices.Contains(auditedReads, p) {
		h.ServeHTTP(w, r)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	h.ServeHTTP(sw, r)
	if code := sw.code(); code < 200 || code > 299 {
		return
	}
	_ = a.RecordAudit(r.Context(), audit.Record{Kind: audit.Access, Action: r.Method + " " + p, Outcome: audit.Success})
}
