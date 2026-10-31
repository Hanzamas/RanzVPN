package api

import (
	"context"
	"fmt"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The audit record of a call that the Guard refuses because its token has expired (AUD1-DT-15, #497). The answer of the Guard says
// when the token ended and not its name (AUD1-DT-13, #461), since it tells the holder of the secret no more than he has. The audit log
// names the tokens that act, and a leaked token that is tried after its expiry must show up there as that token and not as one that is
// unknown. A viewer reads the audit log (ADR-0030, ADR-0031), so it reads that name as it reads the name of any token that made a call
// that is recorded, though it cannot list the tokens (GET /api/v1/tokens is the admin's): AP-5 and AP-8 of docs/threat-model.md say so,
// and TestAViewerReadsTheNamesOfTheTokensInTheAuditLog holds it (AUD1-DT-15-R1, #561). AuditRefusals gives each call a note that the
// Guard fills in with the token, and records the refusal under it.

// refusalKey is the key of the refusalNote in the context of a call.
type refusalKey struct{}

// refusalNote is what the Guard tells AuditRefusals of a call that it refuses with 401 and that the answer does not say: the token
// whose secret it refused because the token has expired. It is empty for any other refusal.
type refusalNote struct {
	expired rbac.Token
}

// withRefusalNote returns ctx with a new refusalNote in it, and the note.
func withRefusalNote(ctx context.Context) (context.Context, *refusalNote) {
	n := &refusalNote{}
	return context.WithValue(ctx, refusalKey{}, n), n
}

// noteExpired tells AuditRefusals, when ctx has a refusalNote, that the Guard refused the secret of the token tok because it has
// expired. A Guard that no AuditRefusals stands in front of tells nothing.
func noteExpired(ctx context.Context, tok rbac.Token) {
	if n, ok := ctx.Value(refusalKey{}).(*refusalNote); ok {
		n.expired = tok
	}
}

// expiredMessage returns what the audit record of the refusal of the expired token tok says: its name, the word expired and when the
// token ended.
func expiredMessage(tok rbac.Token) string {
	return fmt.Sprintf("the bearer token %q expired at %s", tok.Name, tok.Expires.Format(time.RFC3339))
}
