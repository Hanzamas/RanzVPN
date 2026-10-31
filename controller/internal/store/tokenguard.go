package store

import "time"

// The last-admin guard of the API tokens (AUD1-DT-15, #497). The controller keeps one API token that holds the role keep, which is
// admin, so that someone may manage the tokens. The secret of a token that has expired is refused, so the token that the controller
// keeps must be one that has not expired: a store with the token admin and the expired token ops would otherwise let an admin delete
// admin, and leave no token that works. A statement that deletes a token, or takes its role away, carries the condition that
// keepsRole returns, so two changes at once cannot both pass it.

// keepsRole returns the condition, and its parameters in the order of the question marks in it, that holds for the token name when
// a change of it leaves the controller a token that holds the role keep and has not expired at the instant now. It holds when the
// token does not hold the role, since the guard counts no other token; when another token holds the role and has not expired, which
// is the one that stays; and when the token has expired itself and another token holds the role, expired or not, since the change
// then takes nothing that works from the controller, and the last token with the role is kept as it always was. A token with no row
// in api_token_life, and one whose expiry is 0, never expires; one has expired from its expiry on, as Token.ExpiredAt of
// internal/rbac says. The condition names the columns role and name of the table api_tokens, so it belongs in a statement on that
// table.
func keepsRole(name, keep string, now time.Time) (string, []any) {
	const cond = `(role != ? OR ` +
		`(SELECT COUNT(*) FROM api_tokens t LEFT JOIN api_token_life l ON l.name = t.name WHERE t.name != ? AND t.role = ? AND (l.expires IS NULL OR l.expires = 0 OR l.expires > ?)) > 0 OR ` +
		`(EXISTS (SELECT 1 FROM api_token_life WHERE name = ? AND expires != 0 AND expires <= ?) AND EXISTS (SELECT 1 FROM api_tokens WHERE name != ? AND role = ?)))`
	at := now.Unix()
	return cond, []any{keep, name, keep, at, name, at, name, keep}
}
