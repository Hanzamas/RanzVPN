package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

func init() {
	RegisterSchema("api_tokens",
		`CREATE TABLE IF NOT EXISTS api_tokens (name TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)`,
		// The life of a token (AUD1-DT-13, #461) is a table of its own: a store of an older release, and a
		// backup of one, holds api_tokens without these columns, and nothing in the store alters a table
		// that exists. A token with no row here never expires and was never used; the times are Unix
		// seconds, 0 for none.
		`CREATE TABLE IF NOT EXISTS api_token_life (name TEXT NOT NULL PRIMARY KEY, expires INTEGER NOT NULL DEFAULT 0, last_used INTEGER NOT NULL DEFAULT 0)`)
}

// Token is a stored API token (internal/rbac): its name, its role, the hash of its secret and its
// life. The secret itself is never stored.
type Token struct {
	Name string
	Role string
	Hash string
	// Expires is the instant from which the token is refused, the zero time for a token that never
	// expires. LastUsed is the instant of the last use that was stored, to the second, the zero time
	// for a token that was never used.
	Expires  time.Time
	LastUsed time.Time
}

// selectToken reads the tokens with their life: the columns that scanToken scans.
const selectToken = `SELECT t.name, t.role, t.hash, COALESCE(l.expires, 0), COALESCE(l.last_used, 0) FROM api_tokens t LEFT JOIN api_token_life l ON l.name = t.name`

// Tokens returns every token, ordered by name.
func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	qr, err := s.conn.QueryOneContext(ctx, selectToken+` ORDER BY t.name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the tokens: %w", err)
	}
	var ts []Token
	for qr.Next() {
		t, err := scanToken(&qr)
		if err != nil {
			return nil, fmt.Errorf("store: reading the tokens: %w", err)
		}
		ts = append(ts, t)
	}
	return ts, nil
}

// TokenByHash returns the token whose secret has the hash hash, and false if there is none.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(selectToken+` WHERE t.hash = ?`, hash))
	if err != nil {
		return Token{}, false, fmt.Errorf("store: reading a token: %w", err)
	}
	if !qr.Next() {
		return Token{}, false, nil
	}
	t, err := scanToken(&qr)
	if err != nil {
		return Token{}, false, fmt.Errorf("store: reading a token: %w", err)
	}
	return t, true, nil
}

// scanToken scans the current row of a read of selectToken.
func scanToken(qr *gorqlite.QueryResult) (Token, error) {
	var t Token
	var expires, lastUsed int64
	if err := qr.Scan(&t.Name, &t.Role, &t.Hash, &expires, &lastUsed); err != nil {
		return Token{}, err
	}
	t.Expires, t.LastUsed = fromUnix(expires), fromUnix(lastUsed)
	return t, nil
}

// fromUnix returns the time of the Unix seconds sec, in UTC, and the zero time for 0.
func fromUnix(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// toUnix returns the Unix seconds of t, and 0 for the zero time.
func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// AddToken stores t, with its expiry when it has one, in one transaction. It reports false, and
// stores nothing, when a token of that name exists.
func (s *Store) AddToken(ctx context.Context, t Token) (bool, error) {
	stmts := []gorqlite.ParameterizedStatement{
		statement(`INSERT OR IGNORE INTO api_tokens (name, role, hash) VALUES (?, ?, ?)`, t.Name, t.Role, t.Hash),
	}
	if !t.Expires.IsZero() {
		// Only when the token above was stored: the one that holds the name keeps the life it has
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO api_token_life (name, expires) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM api_tokens WHERE name = ? AND hash = ?)`,
			t.Name, toUnix(t.Expires), t.Name, t.Hash))
	}
	return s.writeToken(ctx, stmts...)
}

// AddFirstToken stores t only when the store holds no token at all, in one statement, so of
// controllers that start together on one store only one adds it. It reports whether it did.
func (s *Store) AddFirstToken(ctx context.Context, t Token) (bool, error) {
	return s.writeToken(ctx, statement(`INSERT INTO api_tokens (name, role, hash) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM api_tokens)`,
		t.Name, t.Role, t.Hash))
}

// DeleteToken deletes the token name, unless that takes the last token of the role keep that has
// not expired at the instant now (keepsRole), in one statement, so two deletes at once cannot both
// pass the check, and its life with it. An empty keep keeps nothing. It reports false, and deletes
// nothing, when there is no such token or it is the last one of keep.
func (s *Store) DeleteToken(ctx context.Context, name, keep string, now time.Time) (bool, error) {
	cond, args := keepsRole(name, keep, now)
	return s.writeToken(ctx,
		statement(`DELETE FROM api_tokens WHERE name = ? AND (`+cond+`)`, append([]any{name}, args...)...),
		// In the same transaction: the life goes when the token is gone, and stays when the delete was refused
		statement(`DELETE FROM api_token_life WHERE name = ? AND NOT EXISTS (SELECT 1 FROM api_tokens WHERE name = ?)`, name, name))
}

// TouchToken stores at as the last use of the token whose secret has the hash hash. A use that is
// less than interval after the one stored is not stored, in the same statement, so members of a
// controller cluster that touch the same token at once change the row once, and the hash of a
// token that was deleted meanwhile makes no row.
func (s *Store) TouchToken(ctx context.Context, hash string, at time.Time, interval time.Duration) error {
	_, err := s.writeToken(ctx, statement(`INSERT INTO api_token_life (name, last_used) SELECT name, ? FROM api_tokens WHERE hash = ? `+
		`ON CONFLICT (name) DO UPDATE SET last_used = excluded.last_used WHERE excluded.last_used >= last_used + ?`,
		at.Unix(), hash, int64(interval/time.Second)))
	return err
}

// writeToken runs the statements of one write of the tokens in one transaction and reports whether
// the first changed a row.
func (s *Store) writeToken(ctx context.Context, stmts ...gorqlite.ParameterizedStatement) (bool, error) {
	wrs, err := s.conn.WriteParameterizedContext(ctx, stmts)
	if err != nil {
		return false, fmt.Errorf("store: writing a token: %w", err)
	}
	return len(wrs) > 0 && wrs[0].RowsAffected > 0, nil
}
