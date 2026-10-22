package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// Token is a stored API token (internal/rbac): its name, its role and the hash of its secret.
// The secret itself is never stored.
type Token struct {
	Name string
	Role string
	Hash string
}

// Tokens returns every token, ordered by name.
func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, role, hash FROM api_tokens ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the tokens: %w", err)
	}
	var ts []Token
	for qr.Next() {
		var t Token
		if err := qr.Scan(&t.Name, &t.Role, &t.Hash); err != nil {
			return nil, fmt.Errorf("store: reading the tokens: %w", err)
		}
		ts = append(ts, t)
	}
	return ts, nil
}

// TokenByHash returns the token whose secret has the hash hash, and false if there is none.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT name, role, hash FROM api_tokens WHERE hash = ?`, hash))
	if err != nil {
		return Token{}, false, fmt.Errorf("store: reading a token: %w", err)
	}
	if !qr.Next() {
		return Token{}, false, nil
	}
	var t Token
	if err := qr.Scan(&t.Name, &t.Role, &t.Hash); err != nil {
		return Token{}, false, fmt.Errorf("store: reading a token: %w", err)
	}
	return t, true, nil
}

// AddToken stores t. It reports false, and stores nothing, when a token of that name exists.
func (s *Store) AddToken(ctx context.Context, t Token) (bool, error) {
	return s.writeToken(ctx, statement(`INSERT OR IGNORE INTO api_tokens (name, role, hash) VALUES (?, ?, ?)`, t.Name, t.Role, t.Hash))
}

// AddFirstToken stores t only when the store holds no token at all, in one statement, so of
// controllers that start together on one store only one adds it. It reports whether it did.
func (s *Store) AddFirstToken(ctx context.Context, t Token) (bool, error) {
	return s.writeToken(ctx, statement(`INSERT INTO api_tokens (name, role, hash) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM api_tokens)`,
		t.Name, t.Role, t.Hash))
}

// DeleteToken deletes the token name, unless it is the last token of the role keep, in one
// statement, so two deletes at once cannot both pass the check. An empty keep keeps nothing. It
// reports false, and deletes nothing, when there is no such token or it is the last one of keep.
func (s *Store) DeleteToken(ctx context.Context, name, keep string) (bool, error) {
	return s.writeToken(ctx, statement(`DELETE FROM api_tokens WHERE name = ? AND (role != ? OR (SELECT COUNT(*) FROM api_tokens WHERE role = ?) > 1)`,
		name, keep, keep))
}

// writeToken runs one write of the tokens and reports whether it changed a row.
func (s *Store) writeToken(ctx context.Context, st gorqlite.ParameterizedStatement) (bool, error) {
	wr, err := s.conn.WriteOneParameterizedContext(ctx, st)
	if err != nil {
		return false, fmt.Errorf("store: writing a token: %w", err)
	}
	return wr.RowsAffected > 0, nil
}
