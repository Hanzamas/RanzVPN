package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The tokens of the self scope (SDN-58, #251): one row for each bearer secret that a login for the portal gave
// a User, with the name of the User and the end of the token, and the SHA-256 of the secret, never the secret
// itself (internal/rbac). It is a table of its own and not a column of user_tokens, which holds the tokens of an
// API role and joins them to the role of their User: a token of the self scope holds no role and keeps the scope
// it was made with. Every member of a controller cluster reads them, as it reads the API tokens. A store backup
// holds them. The rows of a User end with its user tokens: DeleteUserTokens, EndUserTokens and DeleteUserRoles
// (usertokens.go, userroles.go) reach this table too.
func init() {
	RegisterSchema("self_tokens", `CREATE TABLE IF NOT EXISTS self_tokens (hash TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, expires INTEGER NOT NULL)`)
}

// AddSelfToken stores t, a token of the self scope, and removes the ones that ended before now, in one
// transaction. The Hash, Name and Expires of t are the hash of the secret, the name of the User and the end.
func (s *Store) AddSelfToken(ctx context.Context, t UserToken, now time.Time) error {
	_, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM self_tokens WHERE expires <= ?`, now.UnixMilli()),
		statement(`INSERT INTO self_tokens (hash, name, expires) VALUES (?, ?, ?)`, t.Hash, t.Name, t.Expires.UnixMilli()),
	})
	if err != nil {
		return fmt.Errorf("store: writing a token of the self scope: %w", err)
	}
	return nil
}

// SelfTokenByHash returns the name of the User of the token of the self scope whose secret has the hash hash,
// when the token has not ended at now. It reports false otherwise.
func (s *Store) SelfTokenByHash(ctx context.Context, hash string, now time.Time) (string, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT name FROM self_tokens WHERE hash = ? AND expires > ?`, hash, now.UnixMilli()))
	if err != nil {
		return "", false, fmt.Errorf("store: reading a token of the self scope: %w", err)
	}
	if !qr.Next() {
		return "", false, nil
	}
	var name string
	if err := qr.Scan(&name); err != nil {
		return "", false, fmt.Errorf("store: reading a token of the self scope: %w", err)
	}
	return name, true, nil
}

// DeleteSelfToken deletes the token of the self scope whose secret has the hash hash and returns the name of
// its User; it reports false when there is none.
func (s *Store) DeleteSelfToken(ctx context.Context, hash string) (string, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT name FROM self_tokens WHERE hash = ?`, hash))
	if err != nil {
		return "", false, fmt.Errorf("store: reading a token of the self scope: %w", err)
	}
	if !qr.Next() {
		return "", false, nil
	}
	var name string
	if err := qr.Scan(&name); err != nil {
		return "", false, fmt.Errorf("store: reading a token of the self scope: %w", err)
	}
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(`DELETE FROM self_tokens WHERE hash = ?`, hash))
	if err != nil {
		return "", false, fmt.Errorf("store: deleting a token of the self scope: %w", err)
	}
	return name, wr.RowsAffected > 0, nil
}
