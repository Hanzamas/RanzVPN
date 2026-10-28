package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The user tokens (SDN-32, #226): one row for each bearer secret that a login of a User gave it for the
// API, with the name of the User and the end of the token, and the SHA-256 of the secret, never the
// secret itself (internal/rbac). A token carries the API role that the User holds when it is used
// (user_roles), so a token of a User whose role an admin took away, or whose row expired, authenticates
// nothing. Every member of a controller cluster reads them, as it reads the API tokens. A store backup
// holds them.
func init() {
	RegisterSchema("user_tokens", `CREATE TABLE IF NOT EXISTS user_tokens (hash TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, expires INTEGER NOT NULL)`)
}

// UserToken is a stored user token: the hash of its secret, the name of its User and its end.
type UserToken struct {
	Hash    string
	Name    string
	Expires time.Time
}

// AddUserToken stores t when its User holds an API role, and removes the user tokens that ended before
// now, in one transaction. It reports false, and stores nothing, when the User holds no role.
func (s *Store) AddUserToken(ctx context.Context, t UserToken, now time.Time) (bool, error) {
	wrs, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM user_tokens WHERE expires <= ?`, now.UnixMilli()),
		statement(`INSERT INTO user_tokens (hash, name, expires) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM user_roles WHERE name = ?)`,
			t.Hash, t.Name, t.Expires.UnixMilli(), t.Name),
	})
	if err != nil {
		return false, fmt.Errorf("store: writing a user token: %w", err)
	}
	return len(wrs) == 2 && wrs[1].RowsAffected > 0, nil
}

// UserTokenByHash returns the name of the User of the user token whose secret has the hash hash, and
// the API role that the User holds, when the token has not ended at now and the User holds a role. It
// reports false otherwise.
func (s *Store) UserTokenByHash(ctx context.Context, hash string, now time.Time) (name, role string, ok bool, err error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(
		`SELECT t.name, r.role FROM user_tokens t JOIN user_roles r ON r.name = t.name WHERE t.hash = ? AND t.expires > ?`, hash, now.UnixMilli()))
	if err != nil {
		return "", "", false, fmt.Errorf("store: reading a user token: %w", err)
	}
	if !qr.Next() {
		return "", "", false, nil
	}
	if err := qr.Scan(&name, &role); err != nil {
		return "", "", false, fmt.Errorf("store: reading a user token: %w", err)
	}
	return name, role, true, nil
}

// DeleteUserToken deletes the user token whose secret has the hash hash and returns the name of its
// User; it reports false when there is none.
func (s *Store) DeleteUserToken(ctx context.Context, hash string) (string, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT name FROM user_tokens WHERE hash = ?`, hash))
	if err != nil {
		return "", false, fmt.Errorf("store: reading a user token: %w", err)
	}
	if !qr.Next() {
		return "", false, nil
	}
	var name string
	if err := qr.Scan(&name); err != nil {
		return "", false, fmt.Errorf("store: reading a user token: %w", err)
	}
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(`DELETE FROM user_tokens WHERE hash = ?`, hash))
	if err != nil {
		return "", false, fmt.Errorf("store: deleting a user token: %w", err)
	}
	return name, wr.RowsAffected > 0, nil
}

// DeleteUserTokens deletes every user token of the users names, in one transaction. A user that has
// none is no error.
func (s *Store) DeleteUserTokens(ctx context.Context, names []string) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, name := range names {
		stmts = append(stmts, statement(`DELETE FROM user_tokens WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the user tokens of users: %w", err)
	}
	return nil
}

// EndUserTokens makes every user token of the User name that would end after until end at until: the
// User expires then (intent.User.Expires), and a token never outlives its User.
func (s *Store) EndUserTokens(ctx context.Context, name string, until time.Time) error {
	ms := until.UnixMilli()
	if err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`UPDATE user_tokens SET expires = ? WHERE name = ? AND expires > ?`, ms, name, ms)}); err != nil {
		return fmt.Errorf("store: ending the user tokens of a user: %w", err)
	}
	return nil
}
