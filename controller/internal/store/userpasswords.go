package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The passwords of the users of the controller (SDN-31, #225): one row for each User that has one,
// with the name of the User and the stored form of its PBKDF2 hash (internal/password), never the
// password. They are not part of the intent, so that nobody who reads the intent, an export of it or
// a revision holds a hash, and a rollback or an import never changes one; a store backup holds them.
// The controller deletes the row of a User that a change of the intent removes
// (internal/controller, users.go).
func init() {
	RegisterSchema("user_passwords", `CREATE TABLE IF NOT EXISTS user_passwords (name TEXT NOT NULL PRIMARY KEY, hash TEXT NOT NULL)`)
}

// UserPassword returns the stored hash of the password of the user name, and false when the user has
// none.
func (s *Store) UserPassword(ctx context.Context, name string) (string, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT hash FROM user_passwords WHERE name = ?`, name))
	if err != nil {
		return "", false, fmt.Errorf("store: reading the password of a user: %w", err)
	}
	if !qr.Next() {
		return "", false, nil
	}
	var hash string
	if err := qr.Scan(&hash); err != nil {
		return "", false, fmt.Errorf("store: reading the password of a user: %w", err)
	}
	return hash, true, nil
}

// UsersWithPassword returns the names of the users that have a password, ordered.
func (s *Store) UsersWithPassword(ctx context.Context) ([]string, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name FROM user_passwords ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the users that have a password: %w", err)
	}
	out := []string{}
	for qr.Next() {
		var name string
		if err := qr.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: reading the users that have a password: %w", err)
		}
		out = append(out, name)
	}
	return out, nil
}

// SetUserPassword stores hash as the password hash of the user name, in place of the one it had.
func (s *Store) SetUserPassword(ctx context.Context, name, hash string) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO user_passwords (name, hash) VALUES (?, ?)`, name, hash)})
	if err != nil {
		return fmt.Errorf("store: writing the password of a user: %w", err)
	}
	return nil
}

// DeleteUserPasswords deletes the passwords of the users names, in one transaction. A user that has
// none is no error.
func (s *Store) DeleteUserPasswords(ctx context.Context, names []string) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, name := range names {
		stmts = append(stmts, statement(`DELETE FROM user_passwords WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the passwords of users: %w", err)
	}
	return nil
}
