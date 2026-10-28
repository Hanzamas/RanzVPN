package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The API roles of the users (SDN-32, #226): one row for each User that an admin gave a role of the
// API, viewer, operator or admin, which the user tokens of its logins carry (internal/rbac). A role
// says who may manage the controller, so it is not part of the intent, for the reasons that API
// tokens are not: an operator applies intent and must not grant himself admin, and a revision, a
// rollback or an import must not change who holds which role. A store backup holds them. The
// controller deletes the row of a User that a change of the intent removes, with its user tokens.
func init() {
	RegisterSchema("user_roles", `CREATE TABLE IF NOT EXISTS user_roles (name TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL)`)
}

// UserRole is the stored API role of a User: the name of the User and the name of its role.
type UserRole struct {
	Name string
	Role string
}

// UserRoles returns the API role of every User that holds one, ordered by the name of the User. A
// new store holds none.
func (s *Store) UserRoles(ctx context.Context) ([]UserRole, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, role FROM user_roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the API roles of users: %w", err)
	}
	out := []UserRole{}
	for qr.Next() {
		var r UserRole
		if err := qr.Scan(&r.Name, &r.Role); err != nil {
			return nil, fmt.Errorf("store: reading the API roles of users: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// UserRole returns the API role of the User name, and false when it holds none.
func (s *Store) UserRole(ctx context.Context, name string) (string, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT role FROM user_roles WHERE name = ?`, name))
	if err != nil {
		return "", false, fmt.Errorf("store: reading the API role of a user: %w", err)
	}
	if !qr.Next() {
		return "", false, nil
	}
	var role string
	if err := qr.Scan(&role); err != nil {
		return "", false, fmt.Errorf("store: reading the API role of a user: %w", err)
	}
	return role, true, nil
}

// SetUserRole stores role as the API role of the User name, in place of the one it held. The user
// tokens of the User carry the new role from their next call on.
func (s *Store) SetUserRole(ctx context.Context, name, role string) error {
	_, err := s.conn.WriteOneParameterizedContext(ctx, statement(`INSERT OR REPLACE INTO user_roles (name, role) VALUES (?, ?)`, name, role))
	if err != nil {
		return fmt.Errorf("store: writing the API role of a user: %w", err)
	}
	return nil
}

// DeleteUserRole deletes the API role of the User name and its user tokens, in one transaction. It
// reports false when the User held no role.
func (s *Store) DeleteUserRole(ctx context.Context, name string) (bool, error) {
	wrs, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM user_tokens WHERE name = ?`, name),
		statement(`DELETE FROM user_roles WHERE name = ?`, name),
	})
	if err != nil {
		return false, fmt.Errorf("store: deleting the API role of a user: %w", err)
	}
	return len(wrs) == 2 && wrs[1].RowsAffected > 0, nil
}

// DeleteUserRoles deletes the API roles and the user tokens of the users names, in one transaction. A
// user that has none is no error.
func (s *Store) DeleteUserRoles(ctx context.Context, names []string) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, name := range names {
		stmts = append(stmts, statement(`DELETE FROM user_tokens WHERE name = ?`, name), statement(`DELETE FROM user_roles WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the API roles of users: %w", err)
	}
	return nil
}
