package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The delegations of the Networks (SDN-38, #231): one row for each Network whose scoped roles an admin bound by
// quotas and permissions (internal/scope), with the JSON of the delegation, so that a quota or a permission that a
// later ticket adds is a field of the JSON and no change of the table. It is not part of the intent, for the
// reasons that API tokens are not: a role that the intent could change would change its own limits, and a
// revision, a rollback or an import must not give a scoped role more. A store backup holds them. The controller
// deletes the row of a Network that a change of the intent removes, with the roles that were held for it
// (DeleteScopedAccess).
func init() {
	RegisterSchema("scope_delegations", `CREATE TABLE IF NOT EXISTS scope_delegations (network TEXT NOT NULL PRIMARY KEY, spec TEXT NOT NULL)`)
}

// Delegation is a stored delegation: the name of its Network and the JSON of its quotas and permissions.
type Delegation struct {
	Network string
	Spec    string
}

// Delegations returns every delegation, ordered by the name of the Network. A new store holds none.
func (s *Store) Delegations(ctx context.Context) ([]Delegation, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT network, spec FROM scope_delegations ORDER BY network`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the delegations of the Networks: %w", err)
	}
	out := []Delegation{}
	for qr.Next() {
		var d Delegation
		if err := qr.Scan(&d.Network, &d.Spec); err != nil {
			return nil, fmt.Errorf("store: reading the delegations of the Networks: %w", err)
		}
		out = append(out, d)
	}
	return out, nil
}

// PutDelegation stores d in place of the delegation that its Network had.
func (s *Store) PutDelegation(ctx context.Context, d Delegation) error {
	if err := s.write(ctx, []gorqlite.ParameterizedStatement{
		statement(`INSERT OR REPLACE INTO scope_delegations (network, spec) VALUES (?, ?)`, d.Network, d.Spec),
	}); err != nil {
		return fmt.Errorf("store: writing the delegation of a Network: %w", err)
	}
	return nil
}

// DeleteDelegation deletes the delegation of the Network network. A Network that has none is no error.
func (s *Store) DeleteDelegation(ctx context.Context, network string) error {
	if err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`DELETE FROM scope_delegations WHERE network = ?`, network)}); err != nil {
		return fmt.Errorf("store: deleting the delegation of a Network: %w", err)
	}
	return nil
}

// DeleteScopedAccess deletes what holds a role for the Network network, which the intent no longer has, and the
// delegation of the Network, in one transaction: the API tokens and the API roles of users that are held for it
// (the stored role ends in @ and the Network), with the user tokens of those users, the user tokens that carry
// such a role (user_token_grants), and the provider groups that map to it. A Network that a new one of the same
// name replaces thus starts with no scoped role and no delegation of its predecessor.
func (s *Store) DeleteScopedAccess(ctx context.Context, network string) error {
	const scoped = `instr(role, '@') > 0 AND substr(role, instr(role, '@') + 1) = ?`
	err := s.write(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM api_token_life WHERE name IN (SELECT name FROM api_tokens WHERE `+scoped+`)`, network),
		statement(`DELETE FROM api_tokens WHERE `+scoped, network),
		statement(`DELETE FROM user_tokens WHERE name IN (SELECT name FROM user_roles WHERE `+scoped+`) OR hash IN (SELECT hash FROM user_token_grants WHERE `+scoped+`)`, network, network),
		statement(`DELETE FROM user_token_grants WHERE `+scoped, network),
		statement(`DELETE FROM user_roles WHERE `+scoped, network),
		statement(`DELETE FROM provider_groups WHERE `+scoped, network),
		statement(`DELETE FROM scope_delegations WHERE network = ?`, network),
	})
	if err != nil {
		return fmt.Errorf("store: deleting what was held for a Network: %w", err)
	}
	return nil
}
