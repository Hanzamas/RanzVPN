package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The provider groups (SDN-38, #231): the groups of an identity provider that an admin mapped to a role of the
// API, global or scoped to one Network (internal/rbac), one row for each provider and group, with the stored
// form of the role. A login through a provider gives the User a user token that carries the role of its groups
// (user_token_grants, one row for each such token), fixed when the token is made, so a change of the groups, or
// of the mapping, takes effect at the next login and no later than the end of the token. They are no part of
// the intent: a mapping says who may manage the controller, as an API role does. A store backup holds them.
func init() {
	RegisterSchema("provider_groups",
		`CREATE TABLE IF NOT EXISTS provider_groups (provider TEXT NOT NULL, group_name TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (provider, group_name))`,
		`CREATE TABLE IF NOT EXISTS user_token_grants (hash TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL)`)
}

// ProviderGroup is a stored mapping: the provider, one of its groups as the provider names it, and the stored
// form of the role that the members of the group get.
type ProviderGroup struct {
	Provider string
	Group    string
	Role     string
}

// ProviderGroups returns every mapping, ordered by provider and group. A new store holds none.
func (s *Store) ProviderGroups(ctx context.Context) ([]ProviderGroup, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT provider, group_name, role FROM provider_groups ORDER BY provider, group_name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the provider groups: %w", err)
	}
	out := []ProviderGroup{}
	for qr.Next() {
		var g ProviderGroup
		if err := qr.Scan(&g.Provider, &g.Group, &g.Role); err != nil {
			return nil, fmt.Errorf("store: reading the provider groups: %w", err)
		}
		out = append(out, g)
	}
	return out, nil
}

// SetProviderGroup stores g in place of the mapping that its provider and group had.
func (s *Store) SetProviderGroup(ctx context.Context, g ProviderGroup) error {
	_, err := s.conn.WriteOneParameterizedContext(ctx, statement(`INSERT OR REPLACE INTO provider_groups (provider, group_name, role) VALUES (?, ?, ?)`, g.Provider, g.Group, g.Role))
	if err != nil {
		return fmt.Errorf("store: writing a provider group: %w", err)
	}
	return nil
}

// DeleteProviderGroup deletes the mapping of the group of the provider and reports whether there was one.
func (s *Store) DeleteProviderGroup(ctx context.Context, provider, group string) (bool, error) {
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(`DELETE FROM provider_groups WHERE provider = ? AND group_name = ?`, provider, group))
	if err != nil {
		return false, fmt.Errorf("store: deleting a provider group: %w", err)
	}
	return wr.RowsAffected > 0, nil
}

// AddGrantedUserToken stores the user token t, which carries the role role, and removes the user tokens that
// ended before now with the roles that they carried, in one transaction. Unlike AddUserToken it asks for no
// row of the API roles of users: the role of the token is the one of the groups of the login that made it.
func (s *Store) AddGrantedUserToken(ctx context.Context, t UserToken, role string, now time.Time) error {
	_, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM user_tokens WHERE expires <= ?`, now.UnixMilli()),
		statement(`DELETE FROM user_token_grants WHERE hash NOT IN (SELECT hash FROM user_tokens)`),
		statement(`INSERT INTO user_tokens (hash, name, expires) VALUES (?, ?, ?)`, t.Hash, t.Name, t.Expires.UnixMilli()),
		statement(`INSERT INTO user_token_grants (hash, role) VALUES (?, ?)`, t.Hash, role),
	})
	if err != nil {
		return fmt.Errorf("store: writing a user token: %w", err)
	}
	return nil
}

// UserTokenRoleByHash returns the name of the User of the user token whose secret has the hash hash, and the
// stored role that the token carries, when the token has not ended at now: the role that its login gave it
// (AddGrantedUserToken), else the API role that the User holds (UserTokenByHash). It reports false when the
// token is none, has ended, or has neither.
func (s *Store) UserTokenRoleByHash(ctx context.Context, hash string, now time.Time) (name, role string, ok bool, err error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(
		`SELECT t.name, COALESCE(g.role, r.role) FROM user_tokens t LEFT JOIN user_token_grants g ON g.hash = t.hash LEFT JOIN user_roles r ON r.name = t.name `+
			`WHERE t.hash = ? AND t.expires > ? AND COALESCE(g.role, r.role) IS NOT NULL`, hash, now.UnixMilli()))
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
