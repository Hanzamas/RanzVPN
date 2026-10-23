package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// The admin source allowlist (SDN-39, #232): the source prefixes that the API and the web UI of
// the controller accept connections from, one row each, in the text that intent.ParseSources
// makes of them. No row means no restriction. It is not part of the intent, so a revision, a
// rollback or an import never changes it; a store backup holds it.
func init() {
	RegisterSchema("admin_sources", `CREATE TABLE IF NOT EXISTS admin_sources (prefix TEXT NOT NULL PRIMARY KEY)`)
}

// AdminSources returns the admin source allowlist, ordered, empty when it holds no prefix.
func (s *Store) AdminSources(ctx context.Context) ([]string, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT prefix FROM admin_sources ORDER BY prefix`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the admin source allowlist: %w", err)
	}
	out := []string{}
	for qr.Next() {
		var p string
		if err := qr.Scan(&p); err != nil {
			return nil, fmt.Errorf("store: reading the admin source allowlist: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

// SetAdminSources replaces the admin source allowlist with prefixes, which hold no prefix twice,
// and adds the events ev in the same transaction, so that no change is made without its record.
func (s *Store) SetAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM admin_sources`)}
	for _, p := range prefixes {
		stmts = append(stmts, statement(`INSERT INTO admin_sources (prefix) VALUES (?)`, p))
	}
	for _, e := range ev {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: event: %w", err)
		}
		// The statement of Commit for Changes.AddEvents
		stmts = append(stmts, statement(`INSERT INTO events (event) VALUES (?)`, string(b)))
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the admin source allowlist: %w", err)
	}
	return nil
}
