package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The bans of users (SDN-50, #243): one row for each User that an operator banned, with the instant
// of the ban, who made it and why. A ban is an operation, not intent, so a revision, a rollback or an
// import never changes one and an Intent export holds none; a store backup holds them. The controller
// leaves the Nodes of a banned User out of every other Node's desired state and refuses their control
// streams (internal/controller, bans.go), and deletes the row of a User that a change of the intent
// removes.
func init() {
	RegisterSchema("user_bans", `CREATE TABLE IF NOT EXISTS user_bans (name TEXT NOT NULL PRIMARY KEY, since INTEGER NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL)`)
}

// Ban is a User that an operator banned.
type Ban struct {
	// User is the name of the User resource.
	User string `json:"user"`
	// Since is when the operator banned the user.
	Since time.Time `json:"since"`
	// By is who banned the user: the actor of the audit record of the ban, such as token:ops.
	By string `json:"by"`
	// Reason is what the operator gave as the reason, empty for none.
	Reason string `json:"reason,omitempty"`
}

// Bans returns every ban, ordered by the name of the user. A new store holds none.
func (s *Store) Bans(ctx context.Context) ([]Ban, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, since, actor, reason FROM user_bans ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the bans of users: %w", err)
	}
	out := []Ban{}
	for qr.Next() {
		var b Ban
		var since int64
		if err := qr.Scan(&b.User, &since, &b.By, &b.Reason); err != nil {
			return nil, fmt.Errorf("store: reading the bans of users: %w", err)
		}
		b.Since = time.UnixMilli(since).UTC()
		out = append(out, b)
	}
	return out, nil
}

// AddBan stores the ban b, in place of the one that the same user had.
func (s *Store) AddBan(ctx context.Context, b Ban) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO user_bans (name, since, actor, reason) VALUES (?, ?, ?, ?)`,
		b.User, b.Since.UnixMilli(), b.By, b.Reason)})
	if err != nil {
		return fmt.Errorf("store: writing the ban of user %q: %w", b.User, err)
	}
	return nil
}

// DeleteBans deletes the bans of the users names, in one transaction. A user that has none is no
// error.
func (s *Store) DeleteBans(ctx context.Context, names []string) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, name := range names {
		stmts = append(stmts, statement(`DELETE FROM user_bans WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the bans of users: %w", err)
	}
	return nil
}
