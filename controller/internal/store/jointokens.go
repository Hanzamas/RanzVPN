package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The join tokens (SDN-58, #251): one row for each secret that a User made in the portal for a device of
// its own, with the name of the User, the name that the device is to take, and the end of the token, and the
// SHA-256 of the secret, never the secret itself. A device that presents the secret with its static key is
// enrolled as a Node that the User owns (internal/controller, joins.go), and the token is spent: the device
// takes it from the store as claimed first, so that two devices cannot enrol with one token, and the row is
// deleted once the Node is made, or given back when the enrolment is refused. A join token is no intent, for
// the reasons that a password and a user token are not: a revision, a rollback or an import never changes one
// and an Intent export holds none; a store backup holds them. The rows of a User end with its roles, when a
// change of the intent removes the User (DeleteUserRoles, userroles.go).
func init() {
	RegisterSchema("join_tokens", `CREATE TABLE IF NOT EXISTS join_tokens (hash TEXT NOT NULL PRIMARY KEY, id TEXT NOT NULL, owner TEXT NOT NULL, `+
		`name TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, claimed INTEGER NOT NULL)`)
}

// JoinToken is a stored join token. It is never the secret: Hash is the hash of it.
type JoinToken struct {
	// Hash is the SHA-256 of the secret, in hex.
	Hash string
	// ID names the token in the list of its User and in its revocation: 16 hex digits that nobody can use to
	// join.
	ID string
	// Owner is the name of the User that the token enrols the devices of.
	Owner string
	// Name is the name that the Node of the device takes, empty for a name that the controller draws.
	Name string
	// Created is when the User made the token, and Expires when it ends.
	Created time.Time
	Expires time.Time
}

// AddJoinToken stores t, and removes the join tokens that ended before now, in one transaction. It reports
// false, and stores nothing, when its User holds limit tokens that wait already.
func (s *Store) AddJoinToken(ctx context.Context, t JoinToken, now time.Time, limit int) (bool, error) {
	wrs, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		statement(`DELETE FROM join_tokens WHERE expires <= ?`, now.UnixMilli()),
		statement(`INSERT INTO join_tokens (hash, id, owner, name, created, expires, claimed) SELECT ?, ?, ?, ?, ?, ?, 0 `+
			`WHERE (SELECT COUNT(*) FROM join_tokens WHERE owner = ? AND claimed = 0) < ?`,
			t.Hash, t.ID, t.Owner, t.Name, t.Created.UnixMilli(), t.Expires.UnixMilli(), t.Owner, limit),
	})
	if err != nil {
		return false, fmt.Errorf("store: writing a join token: %w", err)
	}
	return len(wrs) == 2 && wrs[1].RowsAffected > 0, nil
}

// JoinTokens returns the join tokens of the User owner that wait for a device at now, the ones that were not
// used and have not ended, oldest first. The hash of a token is left out.
func (s *Store) JoinTokens(ctx context.Context, owner string, now time.Time) ([]JoinToken, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(
		`SELECT id, name, created, expires FROM join_tokens WHERE owner = ? AND claimed = 0 AND expires > ? ORDER BY created, id`, owner, now.UnixMilli()))
	if err != nil {
		return nil, fmt.Errorf("store: reading the join tokens of a user: %w", err)
	}
	out := []JoinToken{}
	for qr.Next() {
		t := JoinToken{Owner: owner}
		var created, expires int64
		if err := qr.Scan(&t.ID, &t.Name, &created, &expires); err != nil {
			return nil, fmt.Errorf("store: reading the join tokens of a user: %w", err)
		}
		t.Created, t.Expires = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
		out = append(out, t)
	}
	return out, nil
}

// DeleteJoinToken deletes the join token of the User owner that has the id id, which no device is using
// now, and returns it without its hash. It reports false when the User has no such token.
func (s *Store) DeleteJoinToken(ctx context.Context, owner, id string) (JoinToken, bool, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(
		`SELECT name, created, expires FROM join_tokens WHERE owner = ? AND id = ? AND claimed = 0`, owner, id))
	if err != nil {
		return JoinToken{}, false, fmt.Errorf("store: reading a join token: %w", err)
	}
	if !qr.Next() {
		return JoinToken{}, false, nil
	}
	t := JoinToken{ID: id, Owner: owner}
	var created, expires int64
	if err := qr.Scan(&t.Name, &created, &expires); err != nil {
		return JoinToken{}, false, fmt.Errorf("store: reading a join token: %w", err)
	}
	t.Created, t.Expires = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(`DELETE FROM join_tokens WHERE owner = ? AND id = ? AND claimed = 0`, owner, id))
	if err != nil {
		return JoinToken{}, false, fmt.Errorf("store: deleting a join token: %w", err)
	}
	return t, wr.RowsAffected > 0, nil
}

// ClaimJoinToken takes the join token whose secret has the hash hash for the device that presented it, when
// it was not used and has not ended at now, and returns it with the hash. The claim is one statement, so
// of two devices that present one secret at once only one gets it. It reports false when there is no such
// token. ReleaseJoinToken gives the token back, and FinishJoinToken deletes it.
func (s *Store) ClaimJoinToken(ctx context.Context, hash string, now time.Time) (JoinToken, bool, error) {
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(
		`UPDATE join_tokens SET claimed = 1 WHERE hash = ? AND claimed = 0 AND expires > ?`, hash, now.UnixMilli()))
	if err != nil {
		return JoinToken{}, false, fmt.Errorf("store: claiming a join token: %w", err)
	}
	if wr.RowsAffected == 0 {
		return JoinToken{}, false, nil
	}
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT id, owner, name, created, expires FROM join_tokens WHERE hash = ?`, hash))
	if err != nil {
		return JoinToken{}, false, fmt.Errorf("store: reading a join token: %w", err)
	}
	if !qr.Next() {
		return JoinToken{}, false, nil
	}
	t := JoinToken{Hash: hash}
	var created, expires int64
	if err := qr.Scan(&t.ID, &t.Owner, &t.Name, &created, &expires); err != nil {
		return JoinToken{}, false, fmt.Errorf("store: reading a join token: %w", err)
	}
	t.Created, t.Expires = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	return t, true, nil
}

// ReleaseJoinToken gives back the join token whose secret has the hash hash, which ClaimJoinToken took for a
// device that was then refused, so that its User can use it again.
func (s *Store) ReleaseJoinToken(ctx context.Context, hash string) error {
	if _, err := s.conn.WriteOneParameterizedContext(ctx, statement(`UPDATE join_tokens SET claimed = 0 WHERE hash = ?`, hash)); err != nil {
		return fmt.Errorf("store: giving back a join token: %w", err)
	}
	return nil
}

// FinishJoinToken deletes the join token whose secret has the hash hash, once the device that
// ClaimJoinToken took it for is enrolled.
func (s *Store) FinishJoinToken(ctx context.Context, hash string) error {
	if _, err := s.conn.WriteOneParameterizedContext(ctx, statement(`DELETE FROM join_tokens WHERE hash = ?`, hash)); err != nil {
		return fmt.Errorf("store: deleting a join token: %w", err)
	}
	return nil
}
