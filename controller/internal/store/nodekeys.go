package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
)

// The lives of the node keys (SDN-56, #249): one row for each static key that a Node resource holds, with when
// the key last authenticated, when it ends, and whether the Node was admitted, by whom and when. It is no intent,
// so a revision, a rollback or an import never changes a row and an Intent export holds none; a store backup holds
// them. The controller keeps a Node whose key ended, and a Node that waits for approval, out of the desired state
// of every other Node and refuses its control stream (internal/controller, nodekeys.go), and deletes the row of a
// key that no Node resource holds any more. The rows are by the key and not by the name of the Node, so a Node that
// is deleted and made again, or that gets another key, starts with a life of its own.
func init() {
	RegisterSchema("node_keys", `CREATE TABLE IF NOT EXISTS node_keys (public_key TEXT NOT NULL PRIMARY KEY, node TEXT NOT NULL, refreshed INTEGER NOT NULL, `+
		`expires INTEGER NOT NULL, approved INTEGER NOT NULL, approved_by TEXT NOT NULL, approved_at INTEGER NOT NULL)`)
}

// NodeKey is the life of the static key of one Node.
type NodeKey struct {
	// Key is the static key: its 32 bytes.
	Key []byte
	// Node is the name of the Node resource that held the key last.
	Node string
	// Refreshed is when the key last authenticated: the Node was admitted, its User logged in again, or an
	// operator refreshed it.
	Refreshed time.Time
	// Expires is when the key ends. It is the zero time for a key that does not end, the key of a Node that is
	// marked nonExpiring.
	Expires time.Time
	// Approved says that the Node was admitted: a Network that holds new Nodes for approval does not hold it.
	Approved bool
	// ApprovedBy is who admitted the Node: the actor of the audit record of the approval, such as token:ops, or
	// system for a Node that no Network held.
	ApprovedBy string
	// ApprovedAt is when the Node was admitted.
	ApprovedAt time.Time
}

// NodeKeys returns the life of every key, ordered by the key. A new store holds none.
func (s *Store) NodeKeys(ctx context.Context) ([]NodeKey, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT public_key, node, refreshed, expires, approved, approved_by, approved_at FROM node_keys ORDER BY public_key`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the lives of the node keys: %w", err)
	}
	out := []NodeKey{}
	for qr.Next() {
		var key, node, by string
		var refreshed, expires, approved, at int64
		if err := qr.Scan(&key, &node, &refreshed, &expires, &approved, &by, &at); err != nil {
			return nil, fmt.Errorf("store: reading the lives of the node keys: %w", err)
		}
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("store: the life of key %q: %w", key, err)
		}
		out = append(out, NodeKey{Key: k, Node: node, Refreshed: keyTime(refreshed), Expires: keyTime(expires), Approved: approved != 0,
			ApprovedBy: by, ApprovedAt: keyTime(at)})
	}
	return out, nil
}

// ChangeNodeKeys stores the lives put, each in place of the one that its key had, and deletes the lives of the keys
// gone, in one transaction. A key that has no life is no error.
func (s *Store) ChangeNodeKeys(ctx context.Context, put []NodeKey, gone [][]byte) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, k := range put {
		approved := int64(0)
		if k.Approved {
			approved = 1
		}
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO node_keys (public_key, node, refreshed, expires, approved, approved_by, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			base64.StdEncoding.EncodeToString(k.Key), k.Node, keyMillis(k.Refreshed), keyMillis(k.Expires), approved, k.ApprovedBy, keyMillis(k.ApprovedAt)))
	}
	for _, key := range gone {
		stmts = append(stmts, statement(`DELETE FROM node_keys WHERE public_key = ?`, base64.StdEncoding.EncodeToString(key)))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the lives of the node keys: %w", err)
	}
	return nil
}

// keyMillis returns t as the Unix milliseconds that a row keeps, and 0 for the zero time.
func keyMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// keyTime returns the time that the Unix milliseconds ms are, in UTC, and the zero time for 0.
func keyTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
