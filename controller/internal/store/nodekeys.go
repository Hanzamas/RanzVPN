package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// The lives of the node keys (SDN-56, #249): one row for each static key that a Node resource holds or held, with
// when the key last authenticated, when it ends, whether the Node was admitted, by whom and when, and which of the
// announcements of its life the controller made (SDN-56-R1, #515). It is no intent, so a revision, a rollback or an
// import never changes a row and an Intent export holds none; a store backup holds them. The controller keeps a Node
// whose key ended, and a Node that waits for approval, out of the desired state of every other Node and refuses its
// control stream (internal/controller, nodekeys.go). The rows are by the key and not by the name of the Node, and none
// is deleted: the row of a key that no Node resource holds any more stays, with when the key ends and without the
// approval, so that a Node that is deleted and made again with the key, or that gets its key back, does not give a key
// that ended another life. A Node that gets a new key starts with a life of its own.
//
// The column announced was added to the table before any release held it, so the statement that makes the table has it
// and nothing alters a table that exists.
func init() {
	RegisterSchema("node_keys", `CREATE TABLE IF NOT EXISTS node_keys (public_key TEXT NOT NULL PRIMARY KEY, node TEXT NOT NULL, refreshed INTEGER NOT NULL, `+
		`expires INTEGER NOT NULL, approved INTEGER NOT NULL, approved_by TEXT NOT NULL, approved_at INTEGER NOT NULL, announced INTEGER NOT NULL DEFAULT 0)`)
}

// The announcements that the controller made of the life of a key (NodeKey.Announced), one bit each. The controller notes
// each state that it announced, so that it announces each once, also after a restart (internal/controller, keyevents.go).
const (
	// AnnouncedWaiting: the Event node-waiting was raised for the Node that its Network holds for approval.
	AnnouncedWaiting = 1 << iota
	// AnnouncedExpiring: the Event node-key-expiring was raised when the key entered the span before its end.
	AnnouncedExpiring
	// AnnouncedLast: the Event node-key-expiring was raised when the last days of the key began.
	AnnouncedLast
	// AnnouncedEnded: the Event node-key-ended was raised.
	AnnouncedEnded

	// AnnouncedLife holds the marks that a new period of the key takes away, so that the end of the period is announced
	// again.
	AnnouncedLife = AnnouncedExpiring | AnnouncedLast | AnnouncedEnded
)

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
	// Announced holds the announcements of the life of the key that the controller made and that still hold, as
	// the bits of the Announced constants.
	Announced uint8
}

// NodeKeys returns the life of every key, ordered by the key. A new store holds none.
func (s *Store) NodeKeys(ctx context.Context) ([]NodeKey, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT public_key, node, refreshed, expires, approved, approved_by, approved_at, announced FROM node_keys ORDER BY public_key`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the lives of the node keys: %w", err)
	}
	out := []NodeKey{}
	for qr.Next() {
		var key, node, by string
		var refreshed, expires, approved, at, announced int64
		if err := qr.Scan(&key, &node, &refreshed, &expires, &approved, &by, &at, &announced); err != nil {
			return nil, fmt.Errorf("store: reading the lives of the node keys: %w", err)
		}
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("store: the life of key %q: %w", key, err)
		}
		out = append(out, NodeKey{Key: k, Node: node, Refreshed: keyTime(refreshed), Expires: keyTime(expires), Approved: approved != 0,
			ApprovedBy: by, ApprovedAt: keyTime(at), Announced: uint8(announced)})
	}
	return out, nil
}

// PutNodeKeys stores the lives put, each in place of the one that its key had, and adds the events ev, in one
// transaction, so that an announcement of the controller and the mark that it was made are written together or not at all.
func (s *Store) PutNodeKeys(ctx context.Context, put []NodeKey, ev ...event.Event) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, k := range put {
		approved := int64(0)
		if k.Approved {
			approved = 1
		}
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO node_keys (public_key, node, refreshed, expires, approved, approved_by, approved_at, announced) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			base64.StdEncoding.EncodeToString(k.Key), k.Node, keyMillis(k.Refreshed), keyMillis(k.Expires), approved, k.ApprovedBy, keyMillis(k.ApprovedAt), int64(k.Announced)))
	}
	for _, e := range ev {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: event: %w", err)
		}
		// The statement of Commit for Changes.AddEvents
		stmts = append(stmts, statement(`INSERT INTO events (event) VALUES (?)`, string(b)))
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
