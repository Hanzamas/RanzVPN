package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/rqlite/gorqlite"
)

// The Cluster key of a controller cluster (AUD1-DT-16 #501, ADR-0026 amendment of 2026-10-29). The members
// of a cluster have no Sealing key in common, so a cluster seals the secrets of its targets with one key
// of its own, the Cluster key, which internal/clusterkey keeps. The store holds the public half of the
// key (cluster_key), by which the members know which key is the cluster's, and for each member, by its
// name, the public half of the member's Sealing key and a copy of the Cluster key sealed to it, which
// only that member opens (cluster_key_copies). No row holds a private key, so no backup does either. A
// restore keeps these rows as the store that it replaces holds them (Restore): the Cluster key is the
// cluster's, as the Sealing key of a single Controller is its host's, so a backup of another cluster
// brings its targets and not its key.
func init() {
	RegisterSchema("cluster_key",
		`CREATE TABLE IF NOT EXISTS cluster_key (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), public_key TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS cluster_key_copies (name TEXT NOT NULL PRIMARY KEY, public_key TEXT NOT NULL, copy TEXT NOT NULL)`)
}

// ClusterKey is what the store holds of the Cluster key.
type ClusterKey struct {
	// Public is the public half of the Cluster key, nil while the cluster has none.
	Public []byte
	// Copies are the rows of the members, by name.
	Copies []ClusterKeyCopy
}

// ClusterKeyCopy is the row of one member of the cluster.
type ClusterKeyCopy struct {
	// Member is the name of the member.
	Member string
	// Sealing is the public half of the member's Sealing key, nil for a row that holds no key.
	Sealing []byte
	// Copy is the Cluster key sealed to Sealing, nil until a member that holds the key gave one. The text
	// of a row that is no copy comes as it is: it opens nothing.
	Copy []byte
}

// ClusterKey returns the Cluster key as the store holds it.
func (s *Store) ClusterKey(ctx context.Context) (ClusterKey, error) {
	qrs, err := s.conn.QueryContext(ctx, []string{
		`SELECT public_key FROM cluster_key WHERE id = 1`,
		`SELECT name, public_key, copy FROM cluster_key_copies ORDER BY name`,
	})
	if err != nil {
		return ClusterKey{}, fmt.Errorf("store: reading the Cluster key: %w", err)
	}
	if len(qrs) != 2 {
		return ClusterKey{}, fmt.Errorf("store: reading the Cluster key: rqlite answered %d results to 2 queries", len(qrs))
	}
	var k ClusterKey
	key, copies := &qrs[0], &qrs[1]
	if key.Next() {
		var text string
		if err := key.Scan(&text); err != nil {
			return ClusterKey{}, fmt.Errorf("store: reading the Cluster key: %w", err)
		}
		if k.Public, err = base64.StdEncoding.DecodeString(text); err != nil || len(k.Public) == 0 {
			return ClusterKey{}, errors.New("store: the public half of the Cluster key in the store is not the base64 of a key")
		}
	}
	for copies.Next() {
		var name, sealing, wrapped string
		if err := copies.Scan(&name, &sealing, &wrapped); err != nil {
			return ClusterKey{}, fmt.Errorf("store: reading the copies of the Cluster key: %w", err)
		}
		c := ClusterKeyCopy{Member: name, Copy: decodeCopy(wrapped)}
		if b, err := base64.StdEncoding.DecodeString(sealing); err == nil && len(b) > 0 {
			c.Sealing = b
		}
		k.Copies = append(k.Copies, c)
	}
	return k, nil
}

// PublishSealingKey makes the row of member hold sealing, the public half of the member's Sealing key. A
// row that held another key loses its copy, which that key alone opened.
func (s *Store) PublishSealingKey(ctx context.Context, member string, sealing []byte) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(
		`INSERT INTO cluster_key_copies (name, public_key, copy) VALUES (?, ?, '') ON CONFLICT (name) DO UPDATE SET public_key = excluded.public_key, copy = '' WHERE cluster_key_copies.public_key <> excluded.public_key`,
		member, base64.StdEncoding.EncodeToString(sealing))})
	if err != nil {
		return fmt.Errorf("store: the sealing key of the member %q: %w", member, err)
	}
	return nil
}

// MakeClusterKey makes public the public half of the Cluster key in the place of old, nil when the store
// holds no key, and wrapped, the new key sealed to sealing, the copy of the row of member, in one
// transaction that removes every copy of the old key. It reports whether the store held old: when it did
// not, as when another member made a key first, nothing changes.
func (s *Store) MakeClusterKey(ctx context.Context, old, public []byte, member string, sealing, wrapped []byte) (bool, error) {
	pub := base64.StdEncoding.EncodeToString(public)
	first := statement(`INSERT INTO cluster_key (id, public_key) SELECT 1, ? WHERE NOT EXISTS (SELECT 1 FROM cluster_key)`, pub)
	if old != nil {
		first = statement(`UPDATE cluster_key SET public_key = ? WHERE id = 1 AND public_key = ?`, pub, base64.StdEncoding.EncodeToString(old))
	}
	// The two statements after the first change nothing unless it made the key
	made := `EXISTS (SELECT 1 FROM cluster_key WHERE id = 1 AND public_key = ?)`
	res, err := s.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		first,
		statement(`UPDATE cluster_key_copies SET copy = '' WHERE copy <> '' AND `+made, pub),
		statement(`INSERT INTO cluster_key_copies (name, public_key, copy) SELECT ?, ?, ? WHERE `+made+` ON CONFLICT (name) DO UPDATE SET public_key = excluded.public_key, copy = excluded.copy`,
			member, base64.StdEncoding.EncodeToString(sealing), encodeCopy(wrapped), pub),
	})
	if err != nil {
		return false, fmt.Errorf("store: making the Cluster key: %w", err)
	}
	return len(res) > 0 && res[0].RowsAffected == 1, nil
}

// PutClusterKeyCopy writes wrapped, the Cluster key of the public half public sealed to sealing, as the
// copy of the row of member, while the row holds sealing and no copy and the cluster's key is public. It
// reports whether it wrote it.
func (s *Store) PutClusterKeyCopy(ctx context.Context, public []byte, member string, sealing, wrapped []byte) (bool, error) {
	r, err := s.conn.WriteOneParameterizedContext(ctx, statement(
		`UPDATE cluster_key_copies SET copy = ? WHERE name = ? AND public_key = ? AND copy = '' AND EXISTS (SELECT 1 FROM cluster_key WHERE id = 1 AND public_key = ?)`,
		encodeCopy(wrapped), member, base64.StdEncoding.EncodeToString(sealing), base64.StdEncoding.EncodeToString(public)))
	if err != nil {
		return false, fmt.Errorf("store: a copy of the Cluster key for the member %q: %w", member, err)
	}
	return r.RowsAffected == 1, nil
}

// ClearClusterKeyCopy removes the copy of the row of member while the row holds sealing: a copy that the
// member's key does not open, so that a member that holds the key gives it another.
func (s *Store) ClearClusterKeyCopy(ctx context.Context, member string, sealing []byte) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`UPDATE cluster_key_copies SET copy = '' WHERE name = ? AND public_key = ?`,
		member, base64.StdEncoding.EncodeToString(sealing))})
	if err != nil {
		return fmt.Errorf("store: the copy of the Cluster key of the member %q: %w", member, err)
	}
	return nil
}

// statements returns the statements that make the tables of the Cluster key hold k, and nothing else.
func (k ClusterKey) statements() []gorqlite.ParameterizedStatement {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM cluster_key`), statement(`DELETE FROM cluster_key_copies`)}
	if k.Public != nil {
		stmts = append(stmts, statement(`INSERT INTO cluster_key (id, public_key) VALUES (1, ?)`, base64.StdEncoding.EncodeToString(k.Public)))
	}
	for _, c := range k.Copies {
		wrapped := ""
		if len(c.Copy) > 0 {
			wrapped = encodeCopy(c.Copy)
		}
		stmts = append(stmts, statement(`INSERT INTO cluster_key_copies (name, public_key, copy) VALUES (?, ?, ?)`,
			c.Member, base64.StdEncoding.EncodeToString(c.Sealing), wrapped))
	}
	return stmts
}

// encodeCopy returns the text of the copy wrapped in its row: the form of a sealed secret, sealedPrefix
// and the base64 of the sealed bytes.
func encodeCopy(wrapped []byte) string {
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(wrapped)
}

// decodeCopy returns the sealed bytes of the text of a copy, nil for none. A text of another form comes
// as it is: anyone who can write to the store can put it there, and it opens nothing.
func decodeCopy(text string) []byte {
	if text == "" {
		return nil
	}
	if rest, ok := strings.CutPrefix(text, sealedPrefix); ok {
		if b, err := base64.RawStdEncoding.DecodeString(rest); err == nil && len(b) > 0 {
			return b
		}
	}
	return []byte(text)
}
