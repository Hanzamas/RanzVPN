package store

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The keys that the nodes report about themselves (SDN-94 #423): one row for each node static key, with the Pins message
// that the node reported last, kept as the Capabilities are. The controller keeps a row while a Node resource holds the key
// and deletes it with the Node (internal/controller, mimic.go). A restart of the controller so loads the public keys of the
// mimic servers that its states were made with, and no client loses its link while the Node of a server has not reported
// again. The row holds public keys only: no message of the control protocol has a field for a private key.
func init() {
	RegisterSchema("node_pins", `CREATE TABLE IF NOT EXISTS node_pins (public_key TEXT NOT NULL PRIMARY KEY, pins TEXT NOT NULL)`)
}

// LoadPins returns the stored Pins by node static key (the key's bytes as a string).
func (s *Store) LoadPins(ctx context.Context) (map[string]*controlpb.Pins, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT public_key, pins FROM node_pins ORDER BY public_key`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the keys that the nodes reported: %w", err)
	}
	out := map[string]*controlpb.Pins{}
	for qr.Next() {
		var key, pins string
		if err := qr.Scan(&key, &pins); err != nil {
			return nil, fmt.Errorf("store: reading the keys that the nodes reported: %w", err)
		}
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("store: the keys reported by the node of key %q: %w", key, err)
		}
		p := &controlpb.Pins{}
		if err := decode(pins, p); err != nil {
			return nil, fmt.Errorf("store: the keys reported by the node of key %q: %w", key, err)
		}
		out[string(k)] = p
	}
	return out, nil
}

// SavePins records that the node with the static key key reported the Pins pins, in place of those it reported before.
func (s *Store) SavePins(ctx context.Context, key []byte, pins *controlpb.Pins) error {
	b, err := encode(pins)
	if err != nil {
		return fmt.Errorf("store: the keys that a node reported: %w", err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO node_pins (public_key, pins) VALUES (?, ?)`,
		base64.StdEncoding.EncodeToString(key), b)})
	if err != nil {
		return fmt.Errorf("store: the keys that a node reported: %w", err)
	}
	return nil
}

// DeletePins deletes the Pins of the nodes with the static keys keys, in one transaction. A key that has none is no error.
func (s *Store) DeletePins(ctx context.Context, keys [][]byte) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, key := range keys {
		stmts = append(stmts, statement(`DELETE FROM node_pins WHERE public_key = ?`, base64.StdEncoding.EncodeToString(key)))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the keys that nodes reported: %w", err)
	}
	return nil
}
