package store

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

func init() {
	RegisterSchema("node_capabilities", `CREATE TABLE IF NOT EXISTS node_capabilities (public_key TEXT NOT NULL PRIMARY KEY, capabilities TEXT NOT NULL)`)
}

// LoadCapabilities returns the stored Capabilities by node static key (the key's bytes as a
// string).
func (s *Store) LoadCapabilities(ctx context.Context) (map[string]*controlpb.Capabilities, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT public_key, capabilities FROM node_capabilities ORDER BY public_key`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the Capabilities: %w", err)
	}
	out := map[string]*controlpb.Capabilities{}
	for qr.Next() {
		var key, caps string
		if err := qr.Scan(&key, &caps); err != nil {
			return nil, fmt.Errorf("store: reading the Capabilities: %w", err)
		}
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("store: the Capabilities of key %q: %w", key, err)
		}
		c := &controlpb.Capabilities{}
		if err := decode(caps, c); err != nil {
			return nil, fmt.Errorf("store: the Capabilities of key %q: %w", key, err)
		}
		out[string(k)] = c
	}
	return out, nil
}

// SaveCapabilities records that the node with the static key key reported the Capabilities caps.
func (s *Store) SaveCapabilities(ctx context.Context, key []byte, caps *controlpb.Capabilities) error {
	b, err := encode(caps)
	if err != nil {
		return fmt.Errorf("store: Capabilities: %w", err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO node_capabilities (public_key, capabilities) VALUES (?, ?)`,
		base64.StdEncoding.EncodeToString(key), b)})
	if err != nil {
		return fmt.Errorf("store: Capabilities: %w", err)
	}
	return nil
}
