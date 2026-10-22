package store

import (
	"context"
	"fmt"
)

// The licence key (ADR-0036): one row, read by Licence and written through Changes.Licence in
// Commit.
func init() {
	RegisterSchema("licence", `CREATE TABLE IF NOT EXISTS licence (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), key TEXT NOT NULL)`)
}

// Licence returns the stored licence key, empty when none is stored.
func (s *Store) Licence(ctx context.Context) (string, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT key FROM licence WHERE id = 1`)
	if err != nil {
		return "", fmt.Errorf("store: reading the licence key: %w", err)
	}
	var key string
	for qr.Next() {
		if err := qr.Scan(&key); err != nil {
			return "", fmt.Errorf("store: reading the licence key: %w", err)
		}
	}
	return key, nil
}
