package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// An event is stored as the JSON of its event.Event, and its id is the row id.
func init() {
	RegisterSchema("events", `CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, event TEXT NOT NULL)`)
}

// Events returns every event, oldest first.
func (s *Store) Events(ctx context.Context) ([]event.Event, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT id, event FROM events ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the events: %w", err)
	}
	out := []event.Event{}
	for qr.Next() {
		var id int64
		var b string
		if err := qr.Scan(&id, &b); err != nil {
			return nil, fmt.Errorf("store: reading the events: %w", err)
		}
		var e event.Event
		if err := json.Unmarshal([]byte(b), &e); err != nil {
			return nil, fmt.Errorf("store: reading event %d: %w", id, err)
		}
		e.ID = uint64(id)
		out = append(out, e)
	}
	return out, nil
}
