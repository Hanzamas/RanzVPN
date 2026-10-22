package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// The export targets (SDN-16, ADR-0030): each is stored as the JSON of its export.Target, with the
// id of the last event that its webhook was sent.
func init() {
	RegisterSchema("export_targets", `CREATE TABLE IF NOT EXISTS export_targets (name TEXT NOT NULL PRIMARY KEY, target TEXT NOT NULL, delivered INTEGER NOT NULL)`)
}

// EventsAfter returns up to limit events whose id is above after, the oldest first.
func (s *Store) EventsAfter(ctx context.Context, after uint64, limit int) ([]event.Event, error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT id, event FROM events WHERE id > ? ORDER BY id LIMIT ?`, int64(after), int64(limit)))
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

// Targets returns every export target, ordered by name, with the id of the last event that its
// webhook was sent.
func (s *Store) Targets(ctx context.Context) ([]export.Stored, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, target, delivered FROM export_targets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the export targets: %w", err)
	}
	out := []export.Stored{}
	for qr.Next() {
		var name, doc string
		var delivered int64
		if err := qr.Scan(&name, &doc, &delivered); err != nil {
			return nil, fmt.Errorf("store: reading the export targets: %w", err)
		}
		var t export.Target
		if err := json.Unmarshal([]byte(doc), &t); err != nil {
			return nil, fmt.Errorf("store: export target %q: %w", name, err)
		}
		t.Name = name
		out = append(out, export.Stored{Target: t, Delivered: uint64(delivered)})
	}
	return out, nil
}

// PutTarget stores t, which replaces the target of its name. A new target starts at the latest
// event: its webhook is sent the events that follow, not the ones of before it existed.
func (s *Store) PutTarget(ctx context.Context, t export.Target) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("store: export target %q: %w", t.Name, err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT INTO export_targets (name, target, delivered) VALUES (?, ?, (SELECT COALESCE(MAX(id), 0) FROM events)) ON CONFLICT (name) DO UPDATE SET target = excluded.target`,
		t.Name, string(b))})
	if err != nil {
		return fmt.Errorf("store: export target %q: %w", t.Name, err)
	}
	return nil
}

// DeleteTarget deletes the export target name. It is no error when there is none.
func (s *Store) DeleteTarget(ctx context.Context, name string) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`DELETE FROM export_targets WHERE name = ?`, name)})
	if err != nil {
		return fmt.Errorf("store: export target %q: %w", name, err)
	}
	return nil
}

// Delivered records that the webhook name was sent every event up to id.
func (s *Store) Delivered(ctx context.Context, name string, id uint64) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`UPDATE export_targets SET delivered = ? WHERE name = ? AND delivered < ?`,
		int64(id), name, int64(id))})
	if err != nil {
		return fmt.Errorf("store: export target %q: %w", name, err)
	}
	return nil
}
