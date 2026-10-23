package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// The audit log (SDN-49 #242, ADR-0030): one row for each audit.Record, stored as its JSON beside
// the columns that a listing filters by and the retention policy removes by; the audit targets, each
// as the JSON of its export.Target with the id of the last record that it was sent; and the one row
// of the retention policy that an operator set. The id of a record is AUTOINCREMENT, since the
// retention policy removes records: an id that was used is never used again, so the id that a target
// was sent up to always stays behind the records that it was not sent.
func init() {
	RegisterSchema("audit_log",
		`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, record TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts)`,
		`CREATE TABLE IF NOT EXISTS audit_targets (name TEXT NOT NULL PRIMARY KEY, target TEXT NOT NULL, delivered INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit_retention (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), days INTEGER NOT NULL, max_records INTEGER NOT NULL)`,
	)
}

var _ audit.Store = (*Store)(nil)

// AddAudit stores the record r, which gets the next id. The time of r is what a listing and the
// retention policy go by.
func (s *Store) AddAudit(ctx context.Context, r audit.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: audit record: %w", err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT INTO audit_log (ts, kind, actor, record) VALUES (?, ?, ?, ?)`,
		r.Time.UnixMilli(), r.Kind, r.Actor, string(b))})
	if err != nil {
		return fmt.Errorf("store: audit record: %w", err)
	}
	return nil
}

// Audit returns the records that match f, the oldest first, at most f.Limit of them, or audit.MaxLimit
// when f.Limit is not from 1 to that.
func (s *Store) Audit(ctx context.Context, f audit.Filter) ([]audit.Record, error) {
	query := `SELECT id, record FROM audit_log WHERE id > ?`
	args := []any{int64(min(f.After, math.MaxInt64))}
	if f.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	if f.Actor != "" {
		query += ` AND actor = ?`
		args = append(args, f.Actor)
	}
	if !f.Since.IsZero() {
		query += ` AND ts >= ?`
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		query += ` AND ts <= ?`
		args = append(args, f.Until.UnixMilli())
	}
	limit := f.Limit
	if limit < 1 || limit > audit.MaxLimit {
		limit = audit.MaxLimit
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, int64(limit))
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(query, args...))
	if err != nil {
		return nil, fmt.Errorf("store: reading the audit log: %w", err)
	}
	out := []audit.Record{}
	for qr.Next() {
		var id int64
		var doc string
		if err := qr.Scan(&id, &doc); err != nil {
			return nil, fmt.Errorf("store: reading the audit log: %w", err)
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			return nil, fmt.Errorf("store: reading audit record %d: %w", id, err)
		}
		r.ID = uint64(id)
		out = append(out, r)
	}
	return out, nil
}

// PruneAudit removes the records made before the time before, and then the oldest ones until at most
// keep remain, when keep is above 0, in one transaction. The newest keep records stay: the cutoff is
// the id of the keep-th newest, and nothing is removed while there are fewer.
func (s *Store) PruneAudit(ctx context.Context, before time.Time, keep int) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM audit_log WHERE ts < ?`, before.UnixMilli())}
	if keep > 0 {
		stmts = append(stmts, statement(`DELETE FROM audit_log WHERE id < (SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET ?)`, int64(keep-1)))
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: removing audit records: %w", err)
	}
	return nil
}

// AuditRetention returns the retention policy that an operator set, and false when none is set.
func (s *Store) AuditRetention(ctx context.Context) (audit.Retention, bool, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT days, max_records FROM audit_retention WHERE id = 1`)
	if err != nil {
		return audit.Retention{}, false, fmt.Errorf("store: reading the audit retention: %w", err)
	}
	if !qr.Next() {
		return audit.Retention{}, false, nil
	}
	var days, records int64
	if err := qr.Scan(&days, &records); err != nil {
		return audit.Retention{}, false, fmt.Errorf("store: reading the audit retention: %w", err)
	}
	return audit.Retention{Days: int(days), MaxRecords: int(records)}, true, nil
}

// SetAuditRetention sets the retention policy r.
func (s *Store) SetAuditRetention(ctx context.Context, r audit.Retention) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO audit_retention (id, days, max_records) VALUES (1, ?, ?)`,
		int64(r.Days), int64(r.MaxRecords))})
	if err != nil {
		return fmt.Errorf("store: audit retention: %w", err)
	}
	return nil
}

// AuditTargets returns every audit target, ordered by name, with the id of the last record that it
// was sent.
func (s *Store) AuditTargets(ctx context.Context) ([]export.Stored, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, target, delivered FROM audit_targets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the audit targets: %w", err)
	}
	out := []export.Stored{}
	for qr.Next() {
		var name, doc string
		var delivered int64
		if err := qr.Scan(&name, &doc, &delivered); err != nil {
			return nil, fmt.Errorf("store: reading the audit targets: %w", err)
		}
		var t export.Target
		if err := json.Unmarshal([]byte(doc), &t); err != nil {
			return nil, fmt.Errorf("store: audit target %q: %w", name, err)
		}
		t.Name = name
		out = append(out, export.Stored{Target: t, Delivered: uint64(delivered)})
	}
	return out, nil
}

// PutAuditTarget stores t, which replaces the audit target of its name. A new target starts at the
// latest record: it is sent the records that follow, not the ones of before it existed. An update
// keeps what the target was sent.
func (s *Store) PutAuditTarget(ctx context.Context, t export.Target) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("store: audit target %q: %w", t.Name, err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT INTO audit_targets (name, target, delivered) VALUES (?, ?, (SELECT COALESCE(MAX(id), 0) FROM audit_log)) ON CONFLICT (name) DO UPDATE SET target = excluded.target`,
		t.Name, string(b))})
	if err != nil {
		return fmt.Errorf("store: audit target %q: %w", t.Name, err)
	}
	return nil
}

// DeleteAuditTarget deletes the audit target name. It is no error when there is none.
func (s *Store) DeleteAuditTarget(ctx context.Context, name string) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`DELETE FROM audit_targets WHERE name = ?`, name)})
	if err != nil {
		return fmt.Errorf("store: audit target %q: %w", name, err)
	}
	return nil
}

// AuditDelivered records that the audit target name was sent every record up to id. The record only
// moves forward.
func (s *Store) AuditDelivered(ctx context.Context, name string, id uint64) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`UPDATE audit_targets SET delivered = ? WHERE name = ? AND delivered < ?`,
		int64(id), name, int64(id))})
	if err != nil {
		return fmt.Errorf("store: audit target %q: %w", name, err)
	}
	return nil
}
