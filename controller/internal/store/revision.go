package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A revision is stored as the JSON of its intent.Revision without the resources, and the JSON of
// the resources beside it, so a list of revisions reads no intent.
func init() {
	RegisterSchema("revisions", `CREATE TABLE IF NOT EXISTS revisions (id INTEGER PRIMARY KEY, revision TEXT NOT NULL, intent TEXT NOT NULL)`)
}

// Revisions returns every revision, oldest first, without its resources.
func (s *Store) Revisions(ctx context.Context) ([]intent.Revision, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT revision FROM revisions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the revisions: %w", err)
	}
	out := []intent.Revision{}
	for qr.Next() {
		var meta string
		if err := qr.Scan(&meta); err != nil {
			return nil, fmt.Errorf("store: reading the revisions: %w", err)
		}
		var r intent.Revision
		if err := json.Unmarshal([]byte(meta), &r); err != nil {
			return nil, fmt.Errorf("store: reading the revisions: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// LastRevision returns the latest revision without its resources; ok is false while there is
// none.
func (s *Store) LastRevision(ctx context.Context) (r intent.Revision, ok bool, err error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT revision FROM revisions ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading the last revision: %w", err)
	}
	if !qr.Next() {
		return intent.Revision{}, false, nil
	}
	var meta string
	if err := qr.Scan(&meta); err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading the last revision: %w", err)
	}
	if err := json.Unmarshal([]byte(meta), &r); err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading the last revision: %w", err)
	}
	return r, true, nil
}

// Revision returns revision id with its resources; ok is false if there is no such revision.
func (s *Store) Revision(ctx context.Context, id uint64) (r intent.Revision, ok bool, err error) {
	qr, err := s.conn.QueryOneParameterizedContext(ctx, statement(`SELECT revision, intent FROM revisions WHERE id = ?`, int64(id)))
	if err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading revision %d: %w", id, err)
	}
	if !qr.Next() {
		return intent.Revision{}, false, nil
	}
	var meta, rs string
	if err := qr.Scan(&meta, &rs); err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading revision %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(meta), &r); err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading revision %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(rs), &r.Resources); err != nil {
		return intent.Revision{}, false, fmt.Errorf("store: reading the intent of revision %d: %w", id, err)
	}
	return r, true, nil
}

// encodeRevision returns the JSON of r without its resources, and the JSON of its resources.
func encodeRevision(r intent.Revision) (meta, resources string, err error) {
	rs := r.Resources
	if rs == nil {
		rs = []intent.Resource{}
	}
	r.Resources = nil
	m, err := json.Marshal(r)
	if err != nil {
		return "", "", err
	}
	b, err := json.Marshal(rs)
	if err != nil {
		return "", "", err
	}
	return string(m), string(b), nil
}
