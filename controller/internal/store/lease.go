package store

import (
	"context"
	"errors"
	"fmt"
)

// The lease of the leader (SDN-17, ADR-0026) and the fence that backs it. The lease starts with
// one seed row; the fence holds no rows and only ever takes a failing INSERT, so a write of a
// leader that lost the lease rolls back (see write).
func init() {
	RegisterSchema("lease",
		`CREATE TABLE IF NOT EXISTS lease (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL, renewal INTEGER NOT NULL, holder TEXT NOT NULL, address TEXT NOT NULL, fingerprint TEXT NOT NULL)`,
		`INSERT OR IGNORE INTO lease (id, epoch, renewal, holder, address, fingerprint) VALUES (1, 0, 0, '', '', '')`,
	)
	// The fence: a write of a fenced store first inserts a row here when the lease has another
	// epoch. The row breaks the CHECK, so rqlite rolls the whole transaction back.
	RegisterSchema("fence", `CREATE TABLE IF NOT EXISTS fence (ok INTEGER NOT NULL CONSTRAINT not_the_leader CHECK (ok = 1))`)
}

// Lease is the lease of the leader of a controller cluster.
type Lease struct {
	Epoch       int64  // grows by one at every take-over and release
	Renewal     int64  // grows by one at every change, renewals included
	Holder      string // the name of the member that holds it, empty while none does
	Address     string // host:port of the holder's port, where the members forward to
	Fingerprint string // the TLS fingerprint of the holder (keys.Fingerprint)
}

// Lease returns the lease of the leader.
func (s *Store) Lease(ctx context.Context) (Lease, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT epoch, renewal, holder, address, fingerprint FROM lease WHERE id = 1`)
	if err != nil {
		return Lease{}, fmt.Errorf("store: reading the lease: %w", err)
	}
	if !qr.Next() {
		return Lease{}, errors.New("store: the lease is missing")
	}
	var l Lease
	if err := qr.Scan(&l.Epoch, &l.Renewal, &l.Holder, &l.Address, &l.Fingerprint); err != nil {
		return Lease{}, fmt.Errorf("store: reading the lease: %w", err)
	}
	return l, nil
}

// Acquire takes the lease for holder (its Holder, Address and Fingerprint), if it is still the
// lease seen, and reports whether it did. The lease then has the epoch seen.Epoch+1.
func (s *Store) Acquire(ctx context.Context, seen, holder Lease) (bool, error) {
	r, err := s.conn.WriteOneParameterizedContext(ctx, statement(
		`UPDATE lease SET epoch = epoch + 1, renewal = renewal + 1, holder = ?, address = ?, fingerprint = ? WHERE id = 1 AND epoch = ? AND renewal = ?`,
		holder.Holder, holder.Address, holder.Fingerprint, seen.Epoch, seen.Renewal))
	if err != nil {
		return false, fmt.Errorf("store: taking the lease: %w", err)
	}
	return r.RowsAffected == 1, nil
}

// Renew renews the lease of epoch and reports whether it is still of that epoch.
func (s *Store) Renew(ctx context.Context, epoch int64) (bool, error) {
	r, err := s.conn.WriteOneParameterizedContext(ctx, statement(`UPDATE lease SET renewal = renewal + 1 WHERE id = 1 AND epoch = ?`, epoch))
	if err != nil {
		return false, fmt.Errorf("store: renewing the lease: %w", err)
	}
	return r.RowsAffected == 1, nil
}

// Release gives up the lease of epoch, so another member takes it at once. It ends the epoch:
// the writes of the store that Fenced returned for it fail from then on.
func (s *Store) Release(ctx context.Context, epoch int64) error {
	_, err := s.conn.WriteOneParameterizedContext(ctx, statement(
		`UPDATE lease SET epoch = epoch + 1, renewal = renewal + 1, holder = '', address = '', fingerprint = '' WHERE id = 1 AND epoch = ?`, epoch))
	if err != nil {
		return fmt.Errorf("store: releasing the lease: %w", err)
	}
	return nil
}
