package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// The certificate setting of the controller (SDN-92, #397): where the certificate that its TLS port
// serves comes from, as the JSON of a servercert.Setting, with the TLS fingerprint of the
// certificate that the setting gave when it was set. One row, or none while the controller serves
// its own self-signed certificate. It holds no key, only the path of a file, the thumbprint of a
// certificate of the Windows key storage or the names of an ACME certificate. It is not part of the
// intent, so a revision, a rollback or an import never changes it; a store backup holds it.
func init() {
	RegisterSchema("controller_certificate", `CREATE TABLE IF NOT EXISTS controller_certificate (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), setting TEXT NOT NULL, fingerprint TEXT NOT NULL)`)
}

// ControllerCertificate returns the certificate setting of the controller and the TLS fingerprint
// it was set with; ok is false while none is set.
func (s *Store) ControllerCertificate(ctx context.Context) (setting, fingerprint string, ok bool, err error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT setting, fingerprint FROM controller_certificate WHERE id = 1`)
	if err != nil {
		return "", "", false, fmt.Errorf("store: reading the certificate setting of the controller: %w", err)
	}
	for qr.Next() {
		if err := qr.Scan(&setting, &fingerprint); err != nil {
			return "", "", false, fmt.Errorf("store: reading the certificate setting of the controller: %w", err)
		}
		ok = true
	}
	return setting, fingerprint, ok, nil
}

// SetControllerCertificate stores setting, the JSON of the certificate setting, and the TLS
// fingerprint of the certificate it gave, in place of the setting before; an empty setting removes
// it. It adds the events ev in the same transaction, so that no change is made without its record.
func (s *Store) SetControllerCertificate(ctx context.Context, setting, fingerprint string, ev ...event.Event) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM controller_certificate`)}
	if setting != "" {
		stmts = append(stmts, statement(`INSERT INTO controller_certificate (id, setting, fingerprint) VALUES (1, ?, ?)`, setting, fingerprint))
	}
	for _, e := range ev {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: event: %w", err)
		}
		// The statement of Commit for Changes.AddEvents
		stmts = append(stmts, statement(`INSERT INTO events (event) VALUES (?)`, string(b)))
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the certificate setting of the controller: %w", err)
	}
	return nil
}

// RenewFingerprint renews the lease of epoch as Renew does, and records fingerprint as the TLS
// fingerprint of its holder, which the standbys check when they forward an API call to the leader:
// its certificate changed (SDN-92). It reports whether the lease is still of that epoch.
func (s *Store) RenewFingerprint(ctx context.Context, epoch int64, fingerprint string) (bool, error) {
	r, err := s.conn.WriteOneParameterizedContext(ctx, statement(`UPDATE lease SET renewal = renewal + 1, fingerprint = ? WHERE id = 1 AND epoch = ?`, fingerprint, epoch))
	if err != nil {
		return false, fmt.Errorf("store: renewing the lease: %w", err)
	}
	return r.RowsAffected == 1, nil
}
