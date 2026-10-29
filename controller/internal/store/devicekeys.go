package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The PresharedKeys of the WireGuard Devices (SDN-82, #377): one row for each Device that has one, with
// the name of the Device and the key sealed, never in clear. The controller seals it as the store seals
// the secrets of its targets (sealed.go): to the Sealing key of the Sealer of SetSealer, under the label
// device_keys:NAME, so the store alone, a backup of it or a copy of its disk does not give a
// PresharedKey, and a sealed key that is copied to the row of another Device does not open there
// (internal/controller, devicekeys.go). The keys are not part of the intent, so that nobody who reads the
// intent, an export of it or a revision holds one, and a rollback or an import never changes one; a store
// backup holds them, sealed. The controller deletes the row of a Device that a change of the intent
// removes. The private key of a Device has no row: the controller never keeps it.
func init() {
	RegisterSchema("device_keys", `CREATE TABLE IF NOT EXISTS device_keys (name TEXT NOT NULL PRIMARY KEY, sealed TEXT NOT NULL)`)
}

// Sealer returns the Sealer that SetSealer gave the store, which the controller seals the PresharedKeys
// of the Devices with, nil when the store has none: a member of a cluster, whose members have no sealing
// key in common (ADR-0026), or a store that SetSealer was not called on. The stores that Fenced makes
// share it.
func (s *Store) Sealer() Sealer {
	if s.seal == nil {
		return nil
	}
	return s.seal.sealer
}

// DeviceKeys returns the sealed PresharedKey of every Device that has one, as base64, by Device name.
func (s *Store) DeviceKeys(ctx context.Context) (map[string]string, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, sealed FROM device_keys ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the PresharedKeys of the Devices: %w", err)
	}
	out := map[string]string{}
	for qr.Next() {
		var name, sealed string
		if err := qr.Scan(&name, &sealed); err != nil {
			return nil, fmt.Errorf("store: reading the PresharedKeys of the Devices: %w", err)
		}
		out[name] = sealed
	}
	return out, nil
}

// SetDeviceKey stores sealed, the base64 of a sealed PresharedKey, as the PresharedKey of the Device
// name, in place of the one it had.
func (s *Store) SetDeviceKey(ctx context.Context, name, sealed string) error {
	err := s.write(ctx, []gorqlite.ParameterizedStatement{statement(`INSERT OR REPLACE INTO device_keys (name, sealed) VALUES (?, ?)`, name, sealed)})
	if err != nil {
		return fmt.Errorf("store: writing the PresharedKey of a Device: %w", err)
	}
	return nil
}

// DeleteDeviceKeys deletes the PresharedKeys of the Devices names, in one transaction. A Device that
// has none is no error.
func (s *Store) DeleteDeviceKeys(ctx context.Context, names []string) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, name := range names {
		stmts = append(stmts, statement(`DELETE FROM device_keys WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the PresharedKeys of Devices: %w", err)
	}
	return nil
}
