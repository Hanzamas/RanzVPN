package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The keys of the tag mode hmac (SDN-88 #387): one row for each key of a VRF in that mode, two at most
// while one replaces the other, with the VRF id, the ID of the key, the key sealed, never in clear, and
// whether the Nodes send with it. The controller seals a key as the store seals the secrets of its
// targets and the PresharedKeys of the Devices (sealed.go, devicekeys.go): to the Sealing key of the
// Sealer of SetSealer, or the Cluster key of a cluster, under the label tag_keys:VRF:ID, so the store
// alone, a backup of it or a copy of its disk does not give a key, and a sealed key that is copied to
// another row does not open there (internal/controller, tagkeys.go). The keys are no part of the
// intent, so nobody who reads the intent, an export of it or a revision holds one; a store backup holds
// them, sealed. The controller replaces the rows of a VRF when it rotates its key and deletes them when
// the VRF leaves the mode.
func init() {
	RegisterSchema("tag_keys", `CREATE TABLE IF NOT EXISTS tag_keys (vrf_id INTEGER NOT NULL, key_id INTEGER NOT NULL, sealed TEXT NOT NULL, `+
		`send INTEGER NOT NULL, PRIMARY KEY (vrf_id, key_id))`)
}

// TagKey is a row of the keys of the tag mode hmac: the ID of the key in its VRF, the base64 of the key
// sealed, and whether the Nodes send with it.
type TagKey struct {
	ID     uint32
	Sealed string
	Send   bool
}

// TagKeys returns the keys of the tag mode hmac that the store holds, by VRF id, each VRF's in the order
// of their IDs.
func (s *Store) TagKeys(ctx context.Context) (map[uint32][]TagKey, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT vrf_id, key_id, sealed, send FROM tag_keys ORDER BY vrf_id, key_id`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the keys of the tag mode hmac: %w", err)
	}
	out := map[uint32][]TagKey{}
	for qr.Next() {
		var vrf, id, send int64
		var sealed string
		if err := qr.Scan(&vrf, &id, &sealed, &send); err != nil {
			return nil, fmt.Errorf("store: reading the keys of the tag mode hmac: %w", err)
		}
		out[uint32(vrf)] = append(out[uint32(vrf)], TagKey{ID: uint32(id), Sealed: sealed, Send: send != 0})
	}
	return out, nil
}

// SetTagKeys stores keys as the keys of the tag mode hmac of the VRF vrf, in place of the ones that it had,
// in one transaction.
func (s *Store) SetTagKeys(ctx context.Context, vrf uint32, keys []TagKey) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM tag_keys WHERE vrf_id = ?`, int64(vrf))}
	for _, k := range keys {
		send := int64(0)
		if k.Send {
			send = 1
		}
		stmts = append(stmts, statement(`INSERT INTO tag_keys (vrf_id, key_id, sealed, send) VALUES (?, ?, ?, ?)`, int64(vrf), int64(k.ID), k.Sealed, send))
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the keys of the tag mode hmac: %w", err)
	}
	return nil
}

// DeleteTagKeys deletes the keys of the tag mode hmac of the VRFs vrfs, in one transaction. A VRF that has
// none is no error.
func (s *Store) DeleteTagKeys(ctx context.Context, vrfs []uint32) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, vrf := range vrfs {
		stmts = append(stmts, statement(`DELETE FROM tag_keys WHERE vrf_id = ?`, int64(vrf)))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: deleting the keys of the tag mode hmac: %w", err)
	}
	return nil
}
