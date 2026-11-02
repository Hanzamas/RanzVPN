package store

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// The numbers of the source groups (SDN-87 #386): one row for each group ID that the controller gave a set of tags in a
// VRF, by the VRF id and the tags of the set, sorted and joined by commas; and one for each bit of the tag set that it
// gave a tag. They are no intent, so a revision, a rollback or an import never changes a row and an Intent export holds
// none; a store backup holds them. No row is changed or deleted: a number stays with its set or its tag for good, also
// once no endpoint of the VRF has them and once the VRF is gone, as its id can come back with another VRF, so that a Node
// that forwards on an older Generation never reads a claim in another numbering (internal/controller, sourcegroup.go).
// The unique keys refuse a write that would give a number of a VRF to a second set or tag.
func init() {
	RegisterSchema("source_groups",
		`CREATE TABLE IF NOT EXISTS source_group_ids (vrf_id INTEGER NOT NULL, tags TEXT NOT NULL, group_id INTEGER NOT NULL, `+
			`PRIMARY KEY (vrf_id, tags), UNIQUE (vrf_id, group_id))`,
		`CREATE TABLE IF NOT EXISTS source_group_bits (vrf_id INTEGER NOT NULL, tag TEXT NOT NULL, bit INTEGER NOT NULL, `+
			`PRIMARY KEY (vrf_id, tag), UNIQUE (vrf_id, bit))`)
}

// SourceGroupNumbers are the numbers of the source groups of one VRF: the group ID of each set of tags, by the tags of the
// set sorted and joined by commas ("" for the set without a tag), and the bit of the tag set of each tag.
type SourceGroupNumbers struct {
	Groups map[string]uint32
	Bits   map[string]uint
}

// SourceGroups returns the numbers of the source groups that the store holds, by VRF id. A new store holds none.
func (s *Store) SourceGroups(ctx context.Context) (map[uint32]SourceGroupNumbers, error) {
	out := map[uint32]SourceGroupNumbers{}
	of := func(id int64) SourceGroupNumbers {
		v, ok := out[uint32(id)]
		if !ok {
			v = SourceGroupNumbers{Groups: map[string]uint32{}, Bits: map[string]uint{}}
			out[uint32(id)] = v
		}
		return v
	}
	qr, err := s.conn.QueryOneContext(ctx, `SELECT vrf_id, tags, group_id FROM source_group_ids ORDER BY vrf_id, group_id`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the group IDs of the source groups: %w", err)
	}
	for qr.Next() {
		var id, group int64
		var tags string
		if err := qr.Scan(&id, &tags, &group); err != nil {
			return nil, fmt.Errorf("store: reading the group IDs of the source groups: %w", err)
		}
		of(id).Groups[tags] = uint32(group)
	}
	qr, err = s.conn.QueryOneContext(ctx, `SELECT vrf_id, tag, bit FROM source_group_bits ORDER BY vrf_id, bit`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the bits of the tag sets: %w", err)
	}
	for qr.Next() {
		var id, bit int64
		var tag string
		if err := qr.Scan(&id, &tag, &bit); err != nil {
			return nil, fmt.Errorf("store: reading the bits of the tag sets: %w", err)
		}
		of(id).Bits[tag] = uint(bit)
	}
	return out, nil
}

// AddSourceGroups stores the numbers add by VRF id beside the ones that the store holds, in one transaction. A number that
// the store holds already, for the same set or tag, is no error and stays as it is. Another number for a set or a tag that
// has one, or a number that another set or tag of the VRF has, fails the whole write, which then stores nothing.
func (s *Store) AddSourceGroups(ctx context.Context, add map[uint32]SourceGroupNumbers) error {
	var stmts []gorqlite.ParameterizedStatement
	for id, v := range add {
		for tags, group := range v.Groups {
			stmts = append(stmts, statement(`INSERT INTO source_group_ids (vrf_id, tags, group_id) SELECT ?, ?, ? WHERE NOT EXISTS `+
				`(SELECT 1 FROM source_group_ids WHERE vrf_id = ? AND tags = ? AND group_id = ?)`,
				int64(id), tags, int64(group), int64(id), tags, int64(group)))
		}
		for tag, bit := range v.Bits {
			stmts = append(stmts, statement(`INSERT INTO source_group_bits (vrf_id, tag, bit) SELECT ?, ?, ? WHERE NOT EXISTS `+
				`(SELECT 1 FROM source_group_bits WHERE vrf_id = ? AND tag = ? AND bit = ?)`,
				int64(id), tag, int64(bit), int64(id), tag, int64(bit)))
		}
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the numbers of the source groups: %w", err)
	}
	return nil
}
