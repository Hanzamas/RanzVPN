package store

import (
	"context"
	"fmt"
)

// SetTokenRole gives the API token name the role role in place, its secret unchanged (SDN-32, the
// decision of 2026-10-22 on #226), unless that takes the role keep from the last token that holds it,
// in one statement, so two changes at once cannot both pass the check. It reports false, and changes
// nothing, when there is no such token or it is the last one of keep.
func (s *Store) SetTokenRole(ctx context.Context, name, role, keep string) (bool, error) {
	wr, err := s.conn.WriteOneParameterizedContext(ctx, statement(
		`UPDATE api_tokens SET role = ? WHERE name = ? AND (role != ? OR ? = ? OR (SELECT COUNT(*) FROM api_tokens WHERE role = ?) > 1)`,
		role, name, keep, role, keep, keep))
	if err != nil {
		return false, fmt.Errorf("store: changing the role of a token: %w", err)
	}
	return wr.RowsAffected > 0, nil
}
