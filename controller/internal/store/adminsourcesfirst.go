package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// SetFirstAdminSources sets the admin source allowlist to prefixes, which hold no prefix twice, and adds the events ev, in one
// transaction, but only when the store holds no admin source allowlist yet. The members of a controller cluster that start fresh at
// the same time each make the first start, and each would set the list that its own -admin-from names (AUD1-DT-15, #497): with
// SetAdminSources the last write wins, and the log of every member names its own list. Here the first write wins, as one statement
// that tests for an empty list decides it, and the others write nothing, not a prefix and not an event. It reports whether this write
// was the one that was made, and false, with nothing written, when the store holds a list already or prefixes is empty.
func (s *Store) SetFirstAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) (bool, error) {
	if len(prefixes) == 0 {
		return false, nil
	}
	var stmts []gorqlite.ParameterizedStatement
	// The events come first: while they are written the list is still empty, which the prefixes then end
	for _, e := range ev {
		b, err := json.Marshal(e)
		if err != nil {
			return false, fmt.Errorf("store: event: %w", err)
		}
		stmts = append(stmts, statement(`INSERT INTO events (event) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM admin_sources)`, string(b)))
	}
	// All the prefixes in one statement, so the test for an empty list is made once, before the first of them is written
	terms := make([]string, len(prefixes))
	args := make([]any, len(prefixes))
	for i, p := range prefixes {
		terms[i], args[i] = `SELECT ? AS prefix`, p
	}
	stmts = append(stmts, statement(`INSERT INTO admin_sources (prefix) SELECT prefix FROM (`+strings.Join(terms, ` UNION ALL `)+`) WHERE NOT EXISTS (SELECT 1 FROM admin_sources)`, args...))
	wrs, err := s.conn.WriteParameterizedContext(ctx, stmts)
	if err != nil {
		return false, fmt.Errorf("store: writing the admin source allowlist: %w", err)
	}
	return len(wrs) > 0 && wrs[len(wrs)-1].RowsAffected > 0, nil
}
