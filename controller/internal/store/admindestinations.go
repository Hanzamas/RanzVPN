package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The admin destination lists (AUD1-DT-9, #457): where an operator may point the Controller and the
// Nodes, one row for each entry, in the text that intent.Destinations.Normalize makes of it. The
// list of a row is one of the three below. No row means an empty list. They are not part of the
// intent, so a revision, a rollback or an import never changes them; a store backup holds them.
func init() {
	RegisterSchema("admin_destinations", `CREATE TABLE IF NOT EXISTS admin_destinations (list TEXT NOT NULL, entry TEXT NOT NULL, PRIMARY KEY (list, entry))`)
}

// The lists of admin_destinations.
const (
	listTargets    = "targets"
	listSensors    = "sensors"
	listUNCServers = "uncServers"
)

// AdminDestinations returns the admin destination lists, each ordered, each empty when it holds
// no entry.
func (s *Store) AdminDestinations(ctx context.Context) (intent.Destinations, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT list, entry FROM admin_destinations ORDER BY list, entry`)
	if err != nil {
		return intent.Destinations{}, fmt.Errorf("store: reading the admin destination lists: %w", err)
	}
	out := intent.Destinations{Targets: []string{}, Sensors: []string{}, UNCServers: []string{}}
	for qr.Next() {
		var list, entry string
		if err := qr.Scan(&list, &entry); err != nil {
			return intent.Destinations{}, fmt.Errorf("store: reading the admin destination lists: %w", err)
		}
		switch list {
		case listTargets:
			out.Targets = append(out.Targets, entry)
		case listSensors:
			out.Sensors = append(out.Sensors, entry)
		case listUNCServers:
			out.UNCServers = append(out.UNCServers, entry)
		}
	}
	return out, nil
}

// SetAdminDestinations replaces the admin destination lists with d, whose lists hold no entry twice,
// and adds the events ev in the same transaction, so that no change is made without its record.
func (s *Store) SetAdminDestinations(ctx context.Context, d intent.Destinations, ev ...event.Event) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM admin_destinations`)}
	for list, entries := range map[string][]string{listTargets: d.Targets, listSensors: d.Sensors, listUNCServers: d.UNCServers} {
		for _, e := range entries {
			stmts = append(stmts, statement(`INSERT INTO admin_destinations (list, entry) VALUES (?, ?)`, list, e))
		}
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
		return fmt.Errorf("store: writing the admin destination lists: %w", err)
	}
	return nil
}

// Addr returns the host and the port of the rqlite that the store is connected to, host:port, or an
// empty string when the address has no port. The Controller keeps its targets from it (export.Guard):
// its HTTP API asks for no credential.
func (s *Store) Addr() string {
	u, err := url.Parse(s.url)
	if err != nil || u.Port() == "" {
		return ""
	}
	return u.Host
}
