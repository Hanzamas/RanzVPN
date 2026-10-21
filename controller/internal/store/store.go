// Package store keeps the controller's state in rqlite (#176 "Controller store"): the intent,
// one row per resource, per node the generation of its desired state and the state it
// acknowledged last, and the lease of the leader of a controller cluster. rqlite runs beside
// the controller (internal/sidecar) and is reached over its HTTP API through gorqlite.
//
// The controller talks to its own rqlite member only, with gorqlite's cluster discovery off:
// rqlite forwards writes and reads to its Raft leader itself, so the controller needs no
// address of another member, and rqlite's HTTP API can stay on the loopback interface.
//
// The lease (SDN-17, ADR-0026) elects the leader among the members of a controller cluster, in
// the way of the Lease of Kubernetes (client-go tools/leaderelection): the holder renews it, and
// a member takes it over once it has seen it unchanged for a whole lease duration on its own
// clock. Every take-over gives the lease a new epoch. Fenced returns the store of one epoch,
// whose writes fail with ErrNotLeader once the lease has another epoch, in the same rqlite
// transaction, so a leader that lost the lease cannot write over the one that took it.
package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rqlite/gorqlite"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

var schema = []string{
	`CREATE TABLE IF NOT EXISTS resources (kind TEXT NOT NULL, name TEXT NOT NULL, spec TEXT NOT NULL, PRIMARY KEY (kind, name))`,
	`CREATE TABLE IF NOT EXISTS node_state (name TEXT NOT NULL PRIMARY KEY, generation INTEGER NOT NULL, desired TEXT NOT NULL, acked_generation INTEGER NOT NULL, acked TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS api_tokens (name TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)`,
	`CREATE TABLE IF NOT EXISTS lease (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL, renewal INTEGER NOT NULL, holder TEXT NOT NULL, address TEXT NOT NULL, fingerprint TEXT NOT NULL)`,
	`INSERT OR IGNORE INTO lease (id, epoch, renewal, holder, address, fingerprint) VALUES (1, 0, 0, '', '', '')`,
	// The fence: a write of a fenced store first inserts a row here when the lease has another
	// epoch. The row breaks the CHECK, so rqlite rolls the whole transaction back.
	`CREATE TABLE IF NOT EXISTS fence (ok INTEGER NOT NULL CONSTRAINT not_the_leader CHECK (ok = 1))`,
}

// ErrNotLeader marks a write of a fenced store after another member took the lease.
var ErrNotLeader = errors.New("store: this controller no longer holds the lease of the leader")

// Store is the controller's connection to rqlite.
type Store struct {
	conn  *gorqlite.Connection
	epoch int64 // the lease epoch the writes are fenced with, 0 when they are not
}

// Lease is the lease of the leader of a controller cluster.
type Lease struct {
	Epoch       int64  // grows by one at every take-over and release
	Renewal     int64  // grows by one at every change, renewals included
	Holder      string // the name of the member that holds it, empty while none does
	Address     string // host:port of the holder's port, where the members forward to
	Fingerprint string // the TLS fingerprint of the holder (keys.Fingerprint)
}

// Node is the stored state of one node. Desired is the full state at Generation; Acked is the
// full state at AckedGeneration, nil while the node has acknowledged nothing.
type Node struct {
	Name            string
	Generation      uint64
	Desired         *controlpb.Update
	AckedGeneration uint64
	Acked           *controlpb.Update
}

// Changes is one change of the store, written in one rqlite transaction.
type Changes struct {
	PutResources    []intent.Resource
	DeleteResources []intent.Resource // kind and name
	PutNodes        []Node
	DeleteNodes     []string
}

// Open connects to rqlite at rawURL and creates the tables the first time. It retries until
// rqlite answers or ctx ends, so the controller can start before its sidecar is ready.
func Open(ctx context.Context, rawURL string) (*Store, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("store: rqlite at %s: %w", rawURL, err)
	}
	q := u.Query()
	q.Set("disableClusterDiscovery", "true")
	u.RawQuery = q.Encode()
	for {
		conn, err := gorqlite.Open(u.String())
		if err == nil {
			if _, err = conn.WriteContext(ctx, schema); err == nil {
				return &Store{conn: conn}, nil
			}
			conn.Close()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("store: rqlite at %s: %w", rawURL, err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Close closes the connection, also for every store that Fenced returned.
func (s *Store) Close() {
	s.conn.Close()
}

// Fenced returns the store of the leader of lease epoch epoch: it shares the connection of s,
// and each of its writes fails with ErrNotLeader, and writes nothing, once the lease has another
// epoch.
func (s *Store) Fenced(epoch int64) *Store {
	return &Store{conn: s.conn, epoch: epoch}
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

// write runs stmts in one rqlite transaction, after the fence when s is fenced.
func (s *Store) write(ctx context.Context, stmts []gorqlite.ParameterizedStatement) error {
	if s.epoch != 0 {
		fence := statement(`INSERT INTO fence (ok) SELECT 0 FROM lease WHERE id = 1 AND epoch <> ?`, s.epoch)
		stmts = append([]gorqlite.ParameterizedStatement{fence}, stmts...)
	}
	_, err := s.conn.WriteParameterizedContext(ctx, stmts)
	if err != nil && s.epoch != 0 && strings.Contains(err.Error(), "CHECK constraint failed") {
		return ErrNotLeader
	}
	return err
}

// Load returns the stored resources and nodes.
func (s *Store) Load(ctx context.Context) ([]intent.Resource, []Node, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT kind, name, spec FROM resources ORDER BY kind, name`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: reading the intent: %w", err)
	}
	var rs []intent.Resource
	for qr.Next() {
		var kind, name, spec string
		if err := qr.Scan(&kind, &name, &spec); err != nil {
			return nil, nil, fmt.Errorf("store: reading the intent: %w", err)
		}
		rs = append(rs, intent.Resource{Kind: kind, Name: name, Spec: []byte(spec)})
	}
	qr, err = s.conn.QueryOneContext(ctx, `SELECT name, generation, desired, acked_generation, acked FROM node_state ORDER BY name`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: reading the node states: %w", err)
	}
	var nodes []Node
	for qr.Next() {
		var name, desired, acked string
		var gen, ackedGen int64
		if err := qr.Scan(&name, &gen, &desired, &ackedGen, &acked); err != nil {
			return nil, nil, fmt.Errorf("store: reading the node states: %w", err)
		}
		n := Node{Name: name, Generation: uint64(gen), AckedGeneration: uint64(ackedGen)}
		if n.Desired, err = decodeUpdate(desired); err != nil {
			return nil, nil, fmt.Errorf("store: node %q: desired state: %w", name, err)
		}
		if acked != "" {
			if n.Acked, err = decodeUpdate(acked); err != nil {
				return nil, nil, fmt.Errorf("store: node %q: acknowledged state: %w", name, err)
			}
		}
		nodes = append(nodes, n)
	}
	return rs, nodes, nil
}

// Commit writes c in one rqlite transaction: all of it or nothing.
func (s *Store) Commit(ctx context.Context, c Changes) error {
	var stmts []gorqlite.ParameterizedStatement
	for _, r := range c.PutResources {
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO resources (kind, name, spec) VALUES (?, ?, ?)`,
			r.Kind, r.Name, string(r.Spec)))
	}
	for _, r := range c.DeleteResources {
		stmts = append(stmts, statement(`DELETE FROM resources WHERE kind = ? AND name = ?`, r.Kind, r.Name))
	}
	for _, n := range c.PutNodes {
		desired, err := encodeUpdate(n.Desired)
		if err != nil {
			return fmt.Errorf("store: node %q: %w", n.Name, err)
		}
		acked := ""
		if n.Acked != nil {
			if acked, err = encodeUpdate(n.Acked); err != nil {
				return fmt.Errorf("store: node %q: %w", n.Name, err)
			}
		}
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO node_state (name, generation, desired, acked_generation, acked) VALUES (?, ?, ?, ?, ?)`,
			n.Name, int64(n.Generation), desired, int64(n.AckedGeneration), acked))
	}
	for _, name := range c.DeleteNodes {
		stmts = append(stmts, statement(`DELETE FROM node_state WHERE name = ?`, name))
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// SaveAck records that node name acknowledged generation gen, whose full state is acked.
func (s *Store) SaveAck(ctx context.Context, name string, gen uint64, acked *controlpb.Update) error {
	b, err := encodeUpdate(acked)
	if err != nil {
		return fmt.Errorf("store: node %q: %w", name, err)
	}
	err = s.write(ctx, []gorqlite.ParameterizedStatement{statement(`UPDATE node_state SET acked_generation = ?, acked = ? WHERE name = ?`,
		int64(gen), b, name)})
	if err != nil {
		return fmt.Errorf("store: node %q: %w", name, err)
	}
	return nil
}

func statement(query string, args ...any) gorqlite.ParameterizedStatement {
	return gorqlite.ParameterizedStatement{Query: query, Arguments: args}
}

// encodeUpdate returns the base64 of the protobuf encoding of u, the form a state is stored in.
func encodeUpdate(u *controlpb.Update) (string, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(u)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decodeUpdate(s string) (*controlpb.Update, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	u := &controlpb.Update{}
	if err := proto.Unmarshal(b, u); err != nil {
		return nil, err
	}
	return u, nil
}
