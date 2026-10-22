// Package store keeps the controller's state in rqlite (#176 "Controller store"): the intent,
// one row per resource; per node the generation of its desired state and the state it
// acknowledged last; per node static key the Capabilities that the node reported last
// (ADR-0033); every revision of the intent with its resources; and the events. rqlite runs
// beside the controller (internal/sidecar) and is reached over its HTTP API through gorqlite.
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A revision is stored as the JSON of its intent.Revision without the resources, and the JSON
// of the resources beside it, so a list of revisions reads no intent. An event is stored as the
// JSON of its event.Event, and its id is the row id.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS resources (kind TEXT NOT NULL, name TEXT NOT NULL, spec TEXT NOT NULL, PRIMARY KEY (kind, name))`,
	`CREATE TABLE IF NOT EXISTS node_state (name TEXT NOT NULL PRIMARY KEY, generation INTEGER NOT NULL, desired TEXT NOT NULL, acked_generation INTEGER NOT NULL, acked TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS node_capabilities (public_key TEXT NOT NULL PRIMARY KEY, capabilities TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS api_tokens (name TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)`,
	`CREATE TABLE IF NOT EXISTS revisions (id INTEGER PRIMARY KEY, revision TEXT NOT NULL, intent TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, event TEXT NOT NULL)`,
}

// Store is the controller's connection to rqlite.
type Store struct {
	conn *gorqlite.Connection
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
	// The Capabilities of these node static keys, which no Node resource holds any more.
	DeleteCapabilities [][]byte
	// AddRevision is a new revision, with the resources of its intent.
	AddRevision *intent.Revision
	// UpdateRevisions replace what is stored of earlier revisions, all but their resources,
	// which never change: the state of a confirmation.
	UpdateRevisions []intent.Revision
	// AddEvents are new events; the store gives them their ids.
	AddEvents []event.Event
}

// Open connects to rqlite at url and creates the tables the first time. It retries until
// rqlite answers or ctx ends, so the controller can start before its sidecar is ready.
func Open(ctx context.Context, url string) (*Store, error) {
	for {
		conn, err := gorqlite.Open(url)
		if err == nil {
			if _, err = conn.WriteContext(ctx, schema); err == nil {
				return &Store{conn: conn}, nil
			}
			conn.Close()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("store: rqlite at %s: %w", url, err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Close closes the connection.
func (s *Store) Close() {
	s.conn.Close()
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
	for _, key := range c.DeleteCapabilities {
		stmts = append(stmts, statement(`DELETE FROM node_capabilities WHERE public_key = ?`, base64.StdEncoding.EncodeToString(key)))
	}
	if r := c.AddRevision; r != nil {
		meta, rs, err := encodeRevision(*r)
		if err != nil {
			return fmt.Errorf("store: revision %d: %w", r.ID, err)
		}
		stmts = append(stmts, statement(`INSERT INTO revisions (id, revision, intent) VALUES (?, ?, ?)`, int64(r.ID), meta, rs))
	}
	for _, r := range c.UpdateRevisions {
		meta, _, err := encodeRevision(r)
		if err != nil {
			return fmt.Errorf("store: revision %d: %w", r.ID, err)
		}
		stmts = append(stmts, statement(`UPDATE revisions SET revision = ? WHERE id = ?`, meta, int64(r.ID)))
	}
	for _, e := range c.AddEvents {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: event: %w", err)
		}
		stmts = append(stmts, statement(`INSERT INTO events (event) VALUES (?)`, string(b)))
	}
	if len(stmts) == 0 {
		return nil
	}
	if _, err := s.conn.WriteParameterizedContext(ctx, stmts); err != nil {
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
	_, err = s.conn.WriteOneParameterizedContext(ctx, statement(`UPDATE node_state SET acked_generation = ?, acked = ? WHERE name = ?`,
		int64(gen), b, name))
	if err != nil {
		return fmt.Errorf("store: node %q: %w", name, err)
	}
	return nil
}

// LoadCapabilities returns the stored Capabilities by node static key (the key's bytes as a
// string).
func (s *Store) LoadCapabilities(ctx context.Context) (map[string]*controlpb.Capabilities, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT public_key, capabilities FROM node_capabilities ORDER BY public_key`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the Capabilities: %w", err)
	}
	out := map[string]*controlpb.Capabilities{}
	for qr.Next() {
		var key, caps string
		if err := qr.Scan(&key, &caps); err != nil {
			return nil, fmt.Errorf("store: reading the Capabilities: %w", err)
		}
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("store: the Capabilities of key %q: %w", key, err)
		}
		c := &controlpb.Capabilities{}
		if err := decode(caps, c); err != nil {
			return nil, fmt.Errorf("store: the Capabilities of key %q: %w", key, err)
		}
		out[string(k)] = c
	}
	return out, nil
}

// SaveCapabilities records that the node with the static key key reported the Capabilities caps.
func (s *Store) SaveCapabilities(ctx context.Context, key []byte, caps *controlpb.Capabilities) error {
	b, err := encode(caps)
	if err != nil {
		return fmt.Errorf("store: Capabilities: %w", err)
	}
	_, err = s.conn.WriteOneParameterizedContext(ctx, statement(`INSERT OR REPLACE INTO node_capabilities (public_key, capabilities) VALUES (?, ?)`,
		base64.StdEncoding.EncodeToString(key), b))
	if err != nil {
		return fmt.Errorf("store: Capabilities: %w", err)
	}
	return nil
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

// Events returns every event, oldest first.
func (s *Store) Events(ctx context.Context) ([]event.Event, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT id, event FROM events ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the events: %w", err)
	}
	out := []event.Event{}
	for qr.Next() {
		var id int64
		var b string
		if err := qr.Scan(&id, &b); err != nil {
			return nil, fmt.Errorf("store: reading the events: %w", err)
		}
		var e event.Event
		if err := json.Unmarshal([]byte(b), &e); err != nil {
			return nil, fmt.Errorf("store: reading event %d: %w", id, err)
		}
		e.ID = uint64(id)
		out = append(out, e)
	}
	return out, nil
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

func statement(query string, args ...any) gorqlite.ParameterizedStatement {
	return gorqlite.ParameterizedStatement{Query: query, Arguments: args}
}

// encodeUpdate returns the base64 of the protobuf encoding of u, the form a state is stored in.
func encodeUpdate(u *controlpb.Update) (string, error) {
	return encode(u)
}

func decodeUpdate(s string) (*controlpb.Update, error) {
	u := &controlpb.Update{}
	if err := decode(s, u); err != nil {
		return nil, err
	}
	return u, nil
}

// encode returns the base64 of the protobuf encoding of m, the form a message is stored in.
func encode(m proto.Message) (string, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decode(s string, m proto.Message) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, m)
}
