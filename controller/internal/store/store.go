// Package store keeps the controller's state in rqlite (#176 "Controller store"): the intent,
// one row per resource, and per node the generation of its desired state and the state it
// acknowledged last. rqlite runs beside the controller (internal/sidecar) and is reached over
// its HTTP API through gorqlite.
package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

var schema = []string{
	`CREATE TABLE IF NOT EXISTS resources (kind TEXT NOT NULL, name TEXT NOT NULL, spec TEXT NOT NULL, PRIMARY KEY (kind, name))`,
	`CREATE TABLE IF NOT EXISTS node_state (name TEXT NOT NULL PRIMARY KEY, generation INTEGER NOT NULL, desired TEXT NOT NULL, acked_generation INTEGER NOT NULL, acked TEXT NOT NULL)`,
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
