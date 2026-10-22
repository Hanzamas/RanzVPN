// Package controller is the controller of #176: the single authority that keeps the intent in
// rqlite, compiles it into the desired state of each node with a generation number, and pushes
// that state over the control stream as deltas against the generation each node acknowledged
// last (#176 "Control protocol"). Every change of the intent is a revision, which can be diffed
// and rolled back (ADR-0031, revision.go). In a controller cluster the leader runs it
// (internal/cluster).
package controller

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// SchemaVersion is the newest control schema version of this controller (N). It serves nodes of
// version N and N-1.
const SchemaVersion = controlpb.SchemaVersion_SCHEMA_VERSION_2

const (
	helloTimeout = 10 * time.Second // from the end of the handshake to the Hello
	writeTimeout = 10 * time.Second // for a Refuse, the last frame of a stream
	storeTimeout = 30 * time.Second // for one store write
	// maxRefuseMessage is the size of Refuse.message on the C node (control.options), without
	// the terminating NUL.
	maxRefuseMessage = 255
)

// Config is what a controller runs with.
type Config struct {
	Store  *store.Store
	Key    keys.Static  // the controller's Noise static key
	Log    *slog.Logger // discarded when nil
	Random io.Reader    // draws the ULA of a new VRF; crypto/rand when nil
	// Schema is the control schema version the controller runs as, SchemaVersion when it is
	// unspecified. In a rolling upgrade of a cluster, the members of the new release run as
	// SchemaVersion-1, the version of the old release, until every member runs the new one
	// (SDN-17): they serve the nodes the old release serves, send nothing that version does
	// not have, and refuse the resources it does not know.
	Schema controlpb.SchemaVersion
}

// NodeGeneration is the generation of a node's desired state.
type NodeGeneration struct {
	Name       string `json:"name"`
	Generation uint64 `json:"generation"`
}

// ApplyResult is the answer to a change of the intent (an apply, a delete or a rollback): the
// revision it made, and the nodes whose desired state it changed, with their new generations.
type ApplyResult struct {
	Revision uint64           `json:"revision"`
	Nodes    []NodeGeneration `json:"nodes"`
	// ConfirmBy is set for an apply with a confirmation time: the controller rolls the revision
	// back then unless it is confirmed first.
	ConfirmBy time.Time `json:"confirmBy,omitzero"`
}

// NodeStatus is what the controller knows about one node.
type NodeStatus struct {
	Name            string `json:"name"`
	Generation      uint64 `json:"generation"`      // of the desired state
	AckedGeneration uint64 `json:"ackedGeneration"` // the last one the node acknowledged
	Connected       bool   `json:"connected"`
}

// Controller holds the intent and the desired state of every node.
type Controller struct {
	store  *store.Store
	key    keys.Static
	log    *slog.Logger
	random io.Reader
	schema controlpb.SchemaVersion

	mu      sync.Mutex
	intent  intent.Intent
	members *controlpb.Controllers // the Controller resources of the intent, for nodes of version 2
	nodes   map[string]*node
	byKey   map[string]string // node static key to node name
	conns   map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup

	// The revisions, guarded by mu.
	revision uint64           // the latest revision, 0 before the first
	pending  *intent.Revision // the revision that waits for confirmation, nil if none
	timer    *time.Timer      // rolls pending back at its deadline
}

// node is the desired state of one node and what the node acknowledged of it.
type node struct {
	gen      uint64
	state    desired.State
	ackedGen uint64
	acked    desired.State // the state at ackedGen, nil while ackedGen is 0
	stream   *stream       // the node's control stream, nil while it has none
}

// stream is the control stream of one node.
type stream struct {
	conn *control.Conn
	name string
	wake chan struct{} // the writer has something to look at
	done chan struct{}
	once sync.Once

	// Guarded by Controller.mu.
	version  controlpb.SchemaVersion // of the node's Hello
	known    bool                    // base is the state the node holds, at baseGen
	base     desired.State           // nil at baseGen 0
	baseGen  uint64
	inflight uint64                 // the generation sent and not yet acknowledged, 0 if none
	sent     desired.State          // the state of inflight
	members  *controlpb.Controllers // the Controllers message sent last, nil before the first
	refusal  *controlpb.Refuse
}

// New loads the intent and the node states from the store and reconciles them: a node whose
// compiled state differs from its stored one gets a new generation. A revision that waited for
// confirmation when the controller stopped waits again until its deadline, or is rolled back at
// once if the deadline passed.
func New(ctx context.Context, cfg Config) (*Controller, error) {
	c := &Controller{
		store:  cfg.Store,
		key:    cfg.Key,
		log:    cfg.Log,
		random: cfg.Random,
		schema: cfg.Schema,
		intent: intent.New(),
		nodes:  map[string]*node{},
		byKey:  map[string]string{},
		conns:  map[net.Conn]struct{}{},
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.random == nil {
		c.random = rand.Reader
	}
	if c.schema == controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED {
		c.schema = SchemaVersion
	}
	if c.schema != SchemaVersion && c.schema != SchemaVersion-1 {
		return nil, fmt.Errorf("controller: schema version %d: this release runs as version %d or %d", int32(c.schema), int32(SchemaVersion), int32(SchemaVersion-1))
	}
	rs, stored, err := c.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		return nil, err
	}
	for _, sn := range stored {
		n := &node{gen: sn.Generation, ackedGen: sn.AckedGeneration}
		if n.state, err = desired.FromFull(sn.Desired); err != nil {
			return nil, fmt.Errorf("stored node %q: %w", sn.Name, err)
		}
		if sn.Acked != nil {
			if n.acked, err = desired.FromFull(sn.Acked); err != nil {
				return nil, fmt.Errorf("stored node %q: %w", sn.Name, err)
			}
		}
		c.nodes[sn.Name] = n
	}
	c.intent = in
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.commit(ctx, in, store.Changes{}); err != nil {
		return nil, err
	}
	last, ok, err := c.store.LastRevision(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		c.revision = last.ID
		if last.Confirm != nil && last.Confirm.State == intent.ConfirmPending {
			c.await(last, time.Until(last.Confirm.Deadline))
		}
	}
	c.log.Info("intent loaded", "resources", len(rs), "nodes", len(c.nodes), "revision", c.revision, "schema", int32(c.schema))
	return c, nil
}

// PublicKey returns the controller's static public key, which a node needs to open a stream.
func (c *Controller) PublicKey() []byte {
	return c.key.Public()
}

// Schema returns the control schema version the controller runs as.
func (c *Controller) Schema() controlpb.SchemaVersion {
	return c.schema
}

// Apply applies doc to the intent (`ranz apply -f`) as the next revision.
func (c *Controller) Apply(ctx context.Context, doc intent.Document) (ApplyResult, error) {
	return c.ApplyConfirm(ctx, doc, 0)
}

// ApplyConfirm applies doc to the intent as the next revision. With a confirm above 0
// (`ranz apply --confirm`), the controller rolls that revision back by itself after confirm,
// unless Confirm confirms it first; until then it takes no other change but a rollback.
func (c *Controller) ApplyConfirm(ctx context.Context, doc intent.Document, confirm time.Duration) (ApplyResult, error) {
	if confirm != 0 && (confirm < MinConfirm || confirm > MaxConfirm) {
		return ApplyResult{}, fmt.Errorf("%w: %v is not between %v and %v", ErrBadConfirm, confirm, MinConfirm, MaxConfirm)
	}
	if err := c.known(doc.Resources); err != nil {
		return ApplyResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.unconfirmed(); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Apply(c.intent, doc, c.random)
	if err != nil {
		return ApplyResult{}, err
	}
	rev := c.nextRevision(intent.OpApply)
	if confirm > 0 {
		rev.Confirm = &intent.Confirmation{Deadline: rev.Time.Add(confirm), State: intent.ConfirmPending}
	}
	res, err := c.change(ctx, next, rev, store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	if confirm > 0 {
		c.await(rev, confirm)
		res.ConfirmBy = rev.Confirm.Deadline
	}
	c.log.Info("intent applied", "revision", res.Revision, "resources", len(doc.Resources), "changed", len(res.Nodes), "confirm", confirm)
	return res, nil
}

// Delete deletes the resource kind/name from the intent as the next revision.
func (c *Controller) Delete(ctx context.Context, kind, name string) (ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.unconfirmed(); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Delete(c.intent, kind, name)
	if err != nil {
		return ApplyResult{}, err
	}
	res, err := c.change(ctx, next, c.nextRevision(intent.OpDelete), store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	c.log.Info("resource deleted", "kind", kind, "name", name, "revision", res.Revision, "changed", len(res.Nodes))
	return res, nil
}

// Resources returns the intent.
func (c *Controller) Resources() []intent.Resource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.intent.Resources()
}

// Nodes returns the status of every node, ordered by name.
func (c *Controller) Nodes() []NodeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []NodeStatus{}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		n := c.nodes[name]
		out = append(out, NodeStatus{Name: name, Generation: n.gen, AckedGeneration: n.ackedGen, Connected: n.stream != nil})
	}
	return out
}

// ServeStream serves the control stream of one node on tc, a TLS connection that negotiated
// control.ALPN on the controller's port (internal/port), and returns when the stream ends.
func (c *Controller) ServeStream(tc *tls.Conn) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		tc.Close()
		return
	}
	c.conns[tc] = struct{}{}
	c.wg.Add(1)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.conns, tc)
		c.mu.Unlock()
		c.wg.Done()
	}()
	c.serveConn(tc)
}

// Close closes every control stream and waits until their goroutines end. Stop the port first,
// so no new stream starts.
func (c *Controller) Close() {
	c.mu.Lock()
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	for raw := range c.conns {
		raw.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// commit makes next the intent: it compiles the desired state of every node, gives each node
// whose state changed the next generation, writes the intent and those states to the store in
// one transaction together with the further changes of ch, and then wakes the streams of the
// changed nodes. c.mu is held.
func (c *Controller) commit(ctx context.Context, next intent.Intent, ch store.Changes) ([]NodeGeneration, error) {
	states, err := desired.Compile(next)
	if err != nil {
		return nil, err
	}
	ch.PutResources, ch.DeleteResources = intent.Changed(c.intent, next)
	result := []NodeGeneration{}
	for _, name := range slices.Sorted(maps.Keys(states)) {
		st := states[name]
		sn := store.Node{Name: name, Generation: 1}
		if n := c.nodes[name]; n != nil {
			if desired.Equal(n.state, st) {
				continue
			}
			sn.Generation = n.gen + 1
			sn.AckedGeneration = n.ackedGen
			if n.acked != nil {
				sn.Acked = desired.Full(n.acked, n.ackedGen)
			}
		}
		sn.Desired = desired.Full(st, sn.Generation)
		ch.PutNodes = append(ch.PutNodes, sn)
		result = append(result, NodeGeneration{Name: name, Generation: sn.Generation})
	}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		if _, ok := states[name]; !ok {
			ch.DeleteNodes = append(ch.DeleteNodes, name)
		}
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.Commit(sctx, ch); err != nil {
		return nil, err
	}

	c.intent = next
	if m := members(next); !proto.Equal(m, c.members) {
		c.members = m
		for _, n := range c.nodes {
			if n.stream != nil {
				n.stream.poke()
			}
		}
	}
	for _, ng := range result {
		n := c.nodes[ng.Name]
		if n == nil {
			n = &node{}
			c.nodes[ng.Name] = n
		}
		n.gen, n.state = ng.Generation, states[ng.Name]
		if n.stream != nil {
			n.stream.poke()
		}
	}
	for _, name := range ch.DeleteNodes {
		if s := c.nodes[name].stream; s != nil {
			c.refuse(s, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "the Node resource %q was deleted", name)
		}
		delete(c.nodes, name)
	}
	c.byKey = map[string]string{}
	for name, n := range next.Nodes {
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		c.byKey[string(k)] = name
	}
	for name, n := range c.nodes {
		if n.stream != nil && c.byKey[string(n.stream.conn.PeerKey())] != name {
			c.refuse(n.stream, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "the publicKey of the Node resource %q changed", name)
		}
	}
	return result, nil
}

// refuse detaches s from its node and has its writer send a Refuse and close it. c.mu is held.
func (c *Controller) refuse(s *stream, reason controlpb.RefuseReason, format string, args ...any) {
	if n := c.nodes[s.name]; n != nil && n.stream == s {
		n.stream = nil
	}
	s.refusal = refusal(reason, format, args...)
	s.poke()
}

// serveConn runs one control stream: the Noise handshake, the Hello, then the node's Acks on
// this goroutine and the updates on a writer goroutine.
func (c *Controller) serveConn(tc *tls.Conn) {
	conn, err := control.Accept(context.Background(), tc, c.key)
	if err != nil {
		c.log.Warn("control stream handshake failed", "remote", tc.RemoteAddr().String(), "err", err)
		return
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(helloTimeout)); err != nil {
		return
	}
	m, _, err := conn.Read()
	if err != nil {
		c.log.Warn("control stream closed before its Hello", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	hello := m.GetHello()
	if hello == nil {
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "the first frame must be a Hello"))
		return
	}
	if v := hello.GetSchemaVersion(); !c.served(v) {
		c.log.Warn("node refused: schema version", "remote", conn.RemoteAddr().String(), "version", int32(v))
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_SCHEMA_VERSION,
			"schema version %d is not served: this controller serves version %d and the one before it", int32(v), int32(c.schema)))
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	s := &stream{conn: conn, wake: make(chan struct{}, 1), done: make(chan struct{}), version: hello.GetSchemaVersion()}
	c.mu.Lock()
	name, ok := c.byKey[string(conn.PeerKey())]
	if !ok || c.closed {
		c.mu.Unlock()
		c.log.Warn("node refused: unknown static key", "remote", conn.RemoteAddr().String())
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "no Node resource has the static key of this node"))
		return
	}
	s.name = name
	n := c.nodes[name]
	if n.stream != nil {
		// A new stream of the node replaces its old one.
		n.stream.shut()
	}
	n.stream = s
	c.hello(n, s, hello.GetAppliedGeneration())
	c.wg.Add(1)
	c.mu.Unlock()
	c.log.Info("node connected", "node", name, "remote", conn.RemoteAddr().String(), "applied", hello.GetAppliedGeneration())

	go func() {
		defer c.wg.Done()
		c.writeLoop(s)
	}()
	s.poke()
	c.readLoop(s)
	s.shut()

	c.mu.Lock()
	if n := c.nodes[name]; n != nil && n.stream == s {
		n.stream = nil
	}
	c.mu.Unlock()
	c.log.Info("node disconnected", "node", name)
}

// hello records where the node of s stands: the generation it applied last. c.mu is held.
func (c *Controller) hello(n *node, s *stream, applied uint64) {
	switch {
	case applied == 0:
		s.known, s.base, s.baseGen = true, nil, 0
	case applied == n.gen:
		// The node runs the current generation. Its Ack may have been lost when the controller
		// stopped, so it counts as acknowledged now.
		s.known, s.base, s.baseGen = true, n.state, n.gen
		if n.ackedGen != n.gen {
			c.saveAck(s.name, n, n.gen, n.state)
		}
	case applied == n.ackedGen:
		s.known, s.base, s.baseGen = true, n.acked, n.ackedGen
	case applied > n.gen:
		// The node runs a generation this controller never issued: the store lost state. The
		// node gets the full state as a generation after its own.
		s.known = false
		n.gen = applied + 1
		sn := store.Node{Name: s.name, Generation: n.gen, Desired: desired.Full(n.state, n.gen), AckedGeneration: n.ackedGen}
		if n.acked != nil {
			sn.Acked = desired.Full(n.acked, n.ackedGen)
		}
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
		if err := c.store.Commit(ctx, store.Changes{PutNodes: []store.Node{sn}}); err != nil {
			c.log.Error("storing a node state", "node", s.name, "generation", n.gen, "err", err)
		}
	default:
		// A generation the controller has no state of: the node gets the full state.
		s.known = false
	}
}

// readLoop reads the node's Acks until the stream ends.
func (c *Controller) readLoop(s *stream) {
	for {
		m, _, err := s.conn.Read()
		if err != nil {
			return
		}
		ack := m.GetAck()
		if ack == nil {
			writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "a node sends only Acks after its Hello"))
			return
		}
		c.mu.Lock()
		err = c.ack(s, ack.GetGeneration())
		c.mu.Unlock()
		if err != nil {
			c.log.Warn("node refused: bad Ack", "node", s.name, "err", err)
			writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
			return
		}
		s.poke()
	}
}

// ack records that the node of s applied generation gen. c.mu is held.
func (c *Controller) ack(s *stream, gen uint64) error {
	if s.inflight == 0 || gen != s.inflight {
		return fmt.Errorf("an Ack of generation %d, but the generation in flight is %d", gen, s.inflight)
	}
	s.known, s.base, s.baseGen = true, s.sent, s.inflight
	s.inflight, s.sent = 0, nil
	if n := c.nodes[s.name]; n != nil && n.stream == s {
		c.saveAck(s.name, n, gen, s.base)
	}
	c.log.Info("node acknowledged", "node", s.name, "generation", gen)
	return nil
}

// saveAck records that node name acknowledged generation gen with state. c.mu is held.
func (c *Controller) saveAck(name string, n *node, gen uint64, state desired.State) {
	n.ackedGen, n.acked = gen, state
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.store.SaveAck(ctx, name, gen, desired.Full(state, gen)); err != nil {
		c.log.Error("storing an acknowledgement", "node", name, "generation", gen, "err", err)
	}
}

// writeLoop sends the node of s the updates it lacks, one at a time: the next one after the Ack
// of the one before. It ends with the stream, or after sending a Refuse.
func (c *Controller) writeLoop(s *stream) {
	for {
		select {
		case <-s.wake:
		case <-s.done:
			return
		}
		c.mu.Lock()
		r := s.refusal
		var m *controlpb.Controllers
		var u *controlpb.Update
		if r == nil {
			m = c.nextMembers(s)
			u = c.nextUpdate(s)
		}
		c.mu.Unlock()
		if r != nil {
			c.log.Info("node refused", "node", s.name, "reason", r.GetReason().String(), "message", r.GetMessage())
			writeRefuse(s.conn, r)
			s.shut()
			return
		}
		if m != nil {
			if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Controllers{Controllers: m}}); err != nil {
				c.log.Warn("sending the controllers", "node", s.name, "err", err)
				s.shut()
				return
			}
			c.log.Info("controllers sent", "node", s.name, "controllers", len(m.GetControllers()))
		}
		if u == nil {
			continue
		}
		if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Update{Update: u}}); err != nil {
			c.log.Warn("sending an update", "node", s.name, "generation", u.GetGeneration(), "err", err)
			s.shut()
			return
		}
		c.log.Info("update sent", "node", s.name, "generation", u.GetGeneration(), "base", u.GetBaseGeneration(),
			"set", len(u.GetSet()), "remove", len(u.GetRemove()))
	}
}

// nextUpdate returns the update the node of s lacks, or nil if it has the current generation or
// an update is in flight. c.mu is held.
func (c *Controller) nextUpdate(s *stream) *controlpb.Update {
	n := c.nodes[s.name]
	if n == nil || n.stream != s || s.inflight != 0 || (s.known && s.baseGen == n.gen) {
		return nil
	}
	var u *controlpb.Update
	if s.known {
		u = desired.Delta(s.base, s.baseGen, n.state, n.gen)
	} else {
		u = desired.Full(n.state, n.gen)
	}
	s.inflight, s.sent = n.gen, n.state
	return u
}

// nextMembers returns the Controllers message the node of s lacks: none for a node of schema
// version 1, which does not have the message, and none when the node has the current one.
// c.mu is held.
func (c *Controller) nextMembers(s *stream) *controlpb.Controllers {
	n := c.nodes[s.name]
	if n == nil || n.stream != s || s.version < controlpb.SchemaVersion_SCHEMA_VERSION_2 ||
		(s.members != nil && proto.Equal(s.members, c.members)) {
		return nil
	}
	s.members = c.members
	return c.members
}

// members returns the Controllers message of in: its Controller resources, ordered by name.
func members(in intent.Intent) *controlpb.Controllers {
	m := &controlpb.Controllers{}
	for _, name := range slices.Sorted(maps.Keys(in.Controllers)) {
		ct := in.Controllers[name]
		// Apply validated the key.
		k, _ := intent.ParseKey(ct.PublicKey)
		m.Controllers = append(m.Controllers, &controlpb.Controller{Name: name, Address: ct.Address, PublicKey: k})
	}
	return m
}

// known returns an intent.ErrInvalid error when rs has a resource that the schema version the
// controller runs as does not know: a Controller resource needs version 2.
func (c *Controller) known(rs []intent.Resource) error {
	if c.schema >= controlpb.SchemaVersion_SCHEMA_VERSION_2 {
		return nil
	}
	for _, r := range rs {
		if r.Kind == intent.KindController {
			return fmt.Errorf("%w: Controller %q: Controller resources need control schema version 2, and this controller runs as version %d until every member of the cluster runs the new release",
				intent.ErrInvalid, r.Name, int32(c.schema))
		}
	}
	return nil
}

// served reports whether the controller serves nodes of schema version v: N and N-1, where N is
// the version the controller runs as.
func (c *Controller) served(v controlpb.SchemaVersion) bool {
	return v == c.schema || (v == c.schema-1 && v != controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED)
}

func (s *stream) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *stream) shut() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

func refusal(reason controlpb.RefuseReason, format string, args ...any) *controlpb.Refuse {
	msg := fmt.Sprintf(format, args...)
	if len(msg) > maxRefuseMessage {
		msg = msg[:maxRefuseMessage]
	}
	return &controlpb.Refuse{Reason: reason, Message: msg}
}

func writeRefuse(conn *control.Conn, r *controlpb.Refuse) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Refuse{Refuse: r}})
}
