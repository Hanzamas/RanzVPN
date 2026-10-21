// Package controller is the controller of #176: the single authority that keeps the intent in
// rqlite, compiles it into the desired state of each node with a generation number, and pushes
// that state over the control stream as deltas against the generation each node acknowledged
// last (#176 "Control protocol").
//
// It also enforces the licence (ADR-0036, SDN-30 #206). The licence in force caps the nodes: an
// apply that adds a Node above the cap is refused, and when the intent holds more Nodes than
// the cap (after the licence changed or expired) only the first ones in name order get a desired
// state, so a node above the cap is refused on its control stream and is no peer of the others.
// Without an Enterprise licence the controller refuses the Enterprise features: the resources
// of EVPN and BGP, and any change of the intent while its store is a cluster of more than one
// member (controller high availability).
package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// SchemaVersion is the control schema version of this controller (N). It serves nodes of
// version N and N-1.
const SchemaVersion = controlpb.SchemaVersion_SCHEMA_VERSION_1

const (
	helloTimeout = 10 * time.Second // from the end of the handshake to the Hello
	writeTimeout = 10 * time.Second // for a Refuse, the last frame of a stream
	storeTimeout = 30 * time.Second // for one store write
	// maxRefuseMessage is the size of Refuse.message on the C node (control.options), without
	// the terminating NUL.
	maxRefuseMessage = 255
	// expiryRetry is the wait before the controller tries again to apply the expiry of the
	// licence when the store failed.
	expiryRetry = 10 * time.Second
)

// capFormat is the message of the Refuse for a node above the node cap of the licence in force:
// the tier, the cap and the node's name.
const capFormat = "the %s licence in force allows %d nodes, and Node %q is above that cap (nodes count in name order)"

// enterpriseKinds are the resource kinds of an Enterprise feature: the BGP and EVPN peers of a
// gateway (ADR-0032, #176 "Resource model"). The intent does not hold them yet (SDN-25, #201):
// with an Enterprise licence the intent refuses them as unknown kinds, and without one the
// licence refuses them first.
var enterpriseKinds = map[string]licence.Feature{
	"BgpPeer":  licence.FeatureEVPN,
	"EvpnPeer": licence.FeatureEVPN,
}

// Config is what a controller runs with.
type Config struct {
	Store  *store.Store
	Key    keys.Static  // the controller's Noise static key
	Log    *slog.Logger // discarded when nil
	Random io.Reader    // draws the ULA of a new VRF; crypto/rand when nil
	// LicenceKeys are the public keys that a licence key must be signed with:
	// licence.VendorKeys() when nil.
	LicenceKeys []ed25519.PublicKey
	// Version is the version of the controller that the fallback licence of an expired
	// subscription must cover: version.Version when empty.
	Version string
}

// NodeGeneration is the generation of a node's desired state.
type NodeGeneration struct {
	Name       string `json:"name"`
	Generation uint64 `json:"generation"`
}

// ApplyResult lists the nodes whose desired state an apply or a delete changed, with their new
// generations.
type ApplyResult struct {
	Nodes []NodeGeneration `json:"nodes"`
}

// NodeStatus is what the controller knows about one node.
type NodeStatus struct {
	Name            string `json:"name"`
	Generation      uint64 `json:"generation"`      // of the desired state
	AckedGeneration uint64 `json:"ackedGeneration"` // the last one the node acknowledged
	Connected       bool   `json:"connected"`
	// Unlicensed is true for a Node above the node cap of the licence in force: it has no
	// desired state, and its control stream is refused.
	Unlicensed bool `json:"unlicensed,omitempty"`
}

// Controller holds the intent and the desired state of every node.
type Controller struct {
	store       *store.Store
	key         keys.Static
	log         *slog.Logger
	random      io.Reader
	licenceKeys []ed25519.PublicKey
	version     string

	mu     sync.Mutex
	intent intent.Intent
	lic    *licence.Licence  // what the installed licence key holds, nil without one
	force  licence.Status    // the licence in force at the last commit
	expiry *time.Timer       // recompiles the intent when the active licence expires
	nodes  map[string]*node  // the nodes the licence in force covers
	byKey  map[string]string // node static key to node name
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
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
	known    bool          // base is the state the node holds, at baseGen
	base     desired.State // nil at baseGen 0
	baseGen  uint64
	inflight uint64        // the generation sent and not yet acknowledged, 0 if none
	sent     desired.State // the state of inflight
	refusal  *controlpb.Refuse
}

// New loads the intent, the node states and the licence key from the store and reconciles them:
// a node whose compiled state differs from its stored one gets a new generation.
func New(ctx context.Context, cfg Config) (*Controller, error) {
	c := &Controller{
		store:       cfg.Store,
		key:         cfg.Key,
		log:         cfg.Log,
		random:      cfg.Random,
		licenceKeys: cfg.LicenceKeys,
		version:     cfg.Version,
		intent:      intent.New(),
		nodes:       map[string]*node{},
		byKey:       map[string]string{},
		conns:       map[net.Conn]struct{}{},
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.random == nil {
		c.random = rand.Reader
	}
	if c.version == "" {
		c.version = version.Version
	}
	if c.licenceKeys == nil {
		var err error
		if c.licenceKeys, err = licence.VendorKeys(); err != nil {
			return nil, err
		}
	}
	rs, stored, err := c.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	var lic *licence.Licence
	key, err := c.store.Licence(ctx)
	if err != nil {
		return nil, err
	}
	if key != "" {
		if l, err := licence.Parse(key, c.licenceKeys); err != nil {
			c.log.Warn("the stored licence key does not verify, so the Personal tier is in force", "err", err)
		} else {
			lic = &l
		}
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
	if _, err := c.commit(ctx, in, lic, store.Changes{}); err != nil {
		return nil, err
	}
	c.log.Info("intent loaded", "resources", len(rs), "nodes", len(c.nodes))
	c.log.Info("licence", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
	return c, nil
}

// PublicKey returns the controller's static public key, which a node needs to open a stream.
func (c *Controller) PublicKey() []byte {
	return c.key.Public()
}

// Apply applies doc to the intent (`ranz apply -f`). What the licence in force does not allow
// is refused with an error that wraps licence.ErrRefused.
func (c *Controller) Apply(ctx context.Context, doc intent.Document) (ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.evaluate(c.lic)
	if err := c.checkCluster(ctx, st); err != nil {
		return ApplyResult{}, err
	}
	if err := checkFeatures(doc, st); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Apply(c.intent, doc, c.random)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkCap(next, st); err != nil {
		return ApplyResult{}, err
	}
	nodes, err := c.commit(ctx, next, c.lic, store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	c.log.Info("intent applied", "resources", len(doc.Resources), "changed", len(nodes))
	return ApplyResult{Nodes: nodes}, nil
}

// Delete deletes the resource kind/name from the intent.
func (c *Controller) Delete(ctx context.Context, kind, name string) (ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkCluster(ctx, c.evaluate(c.lic)); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Delete(c.intent, kind, name)
	if err != nil {
		return ApplyResult{}, err
	}
	nodes, err := c.commit(ctx, next, c.lic, store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	c.log.Info("resource deleted", "kind", kind, "name", name, "changed", len(nodes))
	return ApplyResult{Nodes: nodes}, nil
}

// Licence returns the licence in force.
func (c *Controller) Licence() licence.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.force
}

// SetLicence installs the licence key key, or removes the installed one when key is empty
// (`ranz licence`), and returns the licence in force then. The nodes it no longer covers lose
// their desired state and their control streams; the ones it covers again get theirs. A key
// that does not verify changes nothing and gives an error that wraps licence.ErrInvalid.
func (c *Controller) SetLicence(ctx context.Context, key string) (licence.Status, error) {
	key = strings.TrimSpace(key)
	var lic *licence.Licence
	if key != "" {
		l, err := licence.Parse(key, c.licenceKeys)
		if err != nil {
			return licence.Status{}, err
		}
		lic = &l
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.commit(ctx, c.intent, lic, store.Changes{Licence: &key}); err != nil {
		return licence.Status{}, err
	}
	c.log.Info("licence key changed", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
	return c.force, nil
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
	for _, name := range slices.Sorted(maps.Keys(c.intent.Nodes)) {
		n := c.nodes[name]
		if n == nil {
			out = append(out, NodeStatus{Name: name, Unlicensed: true})
			continue
		}
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
	if c.expiry != nil {
		c.expiry.Stop()
	}
	for raw := range c.conns {
		raw.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// commit makes next the intent and lic the licence (nil for none): it compiles the desired
// state of every node that the licence in force covers, gives each node whose state changed the
// next generation, writes the intent, those states and ch to the store in one transaction, and
// then wakes the streams of the changed nodes and refuses the streams of the nodes that lost
// their state. c.mu is held.
func (c *Controller) commit(ctx context.Context, next intent.Intent, lic *licence.Licence, ch store.Changes) ([]NodeGeneration, error) {
	force := c.evaluate(lic)
	states, err := desired.Compile(next.Capped(force.Nodes))
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

	c.intent, c.lic, c.force = next, lic, force
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
			if _, ok := next.Nodes[name]; ok {
				c.refuse(s, controlpb.RefuseReason_REFUSE_REASON_LICENCE, capFormat, force.Tier, force.Nodes, name)
			} else {
				c.refuse(s, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "the Node resource %q was deleted", name)
			}
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
	c.schedule(force)
	return result, nil
}

// evaluate returns the licence in force now with lic installed (nil for none).
func (c *Controller) evaluate(lic *licence.Licence) licence.Status {
	return licence.Evaluate(lic, time.Now(), c.version)
}

// schedule arms the timer that recompiles the intent when force, the licence in force, is an
// active one and expires. c.mu is held.
func (c *Controller) schedule(force licence.Status) {
	if c.expiry != nil {
		c.expiry.Stop()
		c.expiry = nil
	}
	if force.State == licence.StateActive && !c.closed {
		c.expiry = time.AfterFunc(time.Until(force.Key.Expires), c.expire)
	}
}

// expire recompiles the intent once the active licence expired: under its fallback licence, or
// the Personal tier.
func (c *Controller) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if _, err := c.commit(context.Background(), c.intent, c.lic, store.Changes{}); err != nil {
		c.log.Error("applying the expiry of the licence", "err", err)
		c.expiry = time.AfterFunc(expiryRetry, c.expire)
		return
	}
	c.log.Warn("licence expired", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
}

// checkCluster refuses a change of the intent while the store is a cluster of more than one
// member and the licence in force st lacks controller high availability. c.mu is held.
func (c *Controller) checkCluster(ctx context.Context, st licence.Status) error {
	if st.Allows(licence.FeatureHA) {
		return nil
	}
	members, err := c.store.Members(ctx)
	if err != nil {
		return err
	}
	if members > 1 {
		return fmt.Errorf("%w: the store of this controller is a cluster of %d members, and %s is an Enterprise feature; the licence in force is %s: install an Enterprise licence key or run a single member",
			licence.ErrRefused, members, licence.FeatureHA.Name(), st.Tier)
	}
	return nil
}

// checkFeatures refuses the resources of doc whose kind is a feature that the licence in force
// st lacks.
func checkFeatures(doc intent.Document, st licence.Status) error {
	var problems []error
	for _, r := range doc.Resources {
		if f, ok := enterpriseKinds[r.Kind]; ok && !st.Allows(f) {
			problems = append(problems, fmt.Errorf("%s %q: %s is an Enterprise feature, and the licence in force is %s", r.Kind, r.Name, f.Name(), st.Tier))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n%w", licence.ErrRefused, errors.Join(problems...))
	}
	return nil
}

// checkCap refuses an apply that adds a Node when next would hold more Nodes than the licence in
// force st allows. An apply that adds none passes, so an intent above the cap (after the licence
// changed) can still be changed and shrunk. c.mu is held.
func (c *Controller) checkCap(next intent.Intent, st licence.Status) error {
	if len(next.Nodes) <= st.Nodes {
		return nil
	}
	var added []string
	for _, name := range slices.Sorted(maps.Keys(next.Nodes)) {
		if _, ok := c.intent.Nodes[name]; !ok {
			added = append(added, "Node "+strconv.Quote(name))
		}
	}
	if len(added) == 0 {
		return nil
	}
	hint := ""
	if st.Tier == licence.Personal {
		hint = "; a Business or Enterprise licence key raises the cap"
	}
	return fmt.Errorf("%w: the %s licence in force allows %d nodes, and this apply would make %d (new: %s)%s",
		licence.ErrRefused, st.Tier, st.Nodes, len(next.Nodes), strings.Join(added, ", "), hint)
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
	if v := hello.GetSchemaVersion(); !served(v) {
		c.log.Warn("node refused: schema version", "remote", conn.RemoteAddr().String(), "version", int32(v))
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_SCHEMA_VERSION,
			"schema version %d is not served: this controller serves version %d and the one before it", int32(v), int32(SchemaVersion)))
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	s := &stream{conn: conn, wake: make(chan struct{}, 1), done: make(chan struct{})}
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
	if n == nil {
		// The Node resource exists, but the licence in force does not cover it.
		force := c.force
		c.mu.Unlock()
		c.log.Warn("node refused: above the node cap of the licence", "node", name, "tier", force.Tier, "nodes", force.Nodes)
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_LICENCE, capFormat, force.Tier, force.Nodes, name))
		return
	}
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
		var u *controlpb.Update
		if r == nil {
			u = c.nextUpdate(s)
		}
		c.mu.Unlock()
		if r != nil {
			c.log.Info("node refused", "node", s.name, "reason", r.GetReason().String(), "message", r.GetMessage())
			writeRefuse(s.conn, r)
			s.shut()
			return
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

// served reports whether the controller serves nodes of schema version v: N and N-1.
func served(v controlpb.SchemaVersion) bool {
	return v == SchemaVersion || (v == SchemaVersion-1 && v != controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED)
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
