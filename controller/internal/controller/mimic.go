package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The mimic servers and their clients (SDN-94 #423, ADR-0023, CORE-P2-6 #406). An operator declares a mimic server once, in
// the mimic section of the Listener of its Node (intent/listener_mimic.go), and the Controller gives the server its settings
// and each client its link (internal/desired, mimic.go). Two things that those states hold are not in the Intent, and the
// Controller keeps them:
//
//   - the short id of a server: 8 random bytes that the Controller makes when a Node first is a mimic server, and keeps for as
//     long as it is one. The Controller keeps it in the state of the server, which the store holds with its Generation, so it is
//     the same after a restart: a compilation takes the one that the state of the Node holds, and makes a new one only for a
//     Node whose state has none (mimicShortID);
//   - the public key of a server, which its Node makes and reports in a Pins message, after its Hello and whenever the key
//     changes. The Controller keeps the last report of each Node by its static key, in the store (table node_pins), while a
//     Node resource holds the key. It never holds a private key: no message of the control protocol has a field for one.
//
// Until the report of a server arrives, no client has a link to it. A report of a key that the Controller has already changes
// nothing, so a Node that reports again after each Hello makes no Generation.
//
// A Node that changes its keys again and again would keep the Controller busy: each change is a write to the store, a compile of
// the whole intent and a commit, with the lock held, and a Generation for each client (CS-6 of docs/threat-model.md; AUD1-DT-20,
// #522). So the Controller applies one change of the keys of a Node in PinsInterval. A report that differs from the keys in force
// and comes sooner is held, a later one replaces it, and one that returns to the keys in force voids it. The look at the keys
// (sweepKeys) applies the report that is held once the interval ended, so the last word of a Node is late and never lost. A
// restart loses no word either: the Node reports its keys again after its Hello.

// PinsInterval is the least time between two changes of the keys of one Node that the Controller applies. A Node makes the key of
// its mimic server once and changes it only when its operator replaces it, which is rare, so 10 s costs a Node nothing that it
// needs. It is far above the cost of a change, which holds the lock for a write to the store and a compile of the whole intent,
// and it bounds a Node that alternates two keys to 6 changes a minute. A report that comes sooner waits for the end of the
// interval, and the next look at the keys after it (Config.KeyCheck) applies it.
const PinsInterval = 10 * time.Second

// mimicState is what the controller keeps for the mimic servers beside the Intent.
type mimicState struct {
	// pins are the keys that the nodes reported about themselves, by node static key (the bytes as a string). Controller.mu
	// guards them, as it does the intent that they are compiled with.
	pins map[string]*controlpb.Pins
	// limits are the intervals that run, by node static key: a Node whose keys changed less than PinsInterval ago has one, and
	// the report that differs from its keys and came within it waits there. A key has none after a restart, after its Node
	// resource goes, and once its interval ended with no report waiting (flushPins). Controller.mu guards them.
	limits map[string]*pinsLimit
}

// pinsLimit is the interval that the last change of the keys of a Node started.
type pinsLimit struct {
	// until is when the interval ends.
	until time.Time
	// held is the last report that came within the interval and differs from the keys in force, nil for none. It is the word of
	// the node on the stream that it came on, and applying it needs no stream.
	held *controlpb.Pins
	// warned says that the log has the line for the held report of this interval: a Node that floods the controller with
	// changes does not flood the log.
	warned bool
}

// runs says whether the interval runs at now. An interval that is longer than PinsInterval, as one is when the clock was set back,
// does not run, so no report waits for more than an interval.
func (l *pinsLimit) runs(now time.Time) bool {
	wait := l.until.Sub(now)
	return wait > 0 && wait <= PinsInterval
}

// loadPins reads the keys that the nodes reported from the store, at start.
func (c *Controller) loadPins(ctx context.Context) error {
	pins, err := c.store.LoadPins(ctx)
	if err != nil {
		return err
	}
	c.mimic.pins = pins
	c.mimic.limits = map[string]*pinsLimit{}
	return nil
}

// takePins takes the keys that the node of s reported about itself. A report that holds what the controller has already changes
// nothing, and voids the one that the node reported since and that waits. A report that differs is applied (applyPins) when the
// last change of the keys of the node is PinsInterval ago or more, and otherwise it is held, in place of the one held before,
// until the interval ends (flushPins). A mimic key that is not the 32 bytes of a public key of X25519, or none, is an error: the
// stream of a node that sends one ends.
func (c *Controller) takePins(s *stream, p *controlpb.Pins) error {
	if p == nil {
		p = &controlpb.Pins{}
	}
	if n := len(p.GetMimicKey()); n != 0 && n != desired.MimicKeySize {
		return fmt.Errorf("a Pins message holds a mimic key of %d bytes: the public key of a mimic server is %d bytes, or none", n, desired.MimicKeySize)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.nodes[s.name]; n == nil || n.stream != s {
		// The node has another stream now, or its state is gone: what this stream says is no longer the word of the node
		return nil
	}
	key := string(s.conn.PeerKey())
	known := c.mimic.pins[key]
	if known == nil {
		known = &controlpb.Pins{}
	}
	limit := c.mimic.limits[key]
	if proto.Equal(known, p) {
		// The node is back at the keys that the controller holds: what it reported since is void
		if limit != nil {
			limit.held = nil
		}
		return nil
	}
	now := c.keyNow()
	if limit != nil && limit.runs(now) {
		if !limit.warned {
			limit.warned = true
			c.log.Warn("node keys held: the node changed its keys again within the interval, so the last report waits for it to end", "node", s.name, "interval", PinsInterval)
		}
		limit.held = p
		return nil
	}
	c.applyPins(s.name, key, p, now)
	return nil
}

// applyPins makes p the keys of the node name, whose static key is key, at the instant now: the store keeps them, in place of the
// ones it reported before, and when the node is a mimic server, the states of its clients are compiled again with the key, so that
// each gets its link, or a new one. It starts the interval of the node, in which no other change of its keys is applied. Each change
// has the store timeout to itself, so the changes that one look at the keys applies (flushPins) do not share one. c.mu is held.
func (c *Controller) applyPins(name, key string, p *controlpb.Pins, now time.Time) {
	c.mimic.limits[key] = &pinsLimit{until: now.Add(PinsInterval)}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.store.SavePins(ctx, []byte(key), p); err != nil {
		c.log.Error("storing the keys that a node reported", "node", name, "err", err)
	}
	c.mimic.pins[key] = p
	c.log.Info("node keys", "node", name, "mimicKey", hex.EncodeToString(p.GetMimicKey()))
	if _, ok := c.intent.MimicOf(name); !ok {
		// No state holds the key of a Node that is no mimic server
		return
	}
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		c.log.Error("compiling the states with the public key of a mimic server", "node", name, "err", err)
		return
	}
	if _, err := c.commit(ctx, c.intent, cp, store.Changes{}); err != nil {
		c.log.Error("storing the states with the public key of a mimic server", "node", name, "err", err)
	}
}

// flushPins applies the reports that waited for the end of their interval, and ends the intervals that have none waiting. The look
// at the keys calls it (sweepKeys). A report of a Node whose Node resource is gone is dropped. c.mu is held.
func (c *Controller) flushPins() {
	now := c.keyNow()
	for _, key := range slices.Sorted(maps.Keys(c.mimic.limits)) {
		limit := c.mimic.limits[key]
		if limit.runs(now) {
			continue
		}
		delete(c.mimic.limits, key)
		if name, ok := c.byKey[key]; ok && limit.held != nil {
			c.applyPins(name, key, limit.held, now)
		}
	}
}

// withMimic puts the mimic part into the NodeConfig of each state of states, which compile made of in: the settings of each
// mimic server with its short id, and the links of its clients once its Node reported its public key (desired.WithMimic).
// c.mu is held.
func (c *Controller) withMimic(in intent.Intent, states map[string]desired.State) error {
	m := desired.Mimic{ShortIDs: map[string][]byte{}, Keys: map[string][]byte{}}
	for _, name := range slices.Sorted(maps.Keys(states)) {
		if _, ok := in.MimicOf(name); !ok {
			continue
		}
		id, err := c.mimicShortID(name)
		if err != nil {
			return err
		}
		m.ShortIDs[name] = id
		// Apply validated the key
		k, _ := intent.ParseKey(in.Nodes[name].PublicKey)
		if p := c.mimic.pins[string(k)]; len(p.GetMimicKey()) == desired.MimicKeySize {
			m.Keys[name] = p.GetMimicKey()
		}
	}
	return desired.WithMimic(in, states, m)
}

// mimicShortID returns the short id of the mimic server on the Node name: the one that the state of the Node holds, or, for
// a Node whose state holds none, 8 bytes from the random source of the controller. c.mu is held.
func (c *Controller) mimicShortID(name string) ([]byte, error) {
	if n := c.nodes[name]; n != nil {
		self := desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: name}
		if id := n.state[self].GetNode().GetMimic().GetServer().GetShortId(); len(id) == desired.MimicShortIDSize {
			return id, nil
		}
	}
	id := make([]byte, desired.MimicShortIDSize)
	if _, err := io.ReadFull(c.random, id); err != nil {
		return nil, fmt.Errorf("controller: making the short id of the mimic server of Node %q: %w", name, err)
	}
	return id, nil
}

// dropPins deletes the keys that the Nodes reported when no Node resource of next holds their static key any more, so that
// a Node made again, or with another key, starts with none, as it starts with no Capabilities, and with no interval and no
// report that waits. commit calls it once the change is stored, before it makes next the intent. A failure is logged: the keys
// stay, and the key of a Node that the intent does not hold is used by no state. c.mu is held.
func (c *Controller) dropPins(ctx context.Context, next intent.Intent) {
	held := map[string]bool{}
	for _, n := range next.Nodes {
		// Apply validated the key
		k, _ := intent.ParseKey(n.PublicKey)
		held[string(k)] = true
	}
	for k := range c.mimic.limits {
		if !held[k] {
			delete(c.mimic.limits, k)
		}
	}
	var gone [][]byte
	for _, k := range slices.Sorted(maps.Keys(c.mimic.pins)) {
		if !held[k] {
			gone = append(gone, []byte(k))
		}
	}
	if len(gone) == 0 {
		return
	}
	if err := c.store.DeletePins(ctx, gone); err != nil {
		c.log.Warn("deleting the keys that removed nodes reported", "err", err)
		return
	}
	for _, k := range gone {
		delete(c.mimic.pins, string(k))
	}
}

// ExplainListener explains the Listener name for `ranz explain -listener` (GET /api/v1/explain/listeners/{name}): its mimic
// section, whether its Node reported the public key of its mimic server, and the Nodes that have a link to the server. An
// error that wraps intent.ErrNotFound is a Listener that the intent does not hold.
func (c *Controller) ExplainListener(name string) (explain.ListenerResult, error) {
	c.mu.Lock()
	in := c.intent.Clone()
	states := make(map[string]desired.State, len(c.nodes))
	for node, n := range c.nodes {
		states[node] = maps.Clone(n.state)
	}
	var key []byte
	if l, ok := in.Listeners[name]; ok {
		// Apply validated the key
		k, _ := intent.ParseKey(in.Nodes[l.Node].PublicKey)
		key = slices.Clone(c.mimic.pins[string(k)].GetMimicKey())
	}
	c.mu.Unlock()
	if _, ok := in.Listeners[name]; !ok {
		return explain.ListenerResult{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindListener, clip(name, maxSubject))
	}
	return explain.Listener(in, states, name, key)
}
