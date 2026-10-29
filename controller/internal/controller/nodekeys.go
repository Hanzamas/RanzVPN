package controller

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The lives of the node keys (SDN-56 #249, ADR-0031 amendment of 2026-10-28). The static key of a Node is
// authenticated for a period: it lives for the key lifetime of the Networks of the Node (90 days unless a Network
// says otherwise, intent.Network.KeyLifetimeDays) from the moment that the Node was admitted or that its User logged in
// again, which is the re-authentication that refreshes it (EnrolDevice). A Node that an admin marks nonExpiring
// (intent.Node.NonExpiring), as a server or a gateway is, has a key that does not end. A Network admits its new Nodes at
// once or holds each of them until an operator approves it (intent.Network.Approval).
//
// The intent holds the policy and the controller keeps the outcome, one row for each key in the store (table
// node_keys), so that a revision, a rollback or an import does not give an expired key another life and does not
// approve a Node. The row of a key stays when no Node holds the key any more, with when the key ends and without its
// approval, which was the approval of the Node: a Node that is deleted and made again with the key, by an apply, a
// rollback, an import or the automatic rollback of an unconfirmed apply, or that gets its key back, has the life that
// the key had, and waits again in a Network that holds new Nodes for approval. A Node whose key ended, or that its
// Network holds for approval, is held back, as the Nodes of a banned
// user are (bans.go): the desired state of every other Node is compiled as if it were not in the intent, so that no Node
// has it as a Peer, a Relay or a route, and its control stream is refused, with the reason REFUSE_REASON_UNKNOWN_NODE, the
// one reason of the control protocol for a node that is not admitted, and a message that says which of the two it is. A
// Node that the controller holds back keeps its own desired state and its generations, so the first generation that it
// gets once it is admitted again follows the one that it applied.
//
// A key that ended is refreshed when its User logs in again with the device (EnrolDevice), which a User that is no longer
// valid cannot do: a User that was removed where it comes from, today a User whose account expired, is refused the login,
// so the devices of that User lose access when their keys end. An operator refreshes the key of a Node that has no User
// (RefreshNodeKey) and approves a Node that waits (ApproveNode). The controller looks at the lives of the keys every
// Config.KeyCheck, and again at every change that it commits. At each look it also says what comes before it does, with an
// Event for a Node that waits, for a key that is to end and for a key that ended (keyevents.go; SDN-56-R1).

// DefaultKeyCheck is how often the controller looks for keys that ended, when Config.KeyCheck is 0.
const DefaultKeyCheck = 10 * time.Second

// The states of the key of a Node, as NodeKeyInfo says them.
const (
	// KeyValid: the Node is admitted and its key has not ended.
	KeyValid = "valid"
	// KeyExpired: the key of the Node ended. The Node is held back until its User logs in again, or an operator refreshes
	// the key of a Node that has no User.
	KeyExpired = "expired"
	// KeyPending: a Network of the Node holds it until an operator approves it.
	KeyPending = "pending"
)

// keyHold says why the controller holds a Node back.
type keyHold struct {
	reason  string    // KeyExpired or KeyPending
	network string    // the Network that holds the Node for approval, for KeyPending
	expires time.Time // when the key ended, for KeyExpired
}

// keyLifeState is what the controller keeps for the lives of the keys. Controller.mu guards what it holds.
type keyLifeState struct {
	// now is the clock, Config.Now, and every how often the controller looks for keys that ended. startKeys sets
	// them, and nothing changes them.
	now   func() time.Time
	every time.Duration
	// life is the life of each key that a Node resource holds or held, by the static key (its bytes as a string): the
	// life of a key that no Node holds any more is kept (syncKeys). startKeys loads it from the store.
	life map[string]store.NodeKey
	// applied are the Nodes that the desired states in force were compiled without, for the life of their keys, by name:
	// the holds of the compile that made those states (compiled.holds), which commitKeys notes.
	applied map[string]keyHold

	cancel context.CancelFunc
	done   chan struct{}
}

// NodeKeyInfo is the key of one Node as an operator sees it.
type NodeKeyInfo struct {
	// Node is the name of the Node resource, and Owner the User whose device it is, left out for a Node that has none.
	Node  string `json:"node"`
	Owner string `json:"owner,omitempty"`
	// State is KeyValid, KeyExpired or KeyPending.
	State string `json:"state"`
	// NonExpiring says that the Node is marked nonExpiring, so its key has no end.
	NonExpiring bool `json:"nonExpiring,omitempty"`
	// Refreshed is when the key last authenticated: the Node was admitted, its User logged in again, or an operator
	// refreshed it. Expires is when it ends, left out for a Node that is marked nonExpiring.
	Refreshed time.Time `json:"refreshed,omitzero"`
	Expires   time.Time `json:"expires,omitzero"`
	// DaysLeft is how many days a valid key has left, counted up (a key with 3 days and 2 hours left has 4), so that an operator
	// reads how soon it ends. It is left out for a key that has no end, for a key that ended and for the key of a Node that
	// waits, whose life begins when it is approved.
	DaysLeft int `json:"daysLeft,omitempty"`
	// Approved says that the Node was admitted: no Network held it for approval, or an operator approved it.
	Approved   bool      `json:"approved"`
	ApprovedBy string    `json:"approvedBy,omitempty"`
	ApprovedAt time.Time `json:"approvedAt,omitzero"`
	// Network is the Network that holds the Node for approval, for the state KeyPending.
	Network string `json:"network,omitempty"`
}

// startKeys sets the clock and the look at the lives of the keys from cfg, and loads the lives from the store. New calls
// it before it compiles the first desired states, which leave out the Nodes that the lives hold back.
func (c *Controller) startKeys(ctx context.Context, cfg Config) error {
	c.keyLife.now = cfg.Now
	if c.keyLife.now == nil {
		c.keyLife.now = time.Now
	}
	c.keyLife.every = cfg.KeyCheck
	if c.keyLife.every <= 0 {
		c.keyLife.every = DefaultKeyCheck
	}
	stored, err := c.store.NodeKeys(ctx)
	if err != nil {
		return err
	}
	c.keyLife.life = make(map[string]store.NodeKey, len(stored))
	for _, k := range stored {
		c.keyLife.life[string(k.Key)] = k
	}
	c.keyLife.applied = map[string]keyHold{}
	return nil
}

// startKeySweep starts the look at the lives of the keys that ends the Nodes whose keys ended while they were connected.
// New calls it last, so that nothing runs for a controller that did not start.
func (c *Controller) startKeySweep() {
	ctx, cancel := context.WithCancel(context.Background())
	c.keyLife.cancel, c.keyLife.done = cancel, make(chan struct{})
	go func() {
		defer close(c.keyLife.done)
		tick := time.NewTicker(c.keyLife.every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.sweepKeys()
			}
		}
	}()
}

// stopKeys stops the look at the lives of the keys. Close calls it once the control streams ended.
func (c *Controller) stopKeys() {
	if c.keyLife.cancel != nil {
		c.keyLife.cancel()
		<-c.keyLife.done
	}
}

// sweepKeys is one look at the lives of the keys: a Node whose key ended since the last look is left out of the desired
// states of the others and its stream is refused, and a life that the store did not take at its change is written again.
func (c *Controller) sweepKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.reconcileKeys(ctx); err != nil {
		c.log.Error("applying the lives of the node keys", "err", err)
	}
}

// reconcileKeys brings the lives of the keys and the desired states in line with the clock: it writes the lives that the
// store lacks (syncKeys), and when the Nodes that the lives hold back are not the ones that the states in force were
// compiled without, it compiles and commits the states again. c.mu is held.
func (c *Controller) reconcileKeys(ctx context.Context) error {
	c.syncKeys(ctx)
	if sameHolds(c.keyHolds(c.intent, c.keyNow()), c.keyLife.applied) {
		return nil
	}
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		return err
	}
	_, err = c.commit(ctx, c.intent, cp, store.Changes{})
	return err
}

// keyNow returns the time of the lives of the keys: the clock of the controller in UTC, to the millisecond, as the store
// keeps a time.
func (c *Controller) keyNow() time.Time {
	return c.keyLife.now().UTC().Truncate(time.Millisecond)
}

// holdOf says whether the life of the key of the Node name, which n is in in, holds the Node back at the instant now:
// the Node waits when a Network of its VRFs holds new Nodes for approval and nobody approved it, which is also what a
// Node whose key has no life yet (recorded false) does; and its key has ended when it expires at or before now, unless
// the Node is marked nonExpiring. A Node that waits is reported as waiting even when its key also ended.
func holdOf(in intent.Intent, name string, n intent.Node, rec store.NodeKey, recorded bool, now time.Time) (keyHold, bool) {
	if !recorded || !rec.Approved {
		if network, waits := in.ApprovalNeeded(name); waits {
			return keyHold{reason: KeyPending, network: network}, true
		}
	}
	if recorded && !n.NonExpiring && !rec.Expires.IsZero() && !now.Before(rec.Expires) {
		return keyHold{reason: KeyExpired, expires: rec.Expires}, true
	}
	return keyHold{}, false
}

// keyHolds returns the Nodes of in that the lives of the keys hold back at the instant now, by name. compile reads them
// once, for the states that it makes and for commitKeys, which notes them as the holds in force, so that a key that ends
// while a change is committed is not taken as left out of states that still have its Node; reconcileKeys compares the
// holds of now with those. c.mu is held.
func (c *Controller) keyHolds(in intent.Intent, now time.Time) map[string]keyHold {
	out := map[string]keyHold{}
	for name, n := range in.Nodes {
		// Apply validated the key
		k, _ := intent.ParseKey(n.PublicKey)
		rec, recorded := c.keyLife.life[string(k)]
		if h, held := holdOf(in, name, n, rec, recorded, now); held {
			out[name] = h
		}
	}
	return out
}

// keyHeld says whether the life of its key holds the Node name of the intent in force back now, and why. c.mu is held.
func (c *Controller) keyHeld(name string) (keyHold, bool) {
	n, ok := c.intent.Nodes[name]
	if !ok {
		return keyHold{}, false
	}
	// Apply validated the key
	k, _ := intent.ParseKey(n.PublicKey)
	rec, recorded := c.keyLife.life[string(k)]
	return holdOf(c.intent, name, n, rec, recorded, c.keyNow())
}

// withheld returns the names of the Nodes that the desired states of the others are compiled without: the Nodes of the
// banned users, which compileStates names in banned, and the ones that the lives of the keys hold back, holds, which
// compile read, each once and in name order. compileStates calls it.
func withheld(banned []string, holds map[string]keyHold) []string {
	if len(holds) == 0 {
		return banned
	}
	out := append(slices.Clone(banned), slices.Collect(maps.Keys(holds))...)
	slices.Sort(out)
	return slices.Compact(out)
}

// sameHolds reports whether a and b hold back the same Nodes for the same reasons.
func sameHolds(a, b map[string]keyHold) bool {
	if len(a) != len(b) {
		return false
	}
	for name, h := range a {
		if o, ok := b[name]; !ok || o.reason != h.reason || o.network != h.network {
			return false
		}
	}
	return true
}

// holdMessage is the message of the Refuse for a Node that the life of its key holds back, and of the refusals that the
// audit log records: which of the two it is, and what ends it. c.mu is held.
func (c *Controller) holdMessage(name string, h keyHold) string {
	switch {
	case h.reason == KeyPending:
		return fmt.Sprintf("Node %q waits for an administrator to approve it in Network %q", name, h.network)
	case c.intent.Nodes[name].Owner != "":
		return fmt.Sprintf("the key of Node %q expired at %s: its user logs in again to refresh it", name, h.expires.Format(time.RFC3339))
	}
	return fmt.Sprintf("the key of Node %q expired at %s: an operator refreshes it, or marks the Node nonExpiring", name, h.expires.Format(time.RFC3339))
}

// refuseKey ends the control stream conn of the node name, which the life of its key holds back: it records the refusal as
// a failed authentication, and sends the Refuse with the message that holdMessage made.
func (c *Controller) refuseKey(conn *control.Conn, name, message string, remote net.Addr) {
	c.log.Warn("node refused: the life of its key", "node", name, "remote", remote.String(), "message", message)
	c.auditNode(audit.AuthFailed, audit.ActorNode(name), audit.Failure, message, remote)
	writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "%s", message))
}

// sameKeyLife reports whether a and b are the life of the same Node in the same state, with the same announcements.
func sameKeyLife(a, b store.NodeKey) bool {
	return a.Node == b.Node && a.Approved == b.Approved && a.ApprovedBy == b.ApprovedBy && a.Announced == b.Announced &&
		a.Refreshed.Equal(b.Refreshed) && a.Expires.Equal(b.Expires) && a.ApprovedAt.Equal(b.ApprovedAt)
}

// syncKeys brings the stored lives in line with the intent in force. A Node whose key has no life yet gets one: its key
// lives for the key lifetime of its Networks from now, and the Node is admitted unless a Network holds it for approval. A
// Node that no Network holds for approval any more is admitted. A Node marked nonExpiring has a key that does not end, and
// one that is not marked has one that does, from now when it had none. The life of a key that no Node resource holds any
// more is kept as its tombstone: a Node that holds the key again finds when the key ends, so a key that ended stays ended
// until a re-authentication, and finds no approval, so a Network that holds new Nodes for approval holds it. The look also
// announces what the lives call for (announce, keyevents.go): the Events and the marks that they were raised go to the store
// with the lives, in one transaction. A write that fails is logged and made again at the next look; nothing changes in memory
// until the store has it, so a Node whose life is not stored stays as the intent says (a Node that its Network holds waits),
// and no Event is raised for a mark that was not stored. c.mu is held.
func (c *Controller) syncKeys(ctx context.Context) {
	now := c.keyNow()
	in := c.intent
	var put []store.NodeKey
	var events []event.Event
	current := make(map[string]bool, len(in.Nodes))
	for _, name := range slices.Sorted(maps.Keys(in.Nodes)) {
		n := in.Nodes[name]
		// Apply validated the key
		k, _ := intent.ParseKey(n.PublicKey)
		current[string(k)] = true
		rec, recorded := c.keyLife.life[string(k)]
		next := rec
		if !recorded {
			next = store.NodeKey{Key: k, Refreshed: now}
		}
		next.Node = name
		holder, waits := in.ApprovalNeeded(name)
		if !next.Approved && !waits {
			next.Approved, next.ApprovedBy, next.ApprovedAt = true, audit.ActorSystem, now
		}
		switch {
		case n.NonExpiring:
			next.Expires = time.Time{}
		case next.Expires.IsZero():
			next.Expires = now.Add(in.KeyLifetime(name))
		}
		if len(events) < maxAnnouncements {
			var announcements []event.Event
			next, announcements = announce(name, n, next, holder, now)
			events = append(events, announcements...)
		}
		if !recorded || !sameKeyLife(rec, next) {
			put = append(put, next)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(c.keyLife.life)) {
		if rec := c.keyLife.life[k]; !current[k] && !sameKeyLife(rec, tombstone(rec)) {
			put = append(put, tombstone(rec))
		}
	}
	if len(put) == 0 {
		return
	}
	if err := c.store.PutNodeKeys(ctx, put, events...); err != nil {
		c.log.Warn("storing the lives of the node keys, which the next look tries again", "err", err)
		return
	}
	for _, k := range put {
		c.keyLife.life[string(k.Key)] = k
	}
	c.announced(ctx, events)
}

// tombstone returns the life rec of a key that no Node resource holds any more as the store keeps it: with when the key
// last authenticated, when it ends and what was announced of its end, and without the approval, which was the approval of the
// Node that held it, and without the announcement that the Node waited for it, which a Node that holds the key again and waits
// again is announced for.
func tombstone(rec store.NodeKey) store.NodeKey {
	rec.Approved, rec.ApprovedBy, rec.ApprovedAt = false, "", time.Time{}
	rec.Announced &^= store.AnnouncedWaiting
	return rec
}

// commitKeys is what commit does for the lives of the keys once a change is stored: it brings the stored lives in line
// with the intent that is now in force, notes holds, the Nodes that compile held back and the new desired states were
// compiled without, and refuses the control streams of those among them that are open. It does not read the clock again:
// a key that ended since the compile is in states that still have its Node, so it is no hold in force yet, and the next
// look at the keys compiles the states again without it. c.mu is held, and c.intent is the intent that was just committed.
func (c *Controller) commitKeys(ctx context.Context, holds map[string]keyHold) {
	c.syncKeys(ctx)
	c.keyLife.applied = holds
	for _, name := range slices.Sorted(maps.Keys(holds)) {
		if n := c.nodes[name]; n != nil && n.stream != nil {
			c.refuse(n.stream, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "%s", c.holdMessage(name, holds[name]))
		}
	}
}

// putKeyLife stores the life k of a key and keeps it. c.mu is held.
func (c *Controller) putKeyLife(ctx context.Context, k store.NodeKey) error {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.PutNodeKeys(sctx, []store.NodeKey{k}); err != nil {
		return err
	}
	c.keyLife.life[string(k.Key)] = k
	return nil
}

// renewKey gives the key of the Node name a new life: it lives for the key lifetime of the Networks of the Node from now,
// or has no end when the Node is marked nonExpiring. A Node that was held back for the end of its key is admitted again,
// and the other Nodes get it as a Peer again. The end of the new period is announced again, so the marks of the end of the
// last one go. c.mu is held, and the intent holds the Node.
func (c *Controller) renewKey(ctx context.Context, name string) error {
	n := c.intent.Nodes[name]
	// Apply validated the key
	k, _ := intent.ParseKey(n.PublicKey)
	now := c.keyNow()
	rec, recorded := c.keyLife.life[string(k)]
	if !recorded {
		rec = store.NodeKey{Key: k, Node: name}
	}
	rec.Refreshed = now
	rec.Expires = time.Time{}
	if !n.NonExpiring {
		rec.Expires = now.Add(c.intent.KeyLifetime(name))
	}
	rec.Announced &^= store.AnnouncedLife
	if err := c.putKeyLife(ctx, rec); err != nil {
		return err
	}
	return c.reconcileKeys(ctx)
}

// refreshKey is the re-authentication of the device of the User user whose static key is key: the login of the User
// checked its password already, and EnrolDevice calls this when key is the key of the Node name, which the User owns. The
// key of the Node lives for another period from now. EnrolDevice found the Node under an earlier lock, so refreshKey checks
// again that the Node holds key as a device of the User: an error that wraps intent.ErrNotFound is a Node or a User that a
// change of the intent removed since, and one that wraps ErrConflict a Node that it gave another key or another owner. A
// User that is no longer valid at the instant of the clock of the lives of the keys cannot refresh the key, whatever its
// caller checked: an error that wraps ErrUserExpired is a User past its expiry, and one that wraps ErrUserBanned a User
// that an operator banned.
func (c *Controller) refreshKey(ctx context.Context, name, user string, key []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.intent.Nodes[name]
	if !ok {
		// A change of the intent removed the Node since EnrolDevice found it
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNode, name)
	}
	// Apply validated the key
	if k, _ := intent.ParseKey(n.PublicKey); !bytes.Equal(k, key) || n.Owner != user {
		// A change of the intent gave the Node another key or another owner since EnrolDevice found it
		return fmt.Errorf("%w: Node %q no longer holds the static key of the device as a device of User %q", ErrConflict, name, user)
	}
	u, ok := c.intent.Users[user]
	if !ok {
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, user)
	}
	if u.ExpiredAt(c.keyNow()) {
		return fmt.Errorf("%w: User %q expired at %s", ErrUserExpired, user, u.Expires.Format(time.RFC3339))
	}
	if _, banned := c.live.bans[user]; banned {
		return fmt.Errorf("%w: User %q", ErrUserBanned, user)
	}
	return c.renewKey(ctx, name)
}

// keyInfo returns the key of the Node name of the intent in force as an operator sees it at the instant now. c.mu is held.
func (c *Controller) keyInfo(name string, now time.Time) NodeKeyInfo {
	n := c.intent.Nodes[name]
	// Apply validated the key
	k, _ := intent.ParseKey(n.PublicKey)
	rec, recorded := c.keyLife.life[string(k)]
	info := NodeKeyInfo{Node: name, Owner: n.Owner, State: KeyValid, NonExpiring: n.NonExpiring}
	if recorded {
		info.Refreshed, info.Expires = rec.Refreshed, rec.Expires
		info.Approved, info.ApprovedBy, info.ApprovedAt = rec.Approved, rec.ApprovedBy, rec.ApprovedAt
	}
	if h, held := holdOf(c.intent, name, n, rec, recorded, now); held {
		info.State, info.Network = h.reason, h.network
	}
	if info.State == KeyValid && !n.NonExpiring && !info.Expires.IsZero() {
		info.DaysLeft = daysIn(info.Expires.Sub(now))
	}
	return info
}

// keyMessage describes the key in info for the audit log: its state, and when it ends.
func keyMessage(info NodeKeyInfo) string {
	switch {
	case info.Node == "":
		return ""
	case info.Expires.IsZero():
		return fmt.Sprintf("the key of node %s is %s and does not end", info.Node, info.State)
	}
	return fmt.Sprintf("the key of node %s is %s and ends at %s", info.Node, info.State, info.Expires.Format(time.RFC3339))
}

// NodeKeys returns the key of every Node, ordered by the name of the Node (GET /api/v1/operations/node-keys). The call is
// recorded in the audit log.
func (c *Controller) NodeKeys(ctx context.Context) []NodeKeyInfo {
	c.mu.Lock()
	now := c.keyNow()
	out := make([]NodeKeyInfo, 0, len(c.intent.Nodes))
	for _, name := range slices.Sorted(maps.Keys(c.intent.Nodes)) {
		out = append(out, c.keyInfo(name, now))
	}
	c.mu.Unlock()
	c.auditOperation(ctx, "node-key-list", "node keys", nil, fmt.Sprintf("node keys listed: %d", len(out)))
	return out
}

// ApproveNode approves the Node name (POST /api/v1/operations/node-keys/{name}/approve): the Network that held it for
// approval admits it, its key lives from now for the key lifetime of its Networks, and the other Nodes of its VRFs get it
// as a Peer. It opens its control stream again by itself, at the next try. A Node that is admitted already is left as it
// is, with its first approval. An error that wraps intent.ErrNotFound is a Node that the intent does not hold. The call is
// recorded in the audit log.
func (c *Controller) ApproveNode(ctx context.Context, name string) (NodeKeyInfo, error) {
	info, err := c.approveNode(ctx, name)
	c.auditOperation(ctx, "node-approve", "node "+clip(name, maxSubject), err, keyMessage(info))
	return info, err
}

func (c *Controller) approveNode(ctx context.Context, name string) (NodeKeyInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.intent.Nodes[name]
	if !ok {
		return NodeKeyInfo{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNode, clip(name, maxSubject))
	}
	now := c.keyNow()
	// Apply validated the key
	k, _ := intent.ParseKey(n.PublicKey)
	rec, recorded := c.keyLife.life[string(k)]
	if recorded && rec.Approved {
		return c.keyInfo(name, now), nil
	}
	origin, _ := audit.FromContext(ctx)
	if !recorded {
		rec = store.NodeKey{Key: k, Node: name}
	}
	rec.Approved, rec.ApprovedBy, rec.ApprovedAt = true, cmp.Or(origin.Actor, audit.ActorSystem), now
	// The key lives from the approval, so that a Node that waited long is not admitted with a key at its end
	rec.Refreshed = now
	rec.Expires = time.Time{}
	if !n.NonExpiring {
		rec.Expires = now.Add(c.intent.KeyLifetime(name))
	}
	// The Node does not wait any more, and the end of its first period is yet to be announced
	rec.Announced = 0
	if err := c.putKeyLife(ctx, rec); err != nil {
		return NodeKeyInfo{}, err
	}
	if err := c.reconcileKeys(ctx); err != nil {
		return NodeKeyInfo{}, err
	}
	c.log.Info("node approved", "node", name, "by", rec.ApprovedBy)
	return c.keyInfo(name, now), nil
}

// RefreshNodeKey gives the key of the Node name another period (POST /api/v1/operations/node-keys/{name}/refresh): the
// re-authentication of a Node that has no User to log in again, such as a server that nobody marked nonExpiring. The key
// of a device of a User is refreshed by that User's login, and an error that wraps ErrConflict is a Node that has an owner.
// An error that wraps intent.ErrNotFound is a Node that the intent does not hold. The call is recorded in the audit log.
func (c *Controller) RefreshNodeKey(ctx context.Context, name string) (NodeKeyInfo, error) {
	info, err := c.refreshOperation(ctx, name)
	c.auditOperation(ctx, "node-key-refresh", "node "+clip(name, maxSubject), err, keyMessage(info))
	return info, err
}

func (c *Controller) refreshOperation(ctx context.Context, name string) (NodeKeyInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.intent.Nodes[name]
	if !ok {
		return NodeKeyInfo{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNode, clip(name, maxSubject))
	}
	if n.Owner != "" {
		return NodeKeyInfo{}, fmt.Errorf("%w: the key of Node %q is the key of a device of User %q, who refreshes it by logging in again", ErrConflict, name, n.Owner)
	}
	if err := c.renewKey(ctx, name); err != nil {
		return NodeKeyInfo{}, err
	}
	return c.keyInfo(name, c.keyNow()), nil
}
