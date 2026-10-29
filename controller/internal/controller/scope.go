package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/scope"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The roles held for one Network (SDN-38 #231, ADR-0031 amendment of 2026-10-29), at the controller. An admin
// sets the delegation of a Network (SetDelegation): the quotas and the permissions that its scoped roles are
// bound by (internal/scope). A scoped role then changes the intent through the calls of its Network
// (ApplyScoped and DeleteScoped, which check the change against the delegation, under the lock of the apply,
// against the intent that the change makes), reads the resources in its scope (ScopeResources), sets the
// password of a User of the scope (SetScopedPassword) and lists and ends the sessions of its Nodes
// (ScopedSessions, ScopedDisconnect). The sessions quota is kept at the door: the control stream of a Node of a
// Network whose sessions are all open is refused (sessionsFull). The delegations are in the store, outside the
// intent, and the controller keeps them in memory, since only the leader serves the calls that read or change
// them: loadScopes reads them at the start, and every change goes through here.

// ScopedRole is a role that is held for one Network, as it makes a call: the Network, and whether it is the role
// admin (an operator is the other).
type ScopedRole struct {
	Network string
	Admin   bool
}

// scopeState holds the delegations of the Networks in memory, by the name of the Network.
type scopeState struct {
	mu          sync.Mutex
	delegations map[string]scope.Delegation
}

// get returns the delegation of the Network network, and false when it has none.
func (s *scopeState) get(network string) (scope.Delegation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.delegations[network]
	return d, ok
}

// all returns the delegations, ordered by the name of the Network.
func (s *scopeState) all() []scope.Delegation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []scope.Delegation
	for _, network := range slices.Sorted(maps.Keys(s.delegations)) {
		out = append(out, s.delegations[network])
	}
	return out
}

func (s *scopeState) put(d scope.Delegation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delegations == nil {
		s.delegations = map[string]scope.Delegation{}
	}
	s.delegations[d.Network] = d
}

func (s *scopeState) forget(network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.delegations, network)
}

// loadScopes reads the delegations of the Networks from the store. A row that does not read, or that is no
// delegation of its Network, is left out and logged: a Network without a delegation permits its scoped roles
// nothing, so a row that is lost narrows them.
func (c *Controller) loadScopes(ctx context.Context) error {
	rows, err := c.store.Delegations(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		var d scope.Delegation
		if err := json.Unmarshal([]byte(r.Spec), &d); err != nil {
			c.log.Warn("a delegation of a Network cannot be read, so the Network has none", "network", r.Network, "err", err)
			continue
		}
		d.Network = r.Network
		c.scopes.put(d)
	}
	return nil
}

// DelegationInfo is a delegation as the API shows it: with what its Network holds of what the quotas count, and
// the sessions that its Nodes have open.
type DelegationInfo struct {
	scope.Delegation
	Usage    scope.Usage `json:"usage"`
	Sessions uint32      `json:"sessions"`
}

// HoldsNetwork reports whether the intent holds the Network name.
func (c *Controller) HoldsNetwork(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.intent.Networks[name]
	return ok
}

// info returns the delegation d with the usage of its Network. c.mu is held.
func (c *Controller) info(d scope.Delegation) DelegationInfo {
	return DelegationInfo{Delegation: d, Usage: scope.UsageOf(c.intent, d.Network), Sessions: c.openSessions(d.Network)}
}

// openSessions returns the control streams that the Nodes in the scope of the Network network have open. c.mu is
// held.
func (c *Controller) openSessions(network string) uint32 {
	var open uint32
	for name, n := range c.nodes {
		if n.stream == nil {
			continue
		}
		if s, _ := c.intent.ScopeOf(intent.KindNode, name); s == network {
			open++
		}
	}
	return open
}

// Delegations returns the delegation of every Network that has one, ordered by the name of the Network, each
// with its usage (GET /api/v1/tokens/delegations).
func (c *Controller) Delegations(ctx context.Context) []DelegationInfo {
	ds := c.scopes.all()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]DelegationInfo, len(ds))
	for i, d := range ds {
		out[i] = c.info(d)
	}
	return out
}

// SetDelegation sets the delegation of the Network of d, in place of the one it had, and returns it as the
// controller keeps it (PUT /api/v1/tokens/delegations/{network}, `ranz delegation set`). It is the admin's: the
// quotas and the permissions say what a scoped role may do. An error that wraps scope.ErrInvalid is a delegation
// that cannot be set, and one that wraps intent.ErrNotFound a Network that the intent does not hold. A change
// takes effect for the calls and the control streams that come after it.
func (c *Controller) SetDelegation(ctx context.Context, d scope.Delegation) (DelegationInfo, error) {
	d, err := d.Normalize()
	if err != nil {
		return DelegationInfo{}, err
	}
	if !c.HoldsNetwork(d.Network) {
		return DelegationInfo{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, d.Network)
	}
	spec, err := json.Marshal(d)
	if err != nil {
		return DelegationInfo{}, err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.PutDelegation(sctx, store.Delegation{Network: d.Network, Spec: string(spec)}); err != nil {
		return DelegationInfo{}, err
	}
	c.scopes.put(d)
	c.log.Info("delegation set", "network", d.Network, "permissions", d.Permissions, "quotas", d.Quotas)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info(d), nil
}

// DeleteDelegation removes the delegation of the Network network and returns it
// (DELETE /api/v1/tokens/delegations/{network}). The scoped roles of the Network stay, and permit nothing
// until another delegation is set. An error that wraps intent.ErrNotFound is a Network that has none.
func (c *Controller) DeleteDelegation(ctx context.Context, network string) (DelegationInfo, error) {
	d, ok := c.scopes.get(network)
	if !ok {
		return DelegationInfo{}, fmt.Errorf("%w: a delegation of Network %q", intent.ErrNotFound, network)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.DeleteDelegation(sctx, network); err != nil {
		return DelegationInfo{}, err
	}
	c.scopes.forget(network)
	c.log.Info("delegation removed", "network", network)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info(d), nil
}

// dropScopes deletes what was held for each Network that the intent next no longer holds: its delegation, and
// the roles that were held for it, with the tokens (store.DeleteScopedAccess), so that a Network made again
// under the name starts with none, as a User made again starts with no password. commit calls it once the
// change is stored, before it makes next the intent. A failure is logged: the Network is gone, so what was held
// for it calls nothing. c.mu is held.
func (c *Controller) dropScopes(ctx context.Context, next intent.Intent) {
	for _, network := range slices.Sorted(maps.Keys(c.intent.Networks)) {
		if _, ok := next.Networks[network]; ok {
			continue
		}
		if err := c.store.DeleteScopedAccess(ctx, network); err != nil {
			c.log.Warn("deleting what was held for a Network that the intent no longer holds", "network", network, "err", err)
			continue
		}
		c.scopes.forget(network)
	}
}

// ScopeInfo is what a scoped role sees of its Network: the Network, its delegation (which permits nothing when
// the Network has none), and its usage.
type ScopeInfo struct {
	Network    intent.Resource `json:"network"`
	Delegation DelegationInfo  `json:"delegation"`
}

// ScopeInfo returns the Network network as a scoped role of it sees it (GET /api/v1/networks/{network}). An error
// that wraps intent.ErrNotFound is a Network that the intent does not hold.
func (c *Controller) ScopeInfo(network string) (ScopeInfo, error) {
	d, _ := c.scopes.get(network)
	d.Network = network
	if d.Permissions == nil {
		d.Permissions = []string{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.intent.Networks[network]
	if !ok {
		return ScopeInfo{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, network)
	}
	spec, err := json.Marshal(n)
	if err != nil {
		return ScopeInfo{}, err
	}
	return ScopeInfo{Network: intent.Resource{Kind: intent.KindNetwork, Name: network, Spec: spec}, Delegation: c.info(d)}, nil
}

// ScopeResources returns the resources that are in the scope of the Network network, in the order of the intent
// (GET /api/v1/networks/{network}/resources). An error that wraps intent.ErrNotFound is a Network that the intent
// does not hold.
func (c *Controller) ScopeResources(network string) ([]intent.Resource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.intent.Networks[network]; !ok {
		return nil, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, network)
	}
	rs := scope.Resources(c.intent, network)
	if rs == nil {
		rs = []intent.Resource{}
	}
	return rs, nil
}

// scopeCaller returns the check of the changes that the scoped role r makes: its delegation and the Users that
// hold an API role.
func (c *Controller) scopeCaller(ctx context.Context, r ScopedRole) (scope.Caller, error) {
	roles, err := c.store.UserRoles(ctx)
	if err != nil {
		return scope.Caller{}, err
	}
	holders := make(map[string]bool, len(roles))
	for _, role := range roles {
		holders[role.Name] = true
	}
	d, _ := c.scopes.get(r.Network)
	d.Network = r.Network
	return scope.Caller{Network: r.Network, Admin: r.Admin, Delegation: d, Holders: holders}, nil
}

// ApplyScoped applies doc to the intent as the scoped role r (POST /api/v1/networks/{network}/apply): the
// change that it makes is checked against the intent in force and the delegation of the Network, under the lock
// of the apply, and refused with an error that wraps scope.ErrOutOfScope or scope.ErrQuota, and nothing changes,
// when it is outside what the role may do. Everything else is the apply of ApplyConfirm.
func (c *Controller) ApplyScoped(ctx context.Context, r ScopedRole, doc intent.Document) (ApplyResult, error) {
	caller, err := c.scopeCaller(ctx, r)
	if err != nil {
		return ApplyResult{}, err
	}
	check := func(in intent.Intent) error {
		if _, ok := in.Networks[r.Network]; !ok {
			return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, r.Network)
		}
		next, err := intent.Apply(in, doc, c.random)
		if err != nil {
			return err
		}
		return caller.Check(in, next)
	}
	return c.ApplyConfirm(withPrecondition(ctx, check), doc, 0)
}

// DeleteScoped deletes the resource kind/name from the intent as the scoped role r
// (DELETE /api/v1/networks/{network}/resources/{kind}/{name}), checked as ApplyScoped checks an apply.
func (c *Controller) DeleteScoped(ctx context.Context, r ScopedRole, kind, name string) (ApplyResult, error) {
	caller, err := c.scopeCaller(ctx, r)
	if err != nil {
		return ApplyResult{}, err
	}
	check := func(in intent.Intent) error {
		if _, ok := in.Networks[r.Network]; !ok {
			return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, r.Network)
		}
		next, err := intent.Delete(in, kind, name)
		if err != nil {
			return err
		}
		return caller.Check(in, next)
	}
	return c.Delete(withPrecondition(ctx, check), kind, name)
}

// SetScopedPassword sets the password of the User user as the scoped role r
// (PUT /api/v1/networks/{network}/users/{name}/password): the delegation permits users, the User is in the scope
// and holds no API role, whose password would be a way to the role. The password is what SetUserPassword makes
// of it.
func (c *Controller) SetScopedPassword(ctx context.Context, r ScopedRole, user, secret string) error {
	caller, err := c.scopeCaller(ctx, r)
	if err != nil {
		return err
	}
	c.mu.Lock()
	err = caller.CheckUser(c.intent, user)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.SetUserPassword(ctx, user, secret)
}

// ScopedSessions returns the sessions of the Nodes in the scope of the role r, ordered by the name of the Node
// (GET /api/v1/networks/{network}/sessions). The delegation must permit sessions. The call is recorded in the
// audit log, as the list of every session is.
func (c *Controller) ScopedSessions(ctx context.Context, r ScopedRole) ([]Session, error) {
	caller, err := c.scopeCaller(ctx, r)
	if err != nil {
		return nil, err
	}
	if err := caller.Permit(scope.PermSessions); err != nil {
		return nil, err
	}
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	out := []Session{}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		n := c.nodes[name]
		if n.stream == nil {
			continue
		}
		if s, _ := c.intent.ScopeOf(intent.KindNode, name); s == r.Network {
			out = append(out, c.sessionOf(name, n, snaps))
		}
	}
	c.mu.Unlock()
	c.auditOperation(ctx, "session-list", "sessions of Network "+r.Network, nil, fmt.Sprintf("sessions listed: %d", len(out)))
	return out, nil
}

// ScopedDisconnect ends the session id at once, as Disconnect does, when its Node is in the scope of the role r
// (POST /api/v1/networks/{network}/sessions/{id}/disconnect). The delegation must permit sessions. An error that
// wraps scope.ErrOutOfScope is a session of a Node that is in no scope of the role, and one that wraps
// intent.ErrNotFound a session that does not exist, or that ended already.
func (c *Controller) ScopedDisconnect(ctx context.Context, r ScopedRole, id string) (Session, error) {
	caller, err := c.scopeCaller(ctx, r)
	if err != nil {
		return Session{}, err
	}
	if err := caller.Permit(scope.PermSessions); err != nil {
		return Session{}, err
	}
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	var ended []Session
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		if n := c.nodes[name]; n.stream != nil && n.stream.live.id == id {
			if err := caller.CheckNode(c.intent, name); err != nil {
				c.mu.Unlock()
				c.auditOperation(ctx, "session-disconnect", "session "+clip(id, maxSubject), err, "")
				return Session{}, err
			}
			ended = c.endSessions(snaps, func(other string) bool { return other == name }, operatorMessage)
			break
		}
	}
	c.mu.Unlock()
	if len(ended) == 0 {
		err := fmt.Errorf("%w: session %q", intent.ErrNotFound, clip(id, maxSubject))
		c.auditOperation(ctx, "session-disconnect", "session "+clip(id, maxSubject), err, "")
		return Session{}, err
	}
	s := ended[0]
	c.nodeLost(s.Node)
	c.auditOperation(ctx, "session-disconnect", "session "+s.ID, nil, sessionMessage(s))
	return s, nil
}
