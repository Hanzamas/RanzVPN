// Package scope is what binds a role of the controller's API that is held for one Network (SDN-38, #231,
// ADR-0031 amendment of 2026-10-29): which resources of the intent are in the scope of a Network, what a
// scoped role may change in them, and how much of each the Network may hold.
//
// A Delegation is what an admin sets for a Network: its quotas (the most users, groups, nodes, rules and
// sessions it may hold, and the greatest rate that a Node of it may be given) and its permissions (which
// kinds of resource and which operations its scoped roles may change). It is the successor of the admin
// options of a hub of the slim fork. It is not part of the intent: a role that the intent could change
// would change its own limits, and a revision, a rollback or an import must not give a scoped role more.
//
// The check is made on the change, not on the call: Caller.Check takes the intent in force and the intent
// that a change makes of it, and refuses the change when anything that it adds, changes or removes is
// outside the scope or beyond what the delegation permits, or when it takes the Network over a quota.
// Whatever the change does to the intent beyond what the call named, such as the resources that the
// controller completes, is checked the same way, so a change cannot reach what the call did not name.
// Everything that is not allowed here is refused: a kind that the scope does not know and a field of a
// Node that is not listed in checkNode are the global roles', also for a kind or a field that a later
// ticket adds.
package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The permissions of a Delegation, each a kind of resource or an operation that the scoped roles of a
// Network may be allowed to change.
const (
	// PermNetwork is the Network itself: its source prefixes, security, DHCP, approval mode and key
	// lifetime. Only the role admin changes them; the VRF, the mode and the pools stay the global roles'.
	PermNetwork = "network"
	// PermNodes are the Nodes of the scope.
	PermNodes = "nodes"
	// PermUsers are the Users of the scope, and their passwords.
	PermUsers = "users"
	// PermGroups are the Groups of the scope.
	PermGroups = "groups"
	// PermRules are the Policies of the scope.
	PermRules = "rules"
	// PermSessions are the sessions of the Nodes of the scope: to list them and to end them.
	PermSessions = "sessions"
)

// Permissions are the permissions there are, in the order in which a list of them is written.
var Permissions = []string{PermNetwork, PermNodes, PermUsers, PermGroups, PermRules, PermSessions}

const (
	// MaxQuota is the greatest quota of a count: users, groups, nodes, rules and sessions.
	MaxQuota = 1 << 20
	// MaxBandwidth is the greatest bandwidth quota, in bits per second.
	MaxBandwidth = 1 << 40
)

var (
	// ErrOutOfScope marks a change that a scoped role may not make: it names, changes or removes
	// what is outside the scope of the role, or a kind or an operation that the delegation of the
	// Network does not permit.
	ErrOutOfScope = errors.New("outside the scope")
	// ErrQuota marks a change that would take the Network over a quota of its delegation.
	ErrQuota = errors.New("over a quota")
	// ErrInvalid marks a delegation that cannot be set.
	ErrInvalid = errors.New("invalid delegation")
)

// nameRule is the rule of resource names (internal/intent), which a Network has.
var nameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Quotas are the most that a Network holds of what it counts. A quota that is left out, or 0, is no limit.
// A change that adds to a count over its quota is refused; one that does not add to it passes, so a Network
// that is over a quota after the quota was lowered can still shrink.
type Quotas struct {
	// Users, Groups, Nodes and Rules are the most Users, Groups, Nodes and Policies in the scope.
	Users  uint32 `json:"users,omitempty"`
	Groups uint32 `json:"groups,omitempty"`
	Nodes  uint32 `json:"nodes,omitempty"`
	Rules  uint32 `json:"rules,omitempty"`
	// Sessions is the most control streams that the Nodes of the scope have open at once: the controller
	// refuses the stream of one more, since a session is the control stream of a Node (SDN-50).
	Sessions uint32 `json:"sessions,omitempty"`
	// Bandwidth is the greatest rate limit, in bits per second, that a scoped role gives a Node of the
	// scope. A Node that a scoped role makes or changes has a rate limit, and not above this.
	Bandwidth uint64 `json:"bandwidth,omitempty"`
}

// Delegation is what the scoped roles of one Network are bound by.
type Delegation struct {
	// Network is the name of the Network.
	Network string `json:"network"`
	// Quotas are the limits on what the Network holds.
	Quotas Quotas `json:"quotas"`
	// Permissions are what the scoped roles may change, from Permissions. Left out, none: the scoped
	// roles read.
	Permissions []string `json:"permissions"`
}

// Allows reports whether the delegation permits perm.
func (d Delegation) Allows(perm string) bool {
	return slices.Contains(d.Permissions, perm)
}

// Normalize returns d with its permissions in the order of Permissions, or an error that wraps ErrInvalid
// when the name is no Network name, a permission is none of Permissions or is listed twice, or a quota is
// above MaxQuota or MaxBandwidth.
func (d Delegation) Normalize() (Delegation, error) {
	if !nameRule.MatchString(d.Network) {
		return Delegation{}, fmt.Errorf("%w: the Network name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, d.Network)
	}
	seen := map[string]bool{}
	for _, p := range d.Permissions {
		switch {
		case !slices.Contains(Permissions, p):
			return Delegation{}, fmt.Errorf("%w: the permission %q is none of %s", ErrInvalid, p, strings.Join(Permissions, ", "))
		case seen[p]:
			return Delegation{}, fmt.Errorf("%w: the permission %q is listed twice", ErrInvalid, p)
		}
		seen[p] = true
	}
	q := d.Quotas
	for _, c := range []struct {
		name  string
		value uint64
		max   uint64
	}{{"users", uint64(q.Users), MaxQuota}, {"groups", uint64(q.Groups), MaxQuota}, {"nodes", uint64(q.Nodes), MaxQuota}, {"rules", uint64(q.Rules), MaxQuota},
		{"sessions", uint64(q.Sessions), MaxQuota}, {"bandwidth", q.Bandwidth, MaxBandwidth}} {
		if c.value > c.max {
			return Delegation{}, fmt.Errorf("%w: the %s quota %d is above the most that there is, %d", ErrInvalid, c.name, c.value, c.max)
		}
	}
	out := d
	out.Permissions = []string{}
	for _, p := range Permissions {
		if seen[p] {
			out.Permissions = append(out.Permissions, p)
		}
	}
	return out, nil
}

// Usage is what a Network holds of what its quotas count. The sessions are the controller's to count: they
// are control streams, and the intent holds none.
type Usage struct {
	Users  uint32 `json:"users"`
	Groups uint32 `json:"groups"`
	Nodes  uint32 `json:"nodes"`
	Rules  uint32 `json:"rules"`
}

// UsageOf returns what the Network network holds in in: the Users, the Groups, the Nodes and the Policies
// that are in its scope.
func UsageOf(in intent.Intent, network string) Usage {
	var u Usage
	for name := range in.Users {
		if in.Users[name].Scope == network {
			u.Users++
		}
	}
	for name := range in.Groups {
		if in.Groups[name].Scope == network {
			u.Groups++
		}
	}
	for name := range in.Nodes {
		if scope, _ := in.ScopeOf(intent.KindNode, name); scope == network {
			u.Nodes++
		}
	}
	for name := range in.Policies {
		if in.Policies[name].Scope == network {
			u.Rules++
		}
	}
	return u
}

// Resources returns the resources that are in the scope of the Network network, in the order of
// intent.Resources: the Network itself, and its Nodes, Policies, Groups and Users.
func Resources(in intent.Intent, network string) []intent.Resource {
	var out []intent.Resource
	for _, r := range in.Resources() {
		if scope, _ := in.ScopeOf(r.Kind, r.Name); scope == network && scope != "" {
			out = append(out, r)
		}
	}
	return out
}

// permissionOf returns the permission that a change of a resource of kind needs, and false for a kind that
// no scoped role changes.
func permissionOf(kind string) (string, bool) {
	switch kind {
	case intent.KindNetwork:
		return PermNetwork, true
	case intent.KindNode:
		return PermNodes, true
	case intent.KindUser:
		return PermUsers, true
	case intent.KindGroup:
		return PermGroups, true
	case intent.KindPolicy:
		return PermRules, true
	}
	return "", false
}

// Caller is a scoped role that makes a change: the Network that it is held for, whether it is the role
// admin, the delegation of the Network and the Users that hold an API role.
type Caller struct {
	// Network is the Network of the scope.
	Network string
	// Admin is true for the role admin and false for the role operator. Only an admin changes the
	// Network itself.
	Admin bool
	// Delegation is the delegation of the Network: its zero value permits nothing and limits nothing.
	Delegation Delegation
	// Holders are the Users that hold an API role of any kind, global or scoped. A scoped role never
	// changes one: who may manage the controller is for the global roles to say.
	Holders map[string]bool
}

// Permit returns nil when the delegation of the caller permits perm, and an error that wraps
// ErrOutOfScope that says what it permits when it does not.
func (c Caller) Permit(perm string) error {
	if c.Delegation.Allows(perm) {
		return nil
	}
	permitted := "nothing"
	if len(c.Delegation.Permissions) > 0 {
		permitted = strings.Join(c.Delegation.Permissions, ", ")
	}
	return &Refusal{network: c.Network, problems: []error{fmt.Errorf("Network %q does not permit its scoped roles to change %s, and it permits %s", c.Network, perm, permitted)}}
}

// CheckUser returns nil when the caller may set the password of the User name in in, and an error that
// wraps ErrOutOfScope when it may not: the delegation permits users, the User is in the scope, and it holds
// no API role, since its password would be a way to the role.
func (c Caller) CheckUser(in intent.Intent, name string) error {
	if err := c.Permit(PermUsers); err != nil {
		return err
	}
	scope, held := in.ScopeOf(intent.KindUser, name)
	switch {
	case !held:
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, name)
	case scope != c.Network:
		return &Refusal{network: c.Network, problems: []error{fmt.Errorf("User %q is not in the scope of Network %q", name, c.Network)}}
	case c.Holders[name]:
		return &Refusal{network: c.Network, problems: []error{fmt.Errorf("User %q holds an API role, and only the global roles set the password of a User that does", name)}}
	}
	return nil
}

// CheckNode returns nil when the caller may act on the sessions of the Node name in in, and an error that
// wraps ErrOutOfScope when it may not: the delegation permits sessions and the Node is in the scope.
func (c Caller) CheckNode(in intent.Intent, name string) error {
	if err := c.Permit(PermSessions); err != nil {
		return err
	}
	if scope, _ := in.ScopeOf(intent.KindNode, name); scope != c.Network {
		return &Refusal{network: c.Network, problems: []error{fmt.Errorf("Node %q is not in the scope of Network %q", name, c.Network)}}
	}
	return nil
}

// Refusal is the error of a change that a scoped role may not make. It says which Network and lists every
// reason, one for each resource. It is an ErrOutOfScope, or an ErrQuota when the reasons are the quotas of
// the Network.
type Refusal struct {
	network  string
	quota    bool
	problems []error
}

func (r *Refusal) Error() string {
	head := fmt.Sprintf("the change is outside the scope of Network %q", r.network)
	if r.quota {
		head = fmt.Sprintf("the change is over a quota of Network %q", r.network)
	}
	return head + ":\n" + errors.Join(r.problems...).Error()
}

// Is makes a Refusal an ErrOutOfScope or an ErrQuota.
func (r *Refusal) Is(target error) bool {
	return (target == ErrQuota && r.quota) || (target == ErrOutOfScope && !r.quota)
}

// Unwrap returns the reasons.
func (r *Refusal) Unwrap() []error {
	return r.problems
}

// Check returns nil when the caller may make the change from prev, the intent in force, to next, the intent
// that the change makes, and a *Refusal that lists every reason when it may not. A change may add, change
// and remove only resources that are in the scope of the Network, before and after, of a kind that the
// delegation permits; what a resource of each kind may hold is checked by the function of its kind below.
// A change that holds more of a kind than its quota allows, and more than before, is refused last, so a
// refusal for the scope is never mixed with one for a quota.
func (c Caller) Check(prev, next intent.Intent) error {
	put, gone := intent.Changed(prev, next)
	var problems, quota []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	for _, r := range put {
		if !c.mayChange(r.Kind, r.Name, add) {
			continue
		}
		before, existed := prev.ScopeOf(r.Kind, r.Name)
		after, _ := next.ScopeOf(r.Kind, r.Name)
		switch {
		case r.Kind == intent.KindNetwork && (r.Name != c.Network || !existed):
			add("Network %q is not the Network of the scope, %q: a scoped role changes its own Network and cannot make another", r.Name, c.Network)
			continue
		case existed && before != c.Network:
			add("%s %q is not in the scope of Network %q", r.Kind, r.Name, c.Network)
			continue
		case after != c.Network:
			add("%s %q must be in the scope of Network %q: set its scope to %q%s", r.Kind, r.Name, c.Network, c.Network, c.ownerHint(r.Kind, after))
			continue
		}
		if r.Kind == intent.KindUser && c.Holders[r.Name] {
			add("User %q holds an API role, and only the global roles change a User that does", r.Name)
			continue
		}
		switch r.Kind {
		case intent.KindNetwork:
			c.checkNetwork(prev, next, add)
		case intent.KindNode:
			quota = append(quota, c.checkNode(next, r.Name, add)...)
		case intent.KindUser:
			c.checkUser(next, r.Name, add)
		case intent.KindGroup:
			c.checkGroup(prev, next, r.Name, add)
		case intent.KindPolicy:
			c.checkPolicy(next, r.Name, add)
		}
	}
	for _, r := range gone {
		if !c.mayChange(r.Kind, r.Name, add) {
			continue
		}
		switch before, _ := prev.ScopeOf(r.Kind, r.Name); {
		case r.Kind == intent.KindNetwork:
			add("Network %q cannot be deleted by a scoped role: the Network of the scope is the global roles' to delete", r.Name)
		case before != c.Network:
			add("%s %q is not in the scope of Network %q", r.Kind, r.Name, c.Network)
		case r.Kind == intent.KindUser && c.Holders[r.Name]:
			add("User %q holds an API role, and only the global roles delete a User that does", r.Name)
		}
	}
	if len(problems) > 0 {
		return &Refusal{network: c.Network, problems: problems}
	}
	quota = append(quota, c.overQuota(prev, next)...)
	if len(quota) > 0 {
		return &Refusal{network: c.Network, quota: true, problems: quota}
	}
	return nil
}

// mayChange reports whether the caller may change a resource of kind at all: the kind is one that a scoped
// role changes, the delegation permits it, and the Network itself is changed by an admin. When it may not,
// mayChange adds the reason.
func (c Caller) mayChange(kind, name string, add func(format string, args ...any)) bool {
	perm, ok := permissionOf(kind)
	switch {
	case !ok:
		add("%s %q: a scoped role changes the Network of its scope and the Nodes, the Users, the Groups and the Policies in it, and a %s is none of them", kind, name, kind)
	case !c.Delegation.Allows(perm):
		permitted := "nothing"
		if len(c.Delegation.Permissions) > 0 {
			permitted = strings.Join(c.Delegation.Permissions, ", ")
		}
		add("%s %q: Network %q does not permit its scoped roles to change %s, and it permits %s", kind, name, c.Network, perm, permitted)
	case perm == PermNetwork && !c.Admin:
		add("%s %q: changing the Network itself needs the role admin", kind, name)
	default:
		return true
	}
	return false
}

// ownerHint says how a Node that is in no scope can be put into this one, for the refusal of a Node whose
// scope is not the Network of the caller: it names the scope or has an owner of the scope.
func (c Caller) ownerHint(kind, after string) string {
	if kind == intent.KindNode && after == "" {
		return " or give it an owner that is in it"
	}
	return ""
}

// checkNetwork checks the change of the Network of the scope: its VRF, mode and pools stay as they were, and
// a Node that it names for the first time (the one that answers DHCP, the gateways of its security) is in the
// scope.
func (c Caller) checkNetwork(prev, next intent.Intent, add func(format string, args ...any)) {
	was, now := prev.Networks[c.Network], next.Networks[c.Network]
	if was.VRF != now.VRF || was.Mode != now.Mode || was.IPv4Pool != now.IPv4Pool || was.IPv6Pool != now.IPv6Pool {
		add("Network %q: the vrf, the mode and the pools of a Network are the global roles' to change", c.Network)
	}
	before := namedNodes(was)
	for _, node := range namedNodes(now) {
		if slices.Contains(before, node) {
			continue
		}
		if scope, _ := next.ScopeOf(intent.KindNode, node); scope != c.Network {
			add("Network %q: the Node %q that it names is not in the scope of Network %q", c.Network, node, c.Network)
		}
	}
}

// namedNodes returns the Nodes that the Network n names: the one that answers DHCP for it, and the gateways
// of its security.
func namedNodes(n intent.Network) []string {
	var out []string
	if n.DHCP != nil && n.DHCP.Node != "" {
		out = append(out, n.DHCP.Node)
	}
	if n.Security != nil {
		out = append(out, n.Security.Gateways...)
	}
	return out
}

// checkNode checks a Node that the change made or changed. It is in the VRF of the Network and in no other,
// and it sets only the fields below: the others (its relay, the LAN subnets that it advertises, its
// WireGuard end and tunnel endpoint, the endpoints that the other Nodes dial, and the mark of a key that
// never expires) reach the Nodes of the other Networks of its VRF, or the hosts around them, so they are the
// global roles'. The tags that it carries are tags of the Network, and its owner is a User of the scope. It
// returns the reasons that are about the bandwidth quota, which is a quota.
func (c Caller) checkNode(next intent.Intent, name string, add func(format string, args ...any)) []error {
	n := next.Nodes[name]
	if want := []string{next.Networks[c.Network].VRF}; !slices.Equal(n.VRFs, want) {
		add("Node %q: a Node of the scope is in the VRF %q of Network %q and in no other, and its vrfs are %v", name, want[0], c.Network, n.VRFs)
	}
	rest := n
	rest.PublicKey, rest.VRFs, rest.Tags, rest.Addresses, rest.IPv6Addresses = "", nil, nil, nil, nil
	rest.RateLimit, rest.Owner, rest.Scope = 0, "", ""
	if fields := setFields(rest); len(fields) > 0 {
		add("Node %q: a scoped role cannot set %s, which only the global roles do", name, strings.Join(fields, ", "))
	}
	for _, tag := range n.Tags {
		if !c.ownsTag(next, tag) {
			add("Node %q: the tag %q is not a tag of Network %q: a tag is the name of the Network, a name that starts with it and a hyphen, or the name of a Group in its scope", name, tag, c.Network)
		}
	}
	if n.Owner != "" && next.Users[n.Owner].Scope != c.Network {
		add("Node %q: its owner %q is not a User in the scope of Network %q", name, n.Owner, c.Network)
	}
	var quota []error
	if limit := c.Delegation.Quotas.Bandwidth; limit > 0 {
		switch {
		case n.RateLimit == 0:
			quota = append(quota, fmt.Errorf("Node %q has no rate limit, and Network %q allows its Nodes %d bit/s at most: set rateLimit to that or less", name, c.Network, limit))
		case n.RateLimit > limit:
			quota = append(quota, fmt.Errorf("Node %q has the rate limit %d bit/s, and Network %q allows its Nodes %d bit/s at most", name, n.RateLimit, c.Network, limit))
		}
	}
	return quota
}

// setFields returns the JSON names of the fields that n sets, in name order. n is a Node of which the fields
// that a scoped role may set are cleared, so what it returns is what the role may not. It reads the fields
// from the JSON of the Node, in which a field that is left out is not, so that a field that a later ticket
// adds to the Node is one that a scoped role may not set until this function says so.
func setFields(n intent.Node) []string {
	b, err := json.Marshal(n)
	if err != nil {
		return []string{"(the Node cannot be written: " + err.Error() + ")"}
	}
	var set map[string]json.RawMessage
	if err := json.Unmarshal(b, &set); err != nil {
		return []string{"(the Node cannot be read: " + err.Error() + ")"}
	}
	// The one field of a Node that the JSON writes even when it is empty
	delete(set, "publicKey")
	return slices.Sorted(maps.Keys(set))
}

// checkUser checks a User that the change made or changed: the Groups that it belongs to are Groups of the
// scope, since the name of a Group is a tag that the devices of its members carry, and a rule that names the
// tag applies to them.
func (c Caller) checkUser(next intent.Intent, name string, add func(format string, args ...any)) {
	for _, g := range next.Users[name].Groups {
		if next.Groups[g].Scope != c.Network {
			add("User %q: the Group %q is not in the scope of Network %q", name, g, c.Network)
		}
	}
}

// checkGroup checks a Group that the change made or changed. A Group that is made takes the name of a tag of
// the Network, since the name of a Group is a tag of policy and a Group that took the tag of another Network
// would give its members what the rules of that Network give.
func (c Caller) checkGroup(prev, next intent.Intent, name string, add func(format string, args ...any)) {
	if _, existed := prev.ScopeOf(intent.KindGroup, name); existed {
		return
	}
	if tagOwner(next, name) != c.Network {
		add("Group %q: the name of a Group that a scoped role makes is the name of Network %q or starts with it and a hyphen, since the name of a Group is a tag of policy", name, c.Network)
	}
}

// checkPolicy checks a Policy that the change made or changed: it is a rule of the VRF of the Network
// between ends that are in the Network, each a tag of the Network or an address in one of its pools. An end
// that names nothing is any end, so it is not one.
func (c Caller) checkPolicy(next intent.Intent, name string, add func(format string, args ...any)) {
	p := next.Policies[name]
	net := next.Networks[c.Network]
	if p.VRF != net.VRF {
		add("Policy %q: a rule of the scope is in the VRF %q of Network %q, not in %q", name, net.VRF, c.Network, p.VRF)
	}
	for _, end := range []struct {
		name string
		end  intent.PolicyEnd
	}{{"from", p.From}, {"to", p.To}} {
		if len(end.end.Tags) == 0 && len(end.end.Addresses) == 0 {
			add("Policy %q: its %s end names nothing, which is any end, and a rule of a scoped role is between ends in Network %q", name, end.name, c.Network)
		}
		for _, tag := range end.end.Tags {
			if !c.ownsTag(next, tag) {
				add("Policy %q: the tag %q at its %s end is not a tag of Network %q", name, tag, end.name, c.Network)
			}
		}
		for _, a := range end.end.Addresses {
			if !inPools(net, a) {
				add("Policy %q: the address %q at its %s end is not in a pool of Network %q", name, a, end.name, c.Network)
			}
		}
	}
}

// inPools reports whether the prefix or the address a lies within the IPv4 or the IPv6 pool of the Network n.
// An address that is no address, or a prefix that is wider than the pool, is in none.
func inPools(n intent.Network, a string) bool {
	p, err := netip.ParsePrefix(a)
	if err != nil {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return false
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	for _, pool := range []string{n.IPv4Pool, n.IPv6Pool} {
		pp, err := netip.ParsePrefix(pool)
		if err == nil && pp.Addr().BitLen() == p.Addr().BitLen() && pp.Bits() <= p.Bits() && pp.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// tagOwner returns the Network whose tag the tag is: the Network of the longest name that is the tag or that
// the tag starts with, followed by a hyphen. It is empty for a tag that no Network owns. The longest name
// wins, so the tag branch-a-staff is a tag of Network branch-a and not of Network branch.
func tagOwner(in intent.Intent, tag string) string {
	owner := ""
	for name := range in.Networks {
		if (tag == name || strings.HasPrefix(tag, name+"-")) && len(name) > len(owner) {
			owner = name
		}
	}
	return owner
}

// ownsTag reports whether the tag is one that the Network of the caller may give or name: a tag that the
// Network owns (tagOwner), or the name of a Group in its scope, which an admin of the controller named.
func (c Caller) ownsTag(in intent.Intent, tag string) bool {
	return tagOwner(in, tag) == c.Network || in.Groups[tag].Scope == c.Network
}

// overQuota returns the quotas of the Network that next takes over: a count above its quota, and above what
// it was in prev.
func (c Caller) overQuota(prev, next intent.Intent) []error {
	q, before, after := c.Delegation.Quotas, UsageOf(prev, c.Network), UsageOf(next, c.Network)
	var out []error
	for _, k := range []struct {
		what                 string
		limit, before, after uint32
	}{{"users", q.Users, before.Users, after.Users}, {"groups", q.Groups, before.Groups, after.Groups},
		{"nodes", q.Nodes, before.Nodes, after.Nodes}, {"rules", q.Rules, before.Rules, after.Rules}} {
		if k.limit > 0 && k.after > k.limit && k.after > k.before {
			out = append(out, fmt.Errorf("Network %q allows %d %s at most, and the change would make %d", c.Network, k.limit, k.what, k.after))
		}
	}
	return out
}
