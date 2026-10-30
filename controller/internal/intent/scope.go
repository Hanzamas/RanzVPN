package intent

import (
	"fmt"
	"strconv"
)

// The scope of a resource (SDN-38 #231, ADR-0031 amendment of 2026-10-29). A role of the API can be held
// for one Network (internal/rbac, Grant), and the Controller lets it change the resources of that Network
// and no others: the Network itself and the Users, the Groups, the Nodes and the Policies that are in its
// scope. A User, a Group, a Node and a Policy say so in their `scope`, the name of a Network, which an
// intent that holds a scope that is no Network refuses. The scope is a property of the declared network
// and so lives in the intent, where a revision, a rollback and an export carry it; the quotas and the
// permissions that bind the scoped roles of a Network do not (internal/scope), since a role that the
// intent could change would change its own limits. A Node that names no scope is in the scope of its
// owner, so the device that a User of a Network enrols is in that Network without anyone saying so.

// ScopeOf returns the name of the Network in whose scope the resource kind/name of in is, and whether in
// holds the resource. A Network is in its own scope. The scope is empty for a resource that is in none,
// which only the global roles administer, and for a kind that has no scope.
func (in Intent) ScopeOf(kind, name string) (network string, held bool) {
	switch kind {
	case KindNetwork:
		if _, ok := in.Networks[name]; ok {
			return name, true
		}
	case KindNode:
		if n, ok := in.Nodes[name]; ok {
			if n.Scope == "" && n.Owner != "" {
				return in.Users[n.Owner].Scope, true
			}
			return n.Scope, true
		}
	case KindUser:
		if u, ok := in.Users[name]; ok {
			return u.Scope, true
		}
	case KindGroup:
		if g, ok := in.Groups[name]; ok {
			return g.Scope, true
		}
	case KindPolicy:
		if p, ok := in.Policies[name]; ok {
			return p.Scope, true
		}
	}
	return "", false
}

// validateScopes checks that the scope of each User, Group, Node and Policy of a completed intent names a
// Network of it.
func (in Intent) validateScopes() []error {
	var problems []error
	check := func(kind, name, scope string) {
		if _, ok := in.Networks[scope]; scope != "" && !ok {
			problems = append(problems, fmt.Errorf("%s %q: the scope %q is no Network", kind, name, scope))
		}
	}
	for _, name := range sortedNames(in.Users) {
		check(KindUser, name, in.Users[name].Scope)
	}
	for _, name := range sortedNames(in.Groups) {
		check(KindGroup, name, in.Groups[name].Scope)
	}
	for _, name := range sortedNames(in.Nodes) {
		check(KindNode, name, in.Nodes[name].Scope)
	}
	for _, name := range sortedNames(in.Policies) {
		check(KindPolicy, name, in.Policies[name].Scope)
	}
	return problems
}

// scopeUsers returns the resources that name the Network network as their scope, each as its kind and its
// quoted name: the Users, the Groups, the Nodes and the Policies, in that order, each in name order. A Network
// that has any cannot be deleted.
func (in Intent) scopeUsers(network string) []string {
	var out []string
	for _, name := range sortedNames(in.Users) {
		if in.Users[name].Scope == network {
			out = append(out, KindUser+" "+strconv.Quote(name))
		}
	}
	for _, name := range sortedNames(in.Groups) {
		if in.Groups[name].Scope == network {
			out = append(out, KindGroup+" "+strconv.Quote(name))
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		if in.Nodes[name].Scope == network {
			out = append(out, KindNode+" "+strconv.Quote(name))
		}
	}
	for _, name := range sortedNames(in.Policies) {
		if in.Policies[name].Scope == network {
			out = append(out, KindPolicy+" "+strconv.Quote(name))
		}
	}
	return out
}
