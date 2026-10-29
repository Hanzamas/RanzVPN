package scope_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/scope"
)

// quotaCaller is an admin of branch-a whose delegation permits everything and has the quotas q.
func quotaCaller(q scope.Quotas) scope.Caller {
	c := admin("branch-a")
	c.Delegation.Quotas = q
	return c
}

// The scope is told before the intent speaks: CheckDocument and CheckDelete refuse what is not the caller's before
// the intent is asked, so that a refusal never carries what the intent would say of resources of other scopes, such as
// what depends on a VRF.
func TestTheScopeIsToldBeforeTheIntent(t *testing.T) {
	in := base(t)
	caller := admin("branch-a")
	caller.Holders = map[string]bool{"alice": true}
	for _, c := range []struct {
		name string
		rs   []intent.Resource
		want string // empty when nothing is wrong
	}{
		{"a resource of the scope", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-a"}`), res(intent.KindNode, "a-server", `{}`)}, ""},
		{"a resource of another scope", []intent.Resource{res(intent.KindUser, "bob", `{"scope": "branch-a"}`)}, `User "bob" is not in the scope of Network "branch-a"`},
		{"a kind that is not delegated", []intent.Resource{res(intent.KindVRF, "corp", `{}`)}, `a VRF is none of them`},
		{"another Network", []intent.Resource{res(intent.KindNetwork, "branch-b", `{}`)}, `Network "branch-b" is not the Network of the scope, "branch-a"`},
		{"its own Network", []intent.Resource{res(intent.KindNetwork, "branch-a", `{}`)}, ""},
		// What the document holds, wrong as it is for the intent, is not the scope's to say
		{"a document that is no intent", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "nowhere", "groups": ["nobody"]}`)}, ""},
	} {
		err := caller.CheckDocument(in, doc(c.rs...))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: CheckDocument refused: %v", c.name, err)
		case c.want != "" && (!errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: CheckDocument gave %v, want a refusal that says %q", c.name, err, c.want)
		}
	}
	// A caller whose delegation permits nothing is refused at the first resource
	if err := (scope.Caller{Network: "branch-a"}).CheckDocument(in, doc(res(intent.KindUser, "carol", `{}`))); !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("CheckDocument with no delegation gave %v", err)
	}

	for _, c := range []struct {
		kind, name string
		want       string
		err        error
	}{
		{intent.KindNode, "a-server", "", nil},
		{intent.KindGroup, "legacy", "", nil},
		{intent.KindNode, "b-server", `Node "b-server" is not in the scope of Network "branch-a"`, scope.ErrOutOfScope},
		{intent.KindNode, "hub", `Node "hub" is not in the scope`, scope.ErrOutOfScope},
		{intent.KindUser, "alice", `User "alice" holds an API role, and only the global roles delete a User that does`, scope.ErrOutOfScope},
		{intent.KindNetwork, "branch-a", `Network "branch-a" cannot be deleted by a scoped role`, scope.ErrOutOfScope},
		// The intent would list what uses the VRF, and the scope says only that it is not its to delete
		{intent.KindVRF, "corp", `a VRF is none of them`, scope.ErrOutOfScope},
		{intent.KindNode, "nobody", "no such resource", intent.ErrNotFound},
	} {
		err := caller.CheckDelete(in, c.kind, c.name)
		switch {
		case c.err == nil && err != nil:
			t.Errorf("CheckDelete(%s, %s) refused: %v", c.kind, c.name, err)
		case c.err != nil && (!errors.Is(err, c.err) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("CheckDelete(%s, %s) gave %v, want %v that says %q", c.kind, c.name, err, c.err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "is used by") {
			t.Errorf("CheckDelete(%s, %s) told what depends on the resource: %v", c.kind, c.name, err)
		}
	}
}

// A change that takes the Network over a quota is refused, naming the quota and the count that the change would
// make; one that stays within it passes, and so does one that adds nothing to a count that is over its quota.
func TestAChangeThatTakesTheNetworkOverAQuotaIsRefused(t *testing.T) {
	in := base(t) // branch-a holds 1 User, 2 Groups, 2 Nodes and 1 Policy
	users := func(names ...string) []intent.Resource {
		var rs []intent.Resource
		for _, n := range names {
			rs = append(rs, res(intent.KindUser, n, `{"scope": "branch-a"}`))
		}
		return rs
	}
	groups := func(names ...string) []intent.Resource {
		var rs []intent.Resource
		for _, n := range names {
			rs = append(rs, res(intent.KindGroup, n, `{"scope": "branch-a"}`))
		}
		return rs
	}
	nodes := func(first byte, names ...string) []intent.Resource {
		var rs []intent.Resource
		for i, n := range names {
			rs = append(rs, res(intent.KindNode, n, `{"publicKey": "`+key(first+byte(i))+`", "vrfs": ["corp"], "scope": "branch-a"}`))
		}
		return rs
	}
	rule := func(name string) intent.Resource {
		return res(intent.KindPolicy, name, `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"tags": ["branch-a-staff"]}}`)
	}
	for _, c := range []struct {
		name  string
		quota scope.Quotas
		rs    []intent.Resource
		want  string // empty when the change is allowed
	}{
		{"users, up to the quota", scope.Quotas{Users: 3}, users("c1", "c2"), ""},
		{"users, over the quota", scope.Quotas{Users: 3}, users("c1", "c2", "c3"), `Network "branch-a" allows 3 users at most, and the change would make 4`},
		{"groups, up to the quota", scope.Quotas{Groups: 3}, groups("branch-a-g1"), ""},
		{"groups, over the quota", scope.Quotas{Groups: 3}, groups("branch-a-g1", "branch-a-g2"), `Network "branch-a" allows 3 groups at most, and the change would make 4`},
		{"nodes, up to the quota", scope.Quotas{Nodes: 3}, nodes(50, "n1"), ""},
		{"nodes, over the quota", scope.Quotas{Nodes: 2}, nodes(60, "n1"), `Network "branch-a" allows 2 nodes at most, and the change would make 3`},
		{"rules, up to the quota", scope.Quotas{Rules: 2}, []intent.Resource{rule("r1")}, ""},
		{"rules, over the quota", scope.Quotas{Rules: 1}, []intent.Resource{rule("r1")}, `Network "branch-a" allows 1 rules at most, and the change would make 2`},
		{"no quota is no limit", scope.Quotas{}, append(users("c1", "c2", "c3", "c4"), nodes(70, "n1", "n2", "n3")...), ""},
		{"a count that is at its quota", scope.Quotas{Users: 1}, users("c1"), `allows 1 users at most, and the change would make 2`},
		{"two quotas", scope.Quotas{Users: 1, Nodes: 2}, append(users("c1"), nodes(80, "n1")...), `allows 1 users at most, and the change would make 2;allows 2 nodes at most, and the change would make 3`},
		{"a User that changes no count", scope.Quotas{Users: 1}, []intent.Resource{res(intent.KindUser, "alice", `{"scope": "branch-a", "displayName": "Alice", "groups": ["branch-a-staff"]}`)}, ""},
		{"the device of a User counts as a Node", scope.Quotas{Nodes: 2}, []intent.Resource{res(intent.KindNode, "alice-phone", `{"publicKey": "`+key(90)+`", "vrfs": ["corp"], "owner": "alice"}`)}, `allows 2 nodes at most, and the change would make 3`},
	} {
		err := try(t, in, quotaCaller(c.quota), c.rs...)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: the change was refused: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, scope.ErrQuota) || errors.Is(err, scope.ErrOutOfScope) {
			t.Errorf("%s: the change gave %v, want a refusal for a quota", c.name, err)
			continue
		}
		for _, want := range strings.Split(c.want, ";") {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal\n%v\ndoes not say %q", c.name, err, want)
			}
		}
		if !strings.HasPrefix(err.Error(), `the change is over a quota of Network "branch-a":`) {
			t.Errorf("%s: the refusal does not start by naming the Network: %v", c.name, err)
		}
	}
}

// A Network that is over a quota (the quota was lowered after the Network grew) still changes what it holds, and
// shrinks: only a change that adds to the count is refused.
func TestANetworkOverAQuotaCanStillShrink(t *testing.T) {
	in, err := intent.Apply(base(t), doc(
		res(intent.KindUser, "carol", `{"scope": "branch-a"}`),
		res(intent.KindUser, "dave", `{"scope": "branch-a"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := quotaCaller(scope.Quotas{Users: 2}) // branch-a holds 3 Users
	if err := try(t, in, caller, res(intent.KindUser, "carol", `{"scope": "branch-a", "displayName": "Carol"}`)); err != nil {
		t.Errorf("changing a User of a Network that is over its quota was refused: %v", err)
	}
	if err := try(t, in, caller, res(intent.KindUser, "erin", `{"scope": "branch-a"}`)); !errors.Is(err, scope.ErrQuota) {
		t.Errorf("making a User in a Network that is over its quota gave %v, want a refusal for the quota", err)
	}
	if err := tryDelete(t, in, caller, intent.KindUser, "carol"); err != nil {
		t.Errorf("deleting a User of a Network that is over its quota was refused: %v", err)
	}
	// Two Users go and one comes: the count falls, so the change passes
	next, err := intent.Delete(in, intent.KindUser, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if next, err = intent.Delete(next, intent.KindUser, "dave"); err != nil {
		t.Fatal(err)
	}
	if next, err = intent.Apply(next, doc(res(intent.KindUser, "erin", `{"scope": "branch-a"}`)), nil); err != nil {
		t.Fatal(err)
	}
	if err := caller.Check(in, next); err != nil {
		t.Errorf("a change that lowers the count of a Network that is over its quota was refused: %v", err)
	}
}

// The bandwidth quota is the greatest rate limit that a Node of the scope gets from a scoped role: a Node with
// none, which sends at any rate, is over it, and so is a Node above it.
func TestTheBandwidthQuotaBoundsTheRateLimitOfANode(t *testing.T) {
	in := base(t)
	caller := quotaCaller(scope.Quotas{Bandwidth: 1_000_000})
	node := func(name string, i byte, rate string) intent.Resource {
		return res(intent.KindNode, name, `{"publicKey": "`+key(i)+`", "vrfs": ["corp"], "scope": "branch-a"`+rate+`}`)
	}
	for _, c := range []struct {
		name string
		rs   intent.Resource
		want string
	}{
		{"at the quota", node("n1", 100, `, "rateLimit": 1000000`), ""},
		{"under the quota", node("n2", 101, `, "rateLimit": 64000`), ""},
		{"above the quota", node("n3", 102, `, "rateLimit": 1000001`), `Node "n3" has the rate limit 1000001 bit/s, and Network "branch-a" allows its Nodes 1000000 bit/s at most`},
		{"without a rate limit", node("n4", 103, ""), `Node "n4" has no rate limit, and Network "branch-a" allows its Nodes 1000000 bit/s at most: set rateLimit to that or less`},
	} {
		err := try(t, in, caller, c.rs)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: the Node was refused: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, scope.ErrQuota) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the Node gave %v, want a refusal for the quota that says %q", c.name, err, c.want)
		}
	}
	// A Node that the change does not touch is not judged: a-server has no rate limit and stays so
	if err := try(t, in, caller, res(intent.KindUser, "carol", `{"scope": "branch-a"}`)); err != nil {
		t.Errorf("a change that leaves the Nodes of the scope alone was refused for their rate limits: %v", err)
	}
	// Without the quota, a Node has any rate limit
	if err := try(t, in, admin("branch-a"), node("n5", 104, "")); err != nil {
		t.Errorf("a Node was refused for its rate limit by a Network that has no bandwidth quota: %v", err)
	}
}

// A refusal for the scope is never mixed with one for a quota: a change that has both is refused for the
// scope, and for the quota once the scope is put right.
func TestAScopeRefusalComesBeforeAQuotaRefusal(t *testing.T) {
	in := base(t)
	caller := quotaCaller(scope.Quotas{Users: 1})
	both := []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-a"}`), res(intent.KindUser, "dave", `{"scope": "branch-b"}`)}
	err := try(t, in, caller, both...)
	if !errors.Is(err, scope.ErrOutOfScope) || errors.Is(err, scope.ErrQuota) || strings.Contains(err.Error(), "allows 1 users") {
		t.Errorf("a change with a refusal for the scope and one for a quota gave %v, want the first only", err)
	}
	if err := try(t, in, caller, both[0]); !errors.Is(err, scope.ErrQuota) {
		t.Errorf("the change with the scope put right gave %v, want the refusal for the quota", err)
	}
}

// Normalize writes the permissions in their order and refuses what is not a delegation.
func TestNormalizeChecksADelegation(t *testing.T) {
	got, err := scope.Delegation{Network: "branch-a", Permissions: []string{scope.PermSessions, scope.PermUsers, scope.PermNetwork}}.Normalize()
	if err != nil || !slices.Equal(got.Permissions, []string{scope.PermNetwork, scope.PermUsers, scope.PermSessions}) {
		t.Errorf("Normalize gave %v, %v, want the permissions in the order of scope.Permissions", got, err)
	}
	got, err = scope.Delegation{Network: "branch-a"}.Normalize()
	if err != nil || got.Permissions == nil || len(got.Permissions) != 0 {
		t.Errorf("Normalize of a delegation with no permission gave %#v, %v, want an empty list", got.Permissions, err)
	}
	if !got.Allows("") && got.Allows(scope.PermUsers) {
		t.Error("a delegation with no permission allows one")
	}
	for _, c := range []struct {
		name string
		d    scope.Delegation
		want string
	}{
		{"a name that is none", scope.Delegation{Network: "Branch_A"}, `the Network name "Branch_A"`},
		{"no name", scope.Delegation{}, `the Network name ""`},
		{"a permission that is none", scope.Delegation{Network: "a", Permissions: []string{"users", "bridges"}}, `the permission "bridges" is none of network, nodes, users, groups, rules, sessions`},
		{"a permission twice", scope.Delegation{Network: "a", Permissions: []string{"users", "users"}}, `the permission "users" is listed twice`},
		{"a quota that is too big", scope.Delegation{Network: "a", Quotas: scope.Quotas{Users: scope.MaxQuota + 1}}, "the users quota 1048577 is above the most that there is, 1048576"},
		{"a bandwidth that is too big", scope.Delegation{Network: "a", Quotas: scope.Quotas{Bandwidth: scope.MaxBandwidth + 1}}, "the bandwidth quota"},
	} {
		if _, err := c.d.Normalize(); !errors.Is(err, scope.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Normalize gave %v, want an ErrInvalid that says %q", c.name, err, c.want)
		}
	}
}

// UsageOf counts what the Network holds in its scope, and Resources lists it.
func TestUsageAndResourcesOfAScope(t *testing.T) {
	in := base(t)
	if got, want := scope.UsageOf(in, "branch-a"), (scope.Usage{Users: 1, Groups: 2, Nodes: 2, Rules: 1}); got != want {
		t.Errorf("branch-a holds %+v, want %+v", got, want)
	}
	if got, want := scope.UsageOf(in, "branch-b"), (scope.Usage{Users: 1, Nodes: 1}); got != want {
		t.Errorf("branch-b holds %+v, want %+v", got, want)
	}
	if got := scope.UsageOf(in, "lab-lan"); got != (scope.Usage{}) {
		t.Errorf("lab-lan holds %+v, want nothing", got)
	}
	var names []string
	for _, r := range scope.Resources(in, "branch-a") {
		names = append(names, r.Kind+"/"+r.Name)
	}
	want := []string{"Network/branch-a", "Node/a-server", "Node/alice-laptop", "Policy/a-lan", "Group/branch-a-staff", "Group/legacy", "User/alice"}
	if !slices.Equal(names, want) {
		t.Errorf("the resources of branch-a are %v, want %v", names, want)
	}
	if got := scope.Resources(in, ""); len(got) != 0 {
		t.Errorf("the resources of the scope of no Network are %v, want none", got)
	}
}

// Permit, CheckUser and CheckNode answer for the operations that are no change of the intent: setting the
// password of a User, and ending a session.
func TestTheOperationsOfAScope(t *testing.T) {
	in := base(t)
	caller := admin("branch-a")
	if err := caller.Permit(scope.PermSessions); err != nil {
		t.Errorf("Permit refused what the delegation permits: %v", err)
	}
	only := scope.Caller{Network: "branch-a", Delegation: scope.Delegation{Network: "branch-a", Permissions: []string{scope.PermUsers}}}
	if err := only.Permit(scope.PermSessions); !errors.Is(err, scope.ErrOutOfScope) ||
		!strings.Contains(err.Error(), `Network "branch-a" does not permit its scoped roles to change sessions, and it permits users`) {
		t.Errorf("Permit of a permission that the delegation leaves out gave %v", err)
	}

	if err := caller.CheckUser(in, "alice"); err != nil {
		t.Errorf("CheckUser refused a User of the scope: %v", err)
	}
	for _, c := range []struct{ user, want string }{
		{"bob", `User "bob" is not in the scope of Network "branch-a"`},
		{"root", `User "root" is not in the scope`},
		{"nobody", `no such resource: User "nobody"`},
	} {
		if err := caller.CheckUser(in, c.user); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("CheckUser(%s) gave %v, want %q", c.user, err, c.want)
		}
	}
	if err := caller.CheckUser(in, "nobody"); !errors.Is(err, intent.ErrNotFound) {
		t.Errorf("CheckUser of a User that does not exist gave %v, want ErrNotFound", err)
	}
	holder := admin("branch-a")
	holder.Holders = map[string]bool{"alice": true}
	if err := holder.CheckUser(in, "alice"); !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), "holds an API role") {
		t.Errorf("CheckUser of a User that holds a role gave %v", err)
	}
	if err := only.CheckUser(in, "alice"); err != nil {
		t.Errorf("CheckUser refused a User of the scope to a delegation that permits users: %v", err)
	}
	if err := (scope.Caller{Network: "branch-a"}).CheckUser(in, "alice"); !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("CheckUser with no delegation gave %v", err)
	}

	for _, node := range []string{"a-server", "alice-laptop"} {
		if err := caller.CheckNode(in, node); err != nil {
			t.Errorf("CheckNode refused the Node %s of the scope: %v", node, err)
		}
	}
	for _, node := range []string{"b-server", "hub", "nobody"} {
		if err := caller.CheckNode(in, node); !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), "is not in the scope of Network") {
			t.Errorf("CheckNode(%s) gave %v, want a refusal", node, err)
		}
	}
	if err := only.CheckNode(in, "a-server"); !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("CheckNode to a delegation that does not permit sessions gave %v", err)
	}
}

// The name of a Group is a tag, and a tag belongs to the Network of the longest name that it starts with: with
// Networks branch and branch-a, the tag branch-a-staff is a tag of branch-a, so the scoped role of branch cannot
// make a Group of that name, and the one of branch-a can.
func TestATagBelongsToTheNetworkOfTheLongestName(t *testing.T) {
	in, err := intent.Apply(intent.New(), doc(
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "branch", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	staff := func(network string) intent.Resource {
		return res(intent.KindGroup, "branch-a-staff", `{"scope": "`+network+`"}`)
	}
	err = try(t, in, admin("branch"), staff("branch"))
	if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), `Group "branch-a-staff": the name of a Group that a scoped role makes`) {
		t.Errorf("the role of branch making the Group branch-a-staff gave %v", err)
	}
	if err := try(t, in, admin("branch"), res(intent.KindGroup, "branch-staff", `{"scope": "branch"}`), res(intent.KindGroup, "branch", `{"scope": "branch"}`)); err != nil {
		t.Errorf("the role of branch making a Group named after branch was refused: %v", err)
	}
	if err := try(t, in, admin("branch-a"), staff("branch-a")); err != nil {
		t.Errorf("the role of branch-a making the Group branch-a-staff was refused: %v", err)
	}
}

// The Nodes that a Network names, the one that answers DHCP for it and the gateways of its security, are Nodes
// of its scope: the Node then runs what the Network says, and no Node of another scope is made to.
func TestTheNodesThatANetworkNamesAreInItsScope(t *testing.T) {
	in, err := intent.Apply(intent.New(), doc(
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "branch-l2", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.50.0.0/24"}`),
		res(intent.KindNode, "l2-node", `{"publicKey": "`+key(1)+`", "vrfs": ["corp"], "scope": "branch-l2"}`),
		res(intent.KindNode, "hub", `{"publicKey": "`+key(2)+`", "vrfs": ["corp"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := admin("branch-l2")
	network := func(extra string) intent.Resource {
		return res(intent.KindNetwork, "branch-l2", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.50.0.0/24", `+extra+`}`)
	}
	if err := try(t, in, caller, network(`"dhcp": {"mode": "pool", "node": "l2-node"}`)); err != nil {
		t.Errorf("a DHCP responder of the scope was refused: %v", err)
	}
	if err := try(t, in, caller, network(`"security": {"checkMac": true, "gateways": ["l2-node"]}`)); err != nil {
		t.Errorf("a gateway of the scope was refused: %v", err)
	}
	for _, c := range []struct{ name, extra string }{
		{"DHCP", `"dhcp": {"mode": "pool", "node": "hub"}`},
		{"a gateway", `"security": {"checkMac": true, "gateways": ["hub"]}`},
	} {
		err := try(t, in, caller, network(c.extra))
		if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), `Network "branch-l2": the Node "hub" that it names is not in the scope of Network "branch-l2"`) {
			t.Errorf("a Node of no scope as %s gave %v", c.name, err)
		}
	}
}
