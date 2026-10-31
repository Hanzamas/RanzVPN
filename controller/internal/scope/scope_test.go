package scope_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/scope"
)

// key returns the public key of a Node that is the byte i 32 times, as a Node resource writes it.
func key(i byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{i}, intent.KeySize))
}

func res(kind, name, spec string) intent.Resource {
	return intent.Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
}

func doc(rs ...intent.Resource) intent.Document {
	return intent.Document{Resources: rs}
}

// all is a delegation that permits every permission and limits nothing.
func all(network string) scope.Delegation {
	return scope.Delegation{Network: network, Permissions: slices.Clone(scope.Permissions)}
}

// base is the intent of the tests: the VRF corp, with the Networks branch-a and branch-b, and the VRF lab with
// lab-lan. In the scope of branch-a: the Groups branch-a-staff and legacy, the User alice, who is of
// branch-a-staff and has the device alice-laptop, the Node a-server and the Policy a-lan. In the scope of
// branch-b: the User bob and the Node b-server. In none: the Group hq, the User root, the Node hub and the
// Policy hq-allow.
func base(t *testing.T) intent.Intent {
	t.Helper()
	in, err := intent.Apply(intent.New(), doc(
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "branch-b", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.30.0.0/24"}`),
		res(intent.KindGroup, "branch-a-staff", `{"scope": "branch-a"}`),
		res(intent.KindGroup, "legacy", `{"scope": "branch-a"}`),
		res(intent.KindGroup, "hq", `{}`),
		res(intent.KindUser, "alice", `{"groups": ["branch-a-staff"], "scope": "branch-a"}`),
		res(intent.KindUser, "bob", `{"scope": "branch-b"}`),
		res(intent.KindUser, "root", `{}`),
		res(intent.KindNode, "a-server", `{"publicKey": "`+key(1)+`", "vrfs": ["corp"], "scope": "branch-a"}`),
		res(intent.KindNode, "alice-laptop", `{"publicKey": "`+key(2)+`", "vrfs": ["corp"], "owner": "alice"}`),
		res(intent.KindNode, "b-server", `{"publicKey": "`+key(3)+`", "vrfs": ["corp"], "scope": "branch-b"}`),
		res(intent.KindNode, "hub", `{"publicKey": "`+key(4)+`", "vrfs": ["corp"]}`),
		res(intent.KindPolicy, "a-lan", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"addresses": ["10.10.0.0/24"]}}`),
		res(intent.KindPolicy, "hq-allow", `{"vrf": "corp", "action": "allow"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// try applies the resources rs to prev and returns what the caller's check says of the change, and what the
// apply says when the intent refuses it.
func try(t *testing.T, prev intent.Intent, c scope.Caller, rs ...intent.Resource) error {
	t.Helper()
	next, err := intent.Apply(prev, doc(rs...), nil)
	if err != nil {
		t.Fatalf("the intent refuses the apply, which only the check may: %v", err)
	}
	return c.Check(prev, next)
}

// tryDelete deletes the resource kind/name from prev and returns what the caller's check says of the change.
func tryDelete(t *testing.T, prev intent.Intent, c scope.Caller, kind, name string) error {
	t.Helper()
	next, err := intent.Delete(prev, kind, name)
	if err != nil {
		t.Fatalf("the intent refuses the delete, which only the check may: %v", err)
	}
	return c.Check(prev, next)
}

func admin(network string) scope.Caller {
	return scope.Caller{Network: network, Admin: true, Delegation: all(network)}
}

// The scoped role of branch-a makes and changes what is in the scope of branch-a, and the check says what is
// wrong with a change for each resource that is wrong, naming it.
func TestACallerChangesOnlyWhatIsInItsScope(t *testing.T) {
	in := base(t)
	for _, c := range []struct {
		name string
		rs   []intent.Resource
		want string // empty when the change is allowed, else a part of every refusal that the error holds, ";" apart
	}{
		{"a User of the scope", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-a", "groups": ["legacy"]}`)}, ""},
		{"a User of another scope", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-b"}`)}, `User "carol" must be in the scope of Network "branch-a"`},
		{"a User of no scope", []intent.Resource{res(intent.KindUser, "carol", `{}`)}, `User "carol" must be in the scope of Network "branch-a"`},
		{"a User of another scope that exists", []intent.Resource{res(intent.KindUser, "bob", `{"scope": "branch-a"}`)}, `User "bob" is not in the scope of Network "branch-a"`},
		{"a User of no scope that exists", []intent.Resource{res(intent.KindUser, "root", `{"displayName": "Root", "scope": "branch-a"}`)}, `User "root" is not in the scope of Network "branch-a"`},
		{"a User in a Group of no scope", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-a", "groups": ["hq"]}`)}, `User "carol": the Group "hq" is not in the scope of Network "branch-a"`},
		{"two refusals", []intent.Resource{res(intent.KindUser, "carol", `{"scope": "branch-b"}`), res(intent.KindUser, "dave", `{}`)}, `User "carol" must be in;User "dave" must be in`},
		{"a Group named after the Network", []intent.Resource{res(intent.KindGroup, "branch-a-sales", `{"scope": "branch-a"}`), res(intent.KindGroup, "branch-a", `{"scope": "branch-a"}`)}, ""},
		{"a Group that takes a name of no Network", []intent.Resource{res(intent.KindGroup, "sales", `{"scope": "branch-a"}`)}, `Group "sales": the name of a Group that a scoped role makes is the name of Network "branch-a" or starts with it`},
		{"a Group that takes a tag of another Network", []intent.Resource{res(intent.KindGroup, "branch-b-admins", `{"scope": "branch-a"}`)}, `Group "branch-b-admins": the name of a Group`},
		{"a Group that takes a name that only starts like the Network", []intent.Resource{res(intent.KindGroup, "branch-ab", `{"scope": "branch-a"}`)}, `Group "branch-ab": the name of a Group`},
		{"a Group of the scope that an admin named, changed", []intent.Resource{res(intent.KindGroup, "legacy", `{"scope": "branch-a", "displayName": "Legacy"}`)}, ""},
		{"a Group of no scope, changed", []intent.Resource{res(intent.KindGroup, "hq", `{"displayName": "HQ", "scope": "branch-a"}`)}, `Group "hq" is not in the scope`},
		{"a Node of the scope", []intent.Resource{res(intent.KindNode, "a-laptop", `{"publicKey": "`+key(10)+`", "vrfs": ["corp"], "scope": "branch-a", "tags": ["branch-a-laptop", "legacy"], "owner": "alice", "rateLimit": 1000}`)}, ""},
		{"a Node that is the device of a User of the scope", []intent.Resource{res(intent.KindNode, "alice-phone", `{"publicKey": "`+key(11)+`", "vrfs": ["corp"], "owner": "alice"}`)}, ""},
		{"a Node of no scope and no owner", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(12)+`", "vrfs": ["corp"]}`)}, `Node "n" must be in the scope of Network "branch-a": set its scope to "branch-a" or give it an owner that is in it`},
		{"a Node of another scope that exists", []intent.Resource{res(intent.KindNode, "b-server", `{"publicKey": "`+key(3)+`", "vrfs": ["corp"], "scope": "branch-a"}`)}, `Node "b-server" is not in the scope`},
		{"a Node of no scope that exists", []intent.Resource{res(intent.KindNode, "hub", `{"publicKey": "`+key(4)+`", "vrfs": ["corp"], "scope": "branch-a", "tags": ["x"]}`)}, `Node "hub" is not in the scope`},
		{"a Node in a VRF of no Network of the scope", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(13)+`", "vrfs": ["lab"], "scope": "branch-a"}`)}, `Node "n": a Node of the scope is in the VRF "corp" of Network "branch-a" and in no other, and its vrfs are [lab]`},
		{"a Node in two VRFs", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(14)+`", "vrfs": ["corp", "lab"], "scope": "branch-a"}`)}, `a Node of the scope is in the VRF "corp"`},
		{"a Node whose owner is in another scope", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(15)+`", "vrfs": ["corp"], "scope": "branch-a", "owner": "bob"}`)}, `Node "n": its owner "bob" is not a User in the scope of Network "branch-a"`},
		{"a Node of a User of another scope", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(16)+`", "vrfs": ["corp"], "owner": "bob"}`)}, `Node "n" must be in the scope of Network "branch-a"`},
		{"a Node with the tag of a Group that is no one's", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(17)+`", "vrfs": ["corp"], "scope": "branch-a", "tags": ["hq"]}`)}, `Node "n": the tag "hq" is not a tag of Network "branch-a"`},
		{"a Node with a tag of another Network", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(18)+`", "vrfs": ["corp"], "scope": "branch-a", "tags": ["branch-b-servers"]}`)}, `the tag "branch-b-servers" is not a tag of Network "branch-a"`},
		{"a Node that is a relay", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(19)+`", "vrfs": ["corp"], "scope": "branch-a", "relay": "192.0.2.1:3478"}`)}, `Node "n": a scoped role cannot set relay, which only the global roles do`},
		{"a Node that advertises a LAN", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(20)+`", "vrfs": ["corp"], "scope": "branch-a", "lanSubnets": {"corp": ["192.168.50.0/24"]}}`)}, `a scoped role cannot set lanSubnets`},
		{"a Node that is never refreshed", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(21)+`", "vrfs": ["corp"], "scope": "branch-a", "nonExpiring": true}`)}, `a scoped role cannot set nonExpiring`},
		{"a Node that others dial", []intent.Resource{res(intent.KindNode, "n", `{"publicKey": "`+key(22)+`", "vrfs": ["corp"], "scope": "branch-a", "endpoints": [{"transport": "quic", "address": "192.0.2.5:443"}]}`)}, `a scoped role cannot set endpoints`},
		{"a Policy of the scope", []intent.Resource{res(intent.KindPolicy, "a-ssh", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "protocol": "tcp", "ports": ["22"], "from": {"tags": ["branch-a-staff", "legacy"]}, "to": {"addresses": ["10.10.0.0/25", "10.10.0.200"]}}`)}, ""},
		{"a Policy of another VRF", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "lab", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"tags": ["branch-a-staff"]}}`)}, `Policy "p": a rule of the scope is in the VRF "corp" of Network "branch-a", not in "lab"`},
		{"a Policy from any end", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "to": {"tags": ["branch-a-staff"]}}`)}, `Policy "p": its from end names nothing`},
		{"a Policy to any end", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}}`)}, `Policy "p": its to end names nothing`},
		{"a Policy with a tag of no one", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["hq"]}, "to": {"tags": ["branch-a-staff"]}}`)}, `Policy "p": the tag "hq" at its from end is not a tag of Network "branch-a"`},
		{"a Policy with the address of another Network", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "deny", "from": {"tags": ["branch-a-staff"]}, "to": {"addresses": ["10.20.0.5"]}}`)}, `Policy "p": the address "10.20.0.5" at its to end is not in a pool of Network "branch-a"`},
		{"a Policy with an address wider than the pool", []intent.Resource{res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"addresses": ["10.10.0.0/16"]}}`)}, `the address "10.10.0.0/16" at its to end is not in a pool`},
		{"a Policy of no scope that exists", []intent.Resource{res(intent.KindPolicy, "hq-allow", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"tags": ["branch-a-staff"]}}`)}, `Policy "hq-allow" is not in the scope`},
		{"the Network of the scope", []intent.Resource{res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "approval": "manual", "keyLifetimeDays": 30}`)}, ""},
		{"another Network", []intent.Resource{res(intent.KindNetwork, "branch-b", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24", "approval": "manual"}`)}, `Network "branch-b" is not the Network of the scope, "branch-a"`},
		{"a new Network", []intent.Resource{res(intent.KindNetwork, "branch-c", `{"vrf": "corp", "ipv4Pool": "10.40.0.0/24"}`)}, `Network "branch-c" is not the Network of the scope`},
		{"the VRF of the Network", []intent.Resource{res(intent.KindNetwork, "branch-a", `{"vrf": "lab", "ipv4Pool": "10.10.0.0/24"}`)}, `Network "branch-a": the vrf, the mode and the pools of a Network are the global roles' to change`},
		{"the pool of the Network", []intent.Resource{res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.11.0.0/24"}`)}, `the pools of a Network are the global roles' to change`},
		{"a VRF", []intent.Resource{res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}`)}, `VRF "corp": a scoped role changes the Network of its scope and the Nodes, the Users, the Groups and the Policies in it, and a VRF is none of them`},
		{"a Controller", []intent.Resource{res(intent.KindController, "c1", `{"address": "192.0.2.1:443", "publicKey": "`+key(30)+`"}`)}, `a Controller is none of them`},
		{"an Endpoint, which publishes a service of one VRF into another", []intent.Resource{res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48", "dns": true}`),
			res(intent.KindEndpoint, "billing", `{"vrf": "corp", "node": "a-server", "address": "10.10.0.1", "port": 443, "consumer": "lab", "as": "172.16.1.1"}`)},
			`Endpoint "billing": a scoped role changes the Network of its scope and the Nodes, the Users, the Groups and the Policies in it`},
	} {
		err := try(t, in, admin("branch-a"), c.rs...)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: the change was refused: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, scope.ErrOutOfScope) || errors.Is(err, scope.ErrQuota) {
			t.Errorf("%s: the change gave %v, want a refusal for the scope", c.name, err)
			continue
		}
		for _, want := range strings.Split(c.want, ";") {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal\n%v\ndoes not say %q", c.name, err, want)
			}
		}
		if !strings.HasPrefix(err.Error(), `the change is outside the scope of Network "branch-a":`) {
			t.Errorf("%s: the refusal does not start by naming the Network: %v", c.name, err)
		}
	}
}

// A change is checked as what it does to the intent, not as what the call named: a resource that the change
// leaves as it was is no part of it.
func TestAChangeThatLeavesAResourceAsItWasDoesNotTouchIt(t *testing.T) {
	in := base(t)
	// bob is of branch-b, and the document holds him as he is: the change adds carol only
	if err := try(t, in, admin("branch-a"),
		res(intent.KindUser, "bob", `{"scope": "branch-b"}`),
		res(intent.KindUser, "carol", `{"scope": "branch-a"}`)); err != nil {
		t.Errorf("a document that holds a resource of another scope as it is was refused: %v", err)
	}
	// An empty change is no change
	if err := admin("branch-a").Check(in, in); err != nil {
		t.Errorf("no change was refused: %v", err)
	}
}

// Deleting is changing: a scoped role deletes what is in its scope, of a kind that it may change, and nothing
// else, and never the Network itself.
func TestACallerDeletesOnlyWhatIsInItsScope(t *testing.T) {
	in := base(t)
	for _, c := range []struct {
		kind, name string
		want       string
	}{
		{intent.KindNode, "a-server", ""},
		{intent.KindNode, "alice-laptop", ""},
		{intent.KindPolicy, "a-lan", ""},
		{intent.KindGroup, "legacy", ""},
		{intent.KindNode, "b-server", `Node "b-server" is not in the scope of Network "branch-a"`},
		{intent.KindNode, "hub", `Node "hub" is not in the scope`},
		{intent.KindUser, "bob", `User "bob" is not in the scope`},
		{intent.KindGroup, "hq", `Group "hq" is not in the scope`},
		{intent.KindPolicy, "hq-allow", `Policy "hq-allow" is not in the scope`},
	} {
		err := tryDelete(t, in, admin("branch-a"), c.kind, c.name)
		if c.want == "" {
			if err != nil {
				t.Errorf("deleting %s %s was refused: %v", c.kind, c.name, err)
			}
			continue
		}
		if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("deleting %s %s gave %v, want a refusal that says %q", c.kind, c.name, err, c.want)
		}
	}

	// The Network of the scope is the global roles' to delete, with nothing left in its scope to stop the intent
	empty, err := intent.Apply(intent.New(), doc(
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tryDelete(t, empty, admin("branch-a"), intent.KindNetwork, "branch-a"); !errors.Is(err, scope.ErrOutOfScope) ||
		!strings.Contains(err.Error(), `Network "branch-a" cannot be deleted by a scoped role`) {
		t.Errorf("deleting the Network of the scope gave %v", err)
	}
}

// A role that is held for a Network is an operator or an admin: only an admin changes the Network itself, and
// the Network is changed only when its delegation permits it.
func TestOnlyAnAdminChangesTheNetworkItself(t *testing.T) {
	in := base(t)
	network := res(intent.KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "approval": "manual"}`)
	operator := scope.Caller{Network: "branch-a", Delegation: all("branch-a")}
	if err := try(t, in, operator, network); !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), `Network "branch-a": changing the Network itself needs the role admin`) {
		t.Errorf("an operator changing the Network gave %v", err)
	}
	// What an operator may change, it changes
	if err := try(t, in, operator, res(intent.KindUser, "carol", `{"scope": "branch-a"}`)); err != nil {
		t.Errorf("an operator making a User was refused: %v", err)
	}
	noNetwork := scope.Caller{Network: "branch-a", Admin: true, Delegation: scope.Delegation{Network: "branch-a", Permissions: []string{scope.PermUsers}}}
	if err := try(t, in, noNetwork, network); !errors.Is(err, scope.ErrOutOfScope) ||
		!strings.Contains(err.Error(), `Network "branch-a" does not permit its scoped roles to change network, and it permits users`) {
		t.Errorf("an admin whose delegation does not permit the Network gave %v", err)
	}
}

// What the delegation permits is what a scoped role changes: a kind that it leaves out is refused, with what it
// permits, and a delegation that permits nothing refuses every change.
func TestTheDelegationPermitsTheKindsThatItNames(t *testing.T) {
	in := base(t)
	user := res(intent.KindUser, "carol", `{"scope": "branch-a"}`)
	group := res(intent.KindGroup, "branch-a-sales", `{"scope": "branch-a"}`)
	node := res(intent.KindNode, "n", `{"publicKey": "`+key(40)+`", "vrfs": ["corp"], "scope": "branch-a"}`)
	policy := res(intent.KindPolicy, "p", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"tags": ["branch-a-staff"]}}`)
	for _, c := range []struct {
		name    string
		permits []string
		allowed []intent.Resource
		refused []intent.Resource
		perm    string
	}{
		{"users", []string{scope.PermUsers}, []intent.Resource{user}, []intent.Resource{group, node, policy}, "groups"},
		{"groups and nodes", []string{scope.PermNodes, scope.PermGroups}, []intent.Resource{group, node}, []intent.Resource{user, policy}, "users"},
		{"rules", []string{scope.PermRules}, []intent.Resource{policy}, []intent.Resource{user, group, node}, "users"},
		{"nothing", nil, nil, []intent.Resource{user, group, node, policy}, "users"},
	} {
		caller := scope.Caller{Network: "branch-a", Admin: true, Delegation: scope.Delegation{Network: "branch-a", Permissions: c.permits}}
		for _, r := range c.allowed {
			if err := try(t, in, caller, r); err != nil {
				t.Errorf("the delegation that permits %s refused %s %s: %v", c.name, r.Kind, r.Name, err)
			}
		}
		for _, r := range c.refused {
			err := try(t, in, caller, r)
			want := `does not permit its scoped roles to change`
			if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), want) {
				t.Errorf("the delegation that permits %s gave %v for %s %s, want a refusal that says %q", c.name, err, r.Kind, r.Name, want)
			}
		}
	}
	// The refusal says what is permitted, and that nothing is
	err := try(t, in, scope.Caller{Network: "branch-a", Admin: true, Delegation: scope.Delegation{Network: "branch-a", Permissions: []string{scope.PermGroups, scope.PermUsers}}}, node)
	if err == nil || !strings.Contains(err.Error(), `Node "n": Network "branch-a" does not permit its scoped roles to change nodes, and it permits groups, users`) {
		t.Errorf("the refusal of a kind that the delegation leaves out is %v", err)
	}
	err = try(t, in, scope.Caller{Network: "branch-a", Admin: true}, user)
	if err == nil || !strings.Contains(err.Error(), "and it permits nothing") {
		t.Errorf("the refusal of a caller with no delegation is %v", err)
	}
}

// A User that holds an API role of any kind is never changed, deleted or made again by a scoped role.
func TestAScopedRoleLeavesTheUsersThatHoldARoleAlone(t *testing.T) {
	in := base(t)
	caller := admin("branch-a")
	caller.Holders = map[string]bool{"alice": true}
	err := try(t, in, caller, res(intent.KindUser, "alice", `{"scope": "branch-a", "displayName": "Alice", "groups": ["branch-a-staff"]}`))
	if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), `User "alice" holds an API role, and only the global roles change a User that does`) {
		t.Errorf("changing a User that holds a role gave %v", err)
	}
	// alice owns alice-laptop, which the intent keeps a User from being deleted over
	withoutDevice, derr := intent.Delete(in, intent.KindNode, "alice-laptop")
	if derr != nil {
		t.Fatal(derr)
	}
	err = tryDelete(t, withoutDevice, caller, intent.KindUser, "alice")
	if !errors.Is(err, scope.ErrOutOfScope) || !strings.Contains(err.Error(), `User "alice" holds an API role, and only the global roles delete a User that does`) {
		t.Errorf("deleting a User that holds a role gave %v", err)
	}
	// A User of the scope that holds none is changed
	if err := try(t, in, caller, res(intent.KindUser, "carol", `{"scope": "branch-a"}`)); err != nil {
		t.Errorf("making a User beside one that holds a role was refused: %v", err)
	}
}
