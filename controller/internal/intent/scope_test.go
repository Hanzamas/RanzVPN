package intent

import (
	"errors"
	"strings"
	"testing"
)

// scopeIntent is two Networks, branch-a and branch-b, in the VRF corp, and in the scope of branch-a a User, a
// Group, a Node that names the scope and a Node that is the device of the User, and a Policy; and in the scope
// of branch-b a User; the Group hq and the Node hub have none.
func scopeIntent(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "branch-a", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(KindNetwork, "branch-b", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`),
		res(KindGroup, "branch-a-staff", `{"scope": "branch-a"}`),
		res(KindGroup, "hq", `{}`),
		res(KindUser, "alice", `{"groups": ["branch-a-staff"], "scope": "branch-a"}`),
		res(KindUser, "bob", `{"scope": "branch-b"}`),
		res(KindNode, "a-server", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "scope": "branch-a"}`),
		res(KindNode, "alice-laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "alice"}`),
		res(KindNode, "hub", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(KindPolicy, "a-lan", `{"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"addresses": ["10.10.0.0/24"]}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// The scope of a resource is the Network that it names, a Network is in its own scope, and a Node that names
// none is in the scope of its owner.
func TestScopeOf(t *testing.T) {
	in := scopeIntent(t)
	for _, c := range []struct {
		kind, name string
		scope      string
		held       bool
	}{
		{KindNetwork, "branch-a", "branch-a", true},
		{KindNetwork, "nowhere", "", false},
		{KindUser, "alice", "branch-a", true},
		{KindUser, "bob", "branch-b", true},
		{KindGroup, "branch-a-staff", "branch-a", true},
		{KindGroup, "hq", "", true},
		{KindNode, "a-server", "branch-a", true},
		// The device of a User of a Network is in that Network, without a scope of its own
		{KindNode, "alice-laptop", "branch-a", true},
		{KindNode, "hub", "", true},
		{KindPolicy, "a-lan", "branch-a", true},
		{KindUser, "nobody", "", false},
		{KindVRF, "corp", "", false},
	} {
		if scope, held := in.ScopeOf(c.kind, c.name); scope != c.scope || held != c.held {
			t.Errorf("ScopeOf(%s, %s) is %q, %v, want %q, %v", c.kind, c.name, scope, held, c.scope, c.held)
		}
	}

	// A Node that names a scope is in it, whoever owns the Node
	next, err := Apply(in, doc(res(KindNode, "alice-laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "alice", "scope": "branch-b"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if scope, _ := next.ScopeOf(KindNode, "alice-laptop"); scope != "branch-b" {
		t.Errorf("the Node that names the scope branch-b is in the scope of %q", scope)
	}
}

// A scope that is no Network is refused for each kind that has one, and the refusal names the resource and the
// scope.
func TestAScopeIsANetwork(t *testing.T) {
	in := scopeIntent(t)
	for _, c := range []struct {
		name string
		res  Resource
		want string
	}{
		{"user", res(KindUser, "carol", `{"scope": "nowhere"}`), `User "carol": the scope "nowhere" is no Network`},
		{"group", res(KindGroup, "g", `{"scope": "nowhere"}`), `Group "g": the scope "nowhere" is no Network`},
		{"node", res(KindNode, "n", `{"publicKey": "`+key4+`", "vrfs": ["corp"], "scope": "nowhere"}`), `Node "n": the scope "nowhere" is no Network`},
		{"policy", res(KindPolicy, "p", `{"vrf": "corp", "scope": "nowhere", "action": "allow"}`), `Policy "p": the scope "nowhere" is no Network`},
	} {
		_, err := Apply(in, doc(c.res), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: applying a scope that is no Network gave %v, want %q", c.name, err, c.want)
		}
	}
	// A Network that is made with the resource is a Network of the intent
	if _, err := Apply(in, doc(
		res(KindNetwork, "branch-c", `{"vrf": "corp", "ipv4Pool": "10.30.0.0/24"}`),
		res(KindUser, "carol", `{"scope": "branch-c"}`),
	), nil); err != nil {
		t.Errorf("a User in the scope of a Network of the same apply was refused: %v", err)
	}
}

// A Network that is the scope of a resource cannot be deleted, and the refusal names the resources; one that is
// the scope of none can.
func TestANetworkThatIsAScopeCannotBeDeleted(t *testing.T) {
	in := scopeIntent(t)
	_, err := Delete(in, KindNetwork, "branch-a")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleting the scope of five resources gave %v, want ErrInvalid", err)
	}
	for _, want := range []string{`Network "branch-a" is the scope of`, `User "alice"`, `Group "branch-a-staff"`, `Node "a-server"`, `Policy "a-lan"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not name %q", err, want)
		}
	}
	// The device of alice is in the scope through its owner, and no resource names the scope of it
	if strings.Contains(err.Error(), "alice-laptop") {
		t.Errorf("the refusal %q names the device of alice, which has no scope of its own", err)
	}

	// With the resources gone the Network goes
	next := in
	for _, d := range []struct{ kind, name string }{{KindPolicy, "a-lan"}, {KindNode, "a-server"}, {KindNode, "alice-laptop"}, {KindUser, "alice"}, {KindGroup, "branch-a-staff"}} {
		if next, err = Delete(next, d.kind, d.name); err != nil {
			t.Fatalf("deleting %s %s: %v", d.kind, d.name, err)
		}
	}
	if _, err := Delete(next, KindNetwork, "branch-a"); err != nil {
		t.Errorf("deleting a Network that is the scope of none gave %v", err)
	}
}

// A document that holds a scope round-trips through the stored form of the intent: the resources that Apply
// completed carry the scope, and FromResources reads it back.
func TestTheScopeSurvivesTheStoredForm(t *testing.T) {
	in := scopeIntent(t)
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ kind, name, scope string }{
		{KindUser, "alice", "branch-a"}, {KindGroup, "branch-a-staff", "branch-a"}, {KindNode, "a-server", "branch-a"}, {KindPolicy, "a-lan", "branch-a"},
	} {
		if scope, _ := back.ScopeOf(c.kind, c.name); scope != c.scope {
			t.Errorf("%s %s read back with the scope %q, want %q", c.kind, c.name, scope, c.scope)
		}
	}
	// The scope is copied with the intent, not shared
	clone := in.Clone()
	u := clone.Users["alice"]
	u.Scope = "branch-b"
	clone.Users["alice"] = u
	if in.Users["alice"].Scope != "branch-a" {
		t.Error("changing the scope in a clone changed the intent that it was cloned from")
	}
}
