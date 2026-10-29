package intent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// keyLifeIntent is three VRFs: corp has a Network that holds new Nodes for approval and lives its keys 30 days,
// and another that does the same for 365 days; lab has one that admits at once and lives its keys 365 days; bare
// has no Network. Four Nodes are in them: n1 in corp, n2 in lab, n3 in both, and n4 in bare, marked nonExpiring.
func keyLifeIntent(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd00:20::/48"}`),
		res(KindVRF, "bare", `{"id": 30, "ula": "fd00:30::/48"}`),
		res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "approval": "manual", "keyLifetimeDays": 30}`),
		res(KindNetwork, "corp-dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "approval": "manual", "keyLifetimeDays": 365}`),
		res(KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.30.0.0/24", "approval": "auto", "keyLifetimeDays": 365}`),
		res(KindNode, "n1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "n2", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
		res(KindNode, "n3", `{"publicKey": "`+key3+`", "vrfs": ["corp", "lab"]}`),
		res(KindNode, "n4", `{"publicKey": "`+key4+`", "vrfs": ["bare"], "nonExpiring": true}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// A Node is held for approval by the first Network, in name order, of its VRFs whose mode is manual. A Network
// that admits at once, a Node that no such Network holds and a Node that the intent does not have are held by none.
func TestApprovalNeeded(t *testing.T) {
	in := keyLifeIntent(t)
	for _, c := range []struct {
		node    string
		network string
		held    bool
	}{
		{"n1", "corp-dmz", true},
		{"n2", "", false},
		{"n3", "corp-dmz", true},
		{"n4", "", false},
		{"nobody", "", false},
	} {
		if network, held := in.ApprovalNeeded(c.node); network != c.network || held != c.held {
			t.Errorf("ApprovalNeeded(%s) is %q, %v, want %q, %v", c.node, network, held, c.network, c.held)
		}
	}
}

// The key of a Node lives for the shortest key lifetime of the Networks of its VRFs. A Network that sets none
// counts the default, so it shortens a longer one beside it; a Node of no Network gets the default.
func TestKeyLifetime(t *testing.T) {
	const day = 24 * time.Hour
	in := keyLifeIntent(t)
	for _, c := range []struct {
		node string
		want time.Duration
	}{
		{"n1", 30 * day},
		{"n2", 365 * day},
		{"n3", 30 * day},
		{"n4", DefaultKeyLifetimeDays * day},
		{"nobody", DefaultKeyLifetimeDays * day},
	} {
		if got := in.KeyLifetime(c.node); got != c.want {
			t.Errorf("KeyLifetime(%s) is %v, want %v", c.node, got, c.want)
		}
	}

	mixed, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`),
		res(KindNetwork, "long", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "keyLifetimeDays": 365}`),
		res(KindNetwork, "unset", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`),
		res(KindNode, "x", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := mixed.KeyLifetime("x"); got != DefaultKeyLifetimeDays*day {
		t.Errorf("KeyLifetime(x) is %v beside a Network that sets none, want the default of %d days", got, DefaultKeyLifetimeDays)
	}
	alone, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`),
		res(KindNetwork, "long", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "keyLifetimeDays": 365}`),
		res(KindNode, "x", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := alone.KeyLifetime("x"); got != 365*day {
		t.Errorf("KeyLifetime(x) is %v in a Network of 365 days alone, want 365 days: a Network may live keys longer than the default", got)
	}
}

// The approval mode is auto or manual, and a key lifetime is at most MaxKeyLifetimeDays; a field that no Network has
// is refused as any other, and the modes and the limit themselves are accepted.
func TestKeyLifeRejects(t *testing.T) {
	corp := res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`)
	for _, c := range []struct{ spec, want string }{
		{`{"vrf": "corp", "approval": "sometimes"}`, `Network "n": the approval must be auto or manual, not "sometimes"`},
		{`{"vrf": "corp", "approval": "Manual"}`, `Network "n": the approval must be auto or manual, not "Manual"`},
		{`{"vrf": "corp", "keyLifetimeDays": 3651}`, `Network "n": keyLifetimeDays 3651 is more than 3650`},
		{`{"vrf": "corp", "keyLifetime": 30}`, `unknown field "keyLifetime"`},
	} {
		if _, err := Apply(New(), doc(corp, res(KindNetwork, "n", c.spec)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.spec, err, c.want)
		}
	}
	for _, spec := range []string{
		`{"vrf": "corp"}`,
		`{"vrf": "corp", "approval": "auto"}`,
		`{"vrf": "corp", "approval": "manual", "keyLifetimeDays": 3650}`,
		`{"vrf": "corp", "keyLifetimeDays": 1}`,
	} {
		if _, err := Apply(New(), doc(corp, res(KindNetwork, "n", spec)), nil); err != nil {
			t.Errorf("%s: %v, want it accepted", spec, err)
		}
	}
}

// The mark nonExpiring is for a Node that has no owner (SDN-56-R1): the key of a device of a User lives by the login of its
// User, so the mark on such a Node is refused, in an apply and in an import, with a message that says so and names the
// Node and the User. A Node that has no owner takes the mark, and so does a Node of a User whose mark is left out.
func TestNonExpiringIsForANodeThatHasNoOwner(t *testing.T) {
	corp := res(KindVRF, "corp", `{"id": 10, "ula": "fd00:10::/48"}`)
	alice := res(KindUser, "alice", `{}`)
	want := `Node "n": nonExpiring is for a Node that has no owner: the key of a device of User "alice" lives by the login of its User`
	device := res(KindNode, "n", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "owner": "alice", "nonExpiring": true}`)

	if _, err := Apply(New(), doc(corp, alice, device), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("an apply of a device of alice marked nonExpiring gave %v, want an error with %q", err, want)
	}
	if _, err := Replace(New(), doc(corp, alice, device), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("an import of a device of alice marked nonExpiring gave %v, want an error with %q", err, want)
	}
	// Every Node that breaks the rule is named, and the others are not
	both := doc(corp, alice,
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "owner": "alice", "nonExpiring": true}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "alice", "nonExpiring": true}`),
		res(KindNode, "files", `{"publicKey": "`+key3+`", "vrfs": ["corp"], "nonExpiring": true}`))
	if _, err := Apply(New(), both, nil); err == nil || !strings.Contains(err.Error(), `Node "a": nonExpiring`) || !strings.Contains(err.Error(), `Node "b": nonExpiring`) ||
		strings.Contains(err.Error(), `Node "files"`) {
		t.Errorf("an apply of two devices and a server marked nonExpiring gave %v, want the two devices refused and the server not named", err)
	}

	// A server takes the mark, a device that is not marked is a device, and a Node that gets an owner while it is marked is refused
	in, err := Apply(New(), doc(corp, alice,
		res(KindNode, "files", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "nonExpiring": true}`),
		res(KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "alice"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Nodes["files"].NonExpiring || in.Nodes["laptop"].NonExpiring {
		t.Errorf("the nodes are %+v, want only files marked nonExpiring", in.Nodes)
	}
	if _, err := Apply(in, doc(res(KindNode, "files", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "nonExpiring": true, "owner": "alice"}`)), nil); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), `Node "files": nonExpiring is for a Node that has no owner`) {
		t.Errorf("giving the server files an owner while it is marked gave %v, want it refused", err)
	}
	// The stored intent is read back as it is: no check is made of the resources that a store holds
	stored := device.Spec
	if _, err := FromResources([]Resource{{Kind: KindNode, Name: "n", Spec: stored}}); err != nil {
		t.Errorf("reading back a stored device that is marked nonExpiring gave %v, want it read as it was written", err)
	}
}

// The approval mode, the key lifetime and the mark nonExpiring are part of the intent as it is stored and read back,
// and a change of one of them is a change of its resource.
func TestKeyLifeIsPartOfTheIntent(t *testing.T) {
	in := keyLifeIntent(t)
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Networks, in.Networks) || !reflect.DeepEqual(back.Nodes, in.Nodes) {
		t.Errorf("the intent read back from its resources differs:\n%+v\n%+v", back, in)
	}
	if n := back.Networks["corp-lan"]; n.Approval != ApprovalManual || n.KeyLifetimeDays != 30 {
		t.Errorf("corp-lan is %+v, want the approval manual and 30 days", n)
	}
	if !back.Nodes["n4"].NonExpiring || back.Nodes["n1"].NonExpiring {
		t.Errorf("the nodes read back are %+v, want only n4 marked nonExpiring", back.Nodes)
	}

	next, err := Apply(in, doc(res(KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "approval": "auto", "keyLifetimeDays": 30}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	put, gone := Changed(in, next)
	if len(put) != 1 || put[0].Kind != KindNetwork || put[0].Name != "corp-lan" || len(gone) != 0 {
		t.Errorf("turning the approval of corp-lan to auto changed %+v and removed %+v, want that Network alone", put, gone)
	}
	if _, held := next.ApprovalNeeded("n1"); !held {
		t.Error("n1 is held by no Network after corp-lan admits at once, but corp-dmz still holds it")
	}
}
