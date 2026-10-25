package intent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// userJSON is a document with two Groups, two Users and the devices of both, for the tests and the
// fuzz test to start from: alice has two Nodes and a maximum of two, bob has one Node that carries the
// tag of one of his groups of its own too.
const userJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Group", "name": "staff", "spec": {"displayName": "Staff"}},
  {"kind": "Group", "name": "contractors", "spec": {}},
  {"kind": "User", "name": "alice", "spec": {"displayName": "Alice", "groups": ["staff"], "expires": "2031-01-02T03:04:05+07:00", "maxDevices": 2, "noSavedPassword": true}},
  {"kind": "User", "name": "bob", "spec": {"groups": ["staff", "contractors"], "mayChangePassword": false}},
  {"kind": "Node", "name": "alice-laptop", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "owner": "alice", "tags": ["laptop"]}},
  {"kind": "Node", "name": "alice-phone", "spec": {"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"], "owner": "alice"}},
  {"kind": "Node", "name": "bob-laptop", "spec": {"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["corp"], "owner": "bob", "tags": ["staff"]}}
]}`

// userIntent applies userJSON to an empty intent.
func userIntent(t *testing.T) Intent {
	t.Helper()
	d, err := ParseDocument([]byte(userJSON))
	if err != nil {
		t.Fatal(err)
	}
	in, err := Apply(New(), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// userBase is an intent with a VRF, the Groups staff and contractors and the User alice, for the
// tests that apply more.
func userBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindGroup, "staff", `{}`),
		res(KindGroup, "contractors", `{}`),
		res(KindUser, "alice", `{"groups": ["staff"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// nameList returns n names g01, g02, and so on, and the JSON list of them.
func nameList(n int) ([]string, string) {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("g%02d", i+1)
	}
	return names, `["` + strings.Join(names, `", "`) + `"]`
}

// A User and a Group keep what they declare, in one form: the groups ordered, the expiry in UTC, the
// choice to change the password explicit. The Users belong to their Groups, and each Node has the
// devices and the tags of its owner.
func TestApplyUsersAndGroups(t *testing.T) {
	in := userIntent(t)

	alice := in.Users["alice"]
	if alice.DisplayName != "Alice" || !slices.Equal(alice.Groups, []string{"staff"}) || alice.MaxDevices != 2 || !alice.NoSavedPassword {
		t.Errorf("alice is %+v", alice)
	}
	if want := time.Date(2031, time.January, 1, 20, 4, 5, 0, time.UTC); !alice.Expires.Equal(want) {
		t.Errorf("alice expires at %v, want %v", alice.Expires, want)
	}
	if alice.MayChangePassword == nil || !*alice.MayChangePassword || !alice.CanChangePassword() {
		t.Errorf("alice leaves out mayChangePassword, so the controller makes it true: %v", alice.MayChangePassword)
	}
	bob := in.Users["bob"]
	if !slices.Equal(bob.Groups, []string{"contractors", "staff"}) {
		t.Errorf("bob belongs to %v, want his groups ordered", bob.Groups)
	}
	if bob.MayChangePassword == nil || *bob.MayChangePassword || bob.CanChangePassword() {
		t.Errorf("bob may not change his password: %v", bob.MayChangePassword)
	}
	if in.Groups["staff"].DisplayName != "Staff" || len(in.Groups) != 2 {
		t.Errorf("the groups are %+v", in.Groups)
	}

	for user, want := range map[string]string{
		"alice":  `Node "alice-laptop", Node "alice-phone"`,
		"bob":    `Node "bob-laptop"`,
		"nobody": ``,
		"":       ``,
	} {
		if got := deviceList(in.DevicesOf(user)); got != want {
			t.Errorf("the devices of %q are %q, want %q", user, got, want)
		}
	}
	for node, want := range map[string][]string{
		"alice-laptop": {"laptop", "staff"},
		"alice-phone":  {"staff"},
		"bob-laptop":   {"contractors", "staff"},
		"nobody":       nil,
	} {
		if got := in.NodeTags(node); !slices.Equal(got, want) {
			t.Errorf("the tags of %s are %v, want %v", node, got, want)
		}
	}
	for group, want := range map[string][]string{"staff": {"alice", "bob"}, "contractors": {"bob"}, "nobody": nil} {
		if got := in.Members(group); !slices.Equal(got, want) {
			t.Errorf("the members of %s are %v, want %v", group, got, want)
		}
	}

	// The Groups and the Users come after the other resources, the Groups first
	var kinds []string
	for _, r := range in.Resources() {
		kinds = append(kinds, r.Kind)
	}
	if got, want := strings.Join(kinds, " "), "VRF Node Node Node Group Group User User"; got != want {
		t.Errorf("the resources are %s, want %s", got, want)
	}
	if kindOrder(KindGroup) <= kindOrder(KindDNSRecord) || kindOrder(KindUser) <= kindOrder(KindGroup) {
		t.Error("a Group and a User are not ordered after the DnsRecords, the Group first")
	}
}

// The stored form of Users and Groups reads back as the same intent, the time and the choice not to
// change the password included, and the intent that it was made from does not share a slice or a
// pointer with its copy.
func TestUsersRoundTripAndClone(t *testing.T) {
	in := userIntent(t)
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent read back differs: put %+v, gone %+v", put, gone)
	}
	if !back.Users["alice"].Expires.Equal(in.Users["alice"].Expires) || back.Users["bob"].CanChangePassword() {
		t.Errorf("the Users read back are %+v", back.Users)
	}

	clone := in.Clone()
	clone.Users["bob"].Groups[0] = "changed"
	*clone.Users["bob"].MayChangePassword = true
	clone.Groups["extra"] = Group{}
	if in.Users["bob"].Groups[0] != "contractors" || in.Users["bob"].CanChangePassword() || len(in.Groups) != 2 {
		t.Errorf("a change of the copy changed the intent: %+v %+v", in.Users["bob"], in.Groups)
	}
}

// An expiry is written in UTC to the second, so that the same instant is the same text.
func TestUserExpiryIsOneForm(t *testing.T) {
	a, err := Apply(New(), doc(res(KindUser, "u", `{"expires": "2031-01-02T03:04:05.678+07:00"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Apply(New(), doc(res(KindUser, "u", `{"expires": "2031-01-01T20:04:05Z"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(a, b); len(put) != 0 || len(gone) != 0 {
		t.Errorf("one instant in two spellings is two resources: put %+v, gone %+v", put, gone)
	}
}

// A User has expired from its expiry on, and never without one. It may change its password unless it
// says it may not.
func TestUserExpiredAtAndPasswordChoice(t *testing.T) {
	expires := time.Date(2030, time.June, 1, 12, 0, 0, 0, time.UTC)
	u := User{Expires: expires}
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{expires.Add(-time.Second), false},
		{expires, true},
		{expires.Add(time.Hour), true},
	} {
		if got := u.ExpiredAt(c.at); got != c.want {
			t.Errorf("a user that expires at %v has expired at %v: %v, want %v", expires, c.at, got, c.want)
		}
	}
	if (User{}).ExpiredAt(expires.AddDate(100, 0, 0)) {
		t.Error("a user with no expiry has expired")
	}
	no, yes := false, true
	for _, c := range []struct {
		u    User
		want bool
	}{{User{}, true}, {User{MayChangePassword: &yes}, true}, {User{MayChangePassword: &no}, false}} {
		if got := c.u.CanChangePassword(); got != c.want {
			t.Errorf("%+v may change its password: %v, want %v", c.u, got, c.want)
		}
	}
}

func TestApplyRejectsUsers(t *testing.T) {
	base := userBase(t)
	groups, groupList := nameList(17)
	var seventeen []Resource
	for _, g := range groups {
		seventeen = append(seventeen, res(KindGroup, g, `{}`))
	}
	_, tagList := nameList(9)

	refuses(t, base, `User "u": Group "ghost" does not exist`, res(KindUser, "u", `{"groups": ["ghost"]}`))
	refuses(t, base, `User "u": Group "staff" is listed twice`, res(KindUser, "u", `{"groups": ["staff", "staff"]}`))
	refuses(t, base, `User "u": displayName: it is longer than 128 characters`, res(KindUser, "u", `{"displayName": "`+strings.Repeat("x", 129)+`"}`))
	refuses(t, base, `Group "g": displayName: it is longer than 128 characters`, res(KindGroup, "g", `{"displayName": "`+strings.Repeat("é", 129)+`"}`))
	refuses(t, base, `User "u": displayName: it holds a control character, U+0007`, res(KindUser, "u", `{"displayName": "a\u0007b"}`))
	refuses(t, base, `User "u": expires is outside the years 1 to 9999 (UTC)`, res(KindUser, "u", `{"expires": "9999-12-31T23:59:59-05:00"}`))
	refuses(t, base, `User "u": spec:`, res(KindUser, "u", `{"expires": "tomorrow"}`))
	refuses(t, base, `User "u": spec: json: unknown field "password"`, res(KindUser, "u", `{"password": "hunter2hunter2"}`))
	refuses(t, base, `User "Bad_Name": the name must be`, res(KindUser, "Bad_Name", `{}`))
	refuses(t, base, `Group "-g": the name must be`, res(KindGroup, "-g", `{}`))
	refuses(t, base, `Node "n": the owner User "ghost" does not exist`,
		res(KindNode, "n", `{"publicKey": "`+key1+`", "owner": "ghost"}`))
	refuses(t, base, `User "alice": 2 devices (Node "a", Node "b"), and the maximum is 1`,
		res(KindUser, "alice", `{"groups": ["staff"], "maxDevices": 1}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "owner": "alice"}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "owner": "alice"}`))
	refuses(t, base, `User "u": 17 groups, and a device carries at most 16 tags`,
		append(seventeen, res(KindUser, "u", `{"groups": `+groupList+`}`))...)
	refuses(t, base, `Node "n": 18 tags, its own and those of the Groups of its owner, and a node carries at most 16`,
		append(seventeen[:9:9], res(KindUser, "u", `{"groups": `+tagList+`}`),
			res(KindNode, "n", `{"publicKey": "`+key1+`", "owner": "u", "tags": ["t01", "t02", "t03", "t04", "t05", "t06", "t07", "t08", "t09"]}`))...)

	// A failed apply changes nothing
	if len(base.Users) != 1 || len(base.Groups) != 2 || len(base.Nodes) != 0 {
		t.Errorf("a refused apply changed the intent: %+v %+v %+v", base.Users, base.Groups, base.Nodes)
	}
}

// The devices of a User are the Nodes that name it as their owner, and the intent that holds more
// than its maximum is refused, whether a Node is added or the maximum is lowered. A maximum of 0, or
// none, is no limit.
func TestMaxDevices(t *testing.T) {
	in, err := Apply(userBase(t), doc(
		res(KindUser, "alice", `{"groups": ["staff"], "maxDevices": 2}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "owner": "alice"}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "owner": "alice"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	refuses(t, in, `User "alice": 3 devices (Node "a", Node "b", Node "c"), and the maximum is 2`,
		res(KindNode, "c", `{"publicKey": "`+key3+`", "owner": "alice"}`))
	refuses(t, in, `User "alice": 2 devices (Node "a", Node "b"), and the maximum is 1`,
		res(KindUser, "alice", `{"groups": ["staff"], "maxDevices": 1}`))

	// A Node of another owner, or of none, is no device of alice
	if _, err := Apply(in, doc(res(KindNode, "c", `{"publicKey": "`+key3+`"}`)), nil); err != nil {
		t.Errorf("a Node with no owner is a device of alice: %v", err)
	}
	// A Node that moves to another owner leaves alice a place
	moved, err := Apply(in, doc(res(KindUser, "bob", `{}`), res(KindNode, "b", `{"publicKey": "`+key2+`", "owner": "bob"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := deviceList(moved.DevicesOf("alice")); got != `Node "a"` {
		t.Errorf("the devices of alice after b moved are %q, want a alone", got)
	}
	if _, err := Apply(moved, doc(res(KindNode, "c", `{"publicKey": "`+key3+`", "owner": "alice"}`)), nil); err != nil {
		t.Errorf("a device that fits under the maximum was refused: %v", err)
	}
	// A larger maximum, or none, takes the third
	for _, spec := range []string{`{"groups": ["staff"], "maxDevices": 3}`, `{"groups": ["staff"]}`, `{"groups": ["staff"], "maxDevices": 0}`} {
		if _, err := Apply(in, doc(res(KindUser, "alice", spec), res(KindNode, "c", `{"publicKey": "`+key3+`", "owner": "alice"}`)), nil); err != nil {
			t.Errorf("a third device under %s was refused: %v", spec, err)
		}
	}
}

// A Group that a User belongs to and a User that owns a Node cannot be deleted, and the others can,
// with the changes of an apply.
func TestDeleteUsersAndGroups(t *testing.T) {
	in := userIntent(t)
	for _, c := range []struct {
		kind, name, want string
	}{
		{KindGroup, "staff", `Group "staff" is used by User "alice", User "bob"`},
		{KindGroup, "contractors", `Group "contractors" is used by User "bob"`},
		{KindUser, "alice", `User "alice" is the owner of Node "alice-laptop", Node "alice-phone"`},
		{KindUser, "bob", `User "bob" is the owner of Node "bob-laptop"`},
	} {
		if _, err := Delete(in, c.kind, c.name); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("deleting %s %q: %v, want an error with %q", c.kind, c.name, err, c.want)
		}
	}
	for _, c := range [][2]string{{KindGroup, "ghost"}, {KindUser, "ghost"}} {
		if _, err := Delete(in, c[0], c[1]); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting %s %q that does not exist: %v", c[0], c[1], err)
		}
	}

	next := in
	for _, step := range [][2]string{{KindNode, "alice-laptop"}, {KindNode, "alice-phone"}, {KindUser, "alice"}, {KindNode, "bob-laptop"}, {KindUser, "bob"},
		{KindGroup, "contractors"}, {KindGroup, "staff"}} {
		var err error
		if next, err = Delete(next, step[0], step[1]); err != nil {
			t.Fatalf("deleting %s %q: %v", step[0], step[1], err)
		}
	}
	if len(next.Users) != 0 || len(next.Groups) != 0 || len(next.Nodes) != 0 {
		t.Errorf("what is left is %+v %+v %+v", next.Users, next.Groups, next.Nodes)
	}
	if _, ok := in.Users["alice"]; !ok || len(in.Groups) != 2 {
		t.Error("Delete changed the intent it was given")
	}
	put, gone := Changed(in, next)
	var names []string
	for _, r := range gone {
		names = append(names, r.Kind+"/"+r.Name)
	}
	if len(put) != 0 || !slices.Contains(names, "User/alice") || !slices.Contains(names, "Group/staff") {
		t.Errorf("the change of the deletes is put %+v, gone %v", put, names)
	}
}

// The tags of a Node that has no owner are its own, ordered; a Mirror that selects a tag selects the
// devices of the members of the Group of that name.
func TestGroupTagsReachTheMirrors(t *testing.T) {
	in, err := Apply(userBase(t), doc(
		res(KindNode, "plain", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["b", "a"]}`),
		res(KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "alice"}`),
		res(KindNode, "server", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(KindMirror, "staff-copy", `{"tag": "staff", "sensor": "192.0.2.50"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.NodeTags("plain"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("the tags of plain are %v, want [a b]", got)
	}
	for node, want := range map[string][]string{"laptop": {"staff-copy"}, "plain": nil, "server": nil} {
		if got := in.MirrorsOf(node); !slices.Equal(got, want) {
			t.Errorf("the Mirrors of %s are %v, want %v", node, got, want)
		}
	}
}

// An import that leaves out a User or a Group deletes it, and one that keeps a User whose Group it
// leaves out is refused, as an apply is.
func TestReplaceDropsUsersAndGroups(t *testing.T) {
	in := userIntent(t)
	next, err := Replace(in, doc(res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Users) != 0 || len(next.Groups) != 0 || len(next.Nodes) != 0 {
		t.Errorf("the import of a VRF alone left %+v %+v %+v", next.Users, next.Groups, next.Nodes)
	}
	kept, err := Replace(in, doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindGroup, "staff", `{}`),
		res(KindUser, "alice", `{"groups": ["staff"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept.Users) != 1 || len(kept.Groups) != 1 || len(kept.Nodes) != 0 {
		t.Errorf("the import of alice and staff left %+v %+v %+v", kept.Users, kept.Groups, kept.Nodes)
	}
	if _, err := Replace(in, doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindUser, "alice", `{"groups": ["staff"]}`),
	), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `User "alice": Group "staff" does not exist`) {
		t.Errorf("the import of a User without its Group: %v", err)
	}
	if len(in.Users) != 2 {
		t.Error("Replace changed the intent it was given")
	}
}
