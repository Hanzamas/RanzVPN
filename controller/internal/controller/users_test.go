package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/password"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// Users and groups as intent resources (SDN-31, #225): the tests apply them through the HTTP API, as
// `ranz` does, and check what the simulated nodes receive and what the controller answers.

// usersDoc returns the intent document of the resources rs, each the JSON of one resource.
func usersDoc(t *testing.T, rs ...string) intent.Document {
	t.Helper()
	doc, err := intent.ParseDocument([]byte(`{"resources": [` + strings.Join(rs, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// userNode returns the JSON of the Node name, which is a device of owner, with the key of nodeKey(i).
func userNode(name, owner string, i int) string {
	return `{"kind": "Node", "name": "` + name + `", "spec": {"publicKey": "` + base64.StdEncoding.EncodeToString(nodeKey(i).Public()) + `", "owner": "` + owner + `"}}`
}

// userHolds is what a simulated node is expected to hold (userHeld): the tags of the node itself,
// the tags of each of its peers as fmt prints the map, and the names of its rules.
type userHolds struct {
	node  *sim
	self  []string
	peers string
	rules []string
}

// userHeld returns what the state of a simulated node holds that matters here: the tags of the node
// itself, the tags of each of its peers, and the names of its rules.
func userHeld(s *sim) (self []string, peers map[string][]string, rules []string) {
	_, state := s.State()
	peers = map[string][]string{}
	for _, o := range state.Objects() {
		switch {
		case o.GetNode() != nil:
			self = o.GetNode().GetTags()
		case o.GetPeer() != nil:
			peers[o.GetPeer().GetName()] = o.GetPeer().GetTags()
		case o.GetRule() != nil:
			rules = append(rules, o.GetRule().GetName())
		}
	}
	return self, peers, rules
}

// TestGroupTagsReachTheMembers is the second criterion of SDN-31 (#225): a rule on a group tag applies
// to the members of the group. In users.json alice, of the group staff, owns alice-laptop, bob, a
// contractor, owns bob-laptop, and files has the tag db; the rule staff-to-files lets staff reach db.
// The nodes receive the group as a tag of the laptop, in the Peer object that each other node holds of
// it, and the rule goes to the laptop of alice and to files, and not to the laptop of bob. A change of
// the group of alice moves the tag and the rule with her devices, as a delta of the nodes that it
// concerns.
func TestGroupTagsReachTheMembers(t *testing.T) {
	h := newHarness(t)
	h.apply("users.json")
	alice := h.sim("alice-laptop", keyBranch1)
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	sims := []*sim{alice, bob, files}
	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}

	check := func(when string, want []userHolds) {
		t.Helper()
		for _, c := range want {
			self, peers, rules := userHeld(c.node)
			if !slices.Equal(self, c.self) || fmt.Sprint(peers) != c.peers || !slices.Equal(rules, c.rules) {
				t.Errorf("%s: %s holds the tags %v, the peers %v and the rules %v, want %v, %s and %v", when, c.node.name, self, peers, rules, c.self, c.peers, c.rules)
			}
		}
	}
	check("generation 1", []userHolds{
		{alice, []string{"staff"}, "map[bob-laptop:[contractors] files:[db]]", []string{"staff-to-files"}},
		{bob, []string{"contractors"}, "map[alice-laptop:[staff] files:[db]]", nil},
		{files, []string{"db"}, "map[alice-laptop:[staff] bob-laptop:[contractors]]", []string{"staff-to-files"}},
	})

	// Alice leaves staff for contractors: her laptop loses the tag and the rule, each peer sees the new
	// tag, and files, which the rule names at its to end, keeps the rule
	res, err := h.api.PutUser(context.Background(), "alice", intent.User{DisplayName: "Alice", Groups: []string{"contractors"}, MaxDevices: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "alice-laptop", Generation: 2}, {Name: "bob-laptop", Generation: 2}, {Name: "files", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the change of the group of alice changed %+v, want %+v", res.Nodes, want)
	}
	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 2, true)
		h.checkState(s)
	}
	check("generation 2", []userHolds{
		{alice, []string{"contractors"}, "map[bob-laptop:[contractors] files:[db]]", nil},
		{bob, []string{"contractors"}, "map[alice-laptop:[contractors] files:[db]]", nil},
		{files, []string{"db"}, "map[alice-laptop:[contractors] bob-laptop:[contractors]]", []string{"staff-to-files"}},
	})
}

// TestUsersAndGroupsThroughTheAPI is the first criterion of SDN-31 (#225): users and groups are
// created, listed and changed through the API, and deleted; each change is a revision of the intent;
// what cannot be deleted or made is refused with a message; and each call needs the role of the same
// calls on the other resources, a viewer to read and an operator to change.
func TestUsersAndGroupsThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	staff, err := h.api.PutGroup(ctx, "staff", intent.Group{DisplayName: "Staff"})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2031, time.January, 2, 3, 4, 5, 0, time.UTC)
	made, err := h.api.PutUser(ctx, "alice", intent.User{DisplayName: "Alice", Groups: []string{"staff"}, Expires: expires, MaxDevices: 2, NoSavedPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	if made.Revision != staff.Revision+1 {
		t.Errorf("the group is revision %d and the user revision %d, want the next one", staff.Revision, made.Revision)
	}

	users, err := h.api.Users(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("the users are %+v (%v), want alice alone", users, err)
	}
	if u := users[0]; u.Name != "alice" || u.DisplayName != "Alice" || !slices.Equal(u.Groups, []string{"staff"}) || !u.Expires.Equal(expires) || u.MaxDevices != 2 ||
		!u.NoSavedPassword || !u.CanChangePassword() || u.HasPassword || u.Expired || u.Devices == nil || len(u.Devices) != 0 {
		t.Errorf("alice is listed as %+v", u)
	}
	groups, err := h.api.Groups(ctx)
	if err != nil || len(groups) != 1 || groups[0].Name != "staff" || groups[0].DisplayName != "Staff" || !slices.Equal(groups[0].Members, []string{"alice"}) {
		t.Errorf("the groups are %+v (%v), want staff with the member alice", groups, err)
	}

	// A change replaces the user, the expiry that it leaves out included, and gives a password
	if _, err := h.api.PutUser(ctx, "alice", intent.User{DisplayName: "Alice A.", Groups: []string{"staff"}, MaxDevices: 3}); err != nil {
		t.Fatal(err)
	}
	set, err := h.api.SetUserPassword(ctx, "alice", "a good password")
	if err != nil || set.User != "alice" || !set.Set {
		t.Fatalf("setting the password of alice: %+v (%v)", set, err)
	}
	if users, err = h.api.Users(ctx); err != nil || len(users) != 1 {
		t.Fatalf("the users are %+v (%v)", users, err)
	}
	if u := users[0]; u.DisplayName != "Alice A." || u.MaxDevices != 3 || !u.Expires.IsZero() || u.NoSavedPassword || !u.HasPassword {
		t.Errorf("alice after the change is %+v, want the new display name and maximum, no expiry and a password", u)
	}

	// What cannot be done is refused with the reason
	if _, err := h.api.DeleteGroup(ctx, "staff"); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `Group "staff" is used by User "alice"`) {
		t.Errorf("deleting the group of alice: %v, want 400 Bad Request that names her", err)
	}
	if _, err := h.api.PutUser(ctx, "carol", intent.User{Groups: []string{"ghost"}}); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `Group "ghost" does not exist`) {
		t.Errorf("a user of a group that does not exist: %v, want 400 Bad Request", err)
	}
	if _, err := h.api.SetUserPassword(ctx, "nobody", "a good password"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a password for a user that does not exist: %v, want 404 Not Found", err)
	}
	if _, err := h.api.DeleteUser(ctx, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("deleting a user that does not exist: %v, want 404 Not Found", err)
	}
	if _, err := h.api.Apply(ctx, usersDoc(t, userNode("alice-laptop", "alice", 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.DeleteUser(ctx, "alice"); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `User "alice" is the owner of Node "alice-laptop"`) {
		t.Errorf("deleting the owner of a device: %v, want 400 Bad Request that names the device", err)
	}
	if users, err = h.api.Users(ctx); err != nil || len(users) != 1 || len(users[0].Devices) != 1 || users[0].Devices[0] != (intent.DeviceRef{Kind: "Node", Name: "alice-laptop"}) {
		t.Errorf("the devices of alice are %+v (%v), want her laptop", users, err)
	}

	// The roles: a viewer reads and cannot change, no token reads nothing, an operator changes
	viewerToken, err := h.api.CreateToken(ctx, "viewer-1", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	operatorToken, err := h.api.CreateToken(ctx, "operator-1", rbac.Operator)
	if err != nil {
		t.Fatal(err)
	}
	viewer, operator, nobody := h.client(viewerToken.Secret), h.client(operatorToken.Secret), h.client("")
	if _, err := viewer.Users(ctx); err != nil {
		t.Errorf("a viewer lists the users: %v", err)
	}
	if _, err := viewer.Groups(ctx); err != nil {
		t.Errorf("a viewer lists the groups: %v", err)
	}
	if _, err := viewer.PutUser(ctx, "dave", intent.User{}); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer makes a user: %v, want 403 Forbidden", err)
	}
	if _, err := viewer.SetUserPassword(ctx, "alice", "another password"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer sets a password: %v, want 403 Forbidden", err)
	}
	if _, err := viewer.DeleteGroup(ctx, "staff"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer deletes a group: %v, want 403 Forbidden", err)
	}
	if _, err := nobody.Users(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("a call with no token lists the users: %v, want 401 Unauthorized", err)
	}
	if _, err := operator.PutGroup(ctx, "ops", intent.Group{}); err != nil {
		t.Errorf("an operator makes a group: %v", err)
	}
	if _, err := operator.PutUser(ctx, "dave", intent.User{Groups: []string{"ops"}}); err != nil {
		t.Errorf("an operator makes a user: %v", err)
	}
	if _, err := operator.SetUserPassword(ctx, "dave", "dave's password"); err != nil {
		t.Errorf("an operator sets a password: %v", err)
	}
	if _, err := operator.DeleteUser(ctx, "dave"); err != nil {
		t.Errorf("an operator deletes a user: %v", err)
	}
	if _, err := operator.DeleteGroup(ctx, "ops"); err != nil {
		t.Errorf("an operator deletes a group: %v", err)
	}
}

// TestExpiredUserCannotAuthenticate is the first half of the third criterion of SDN-31 (#225): a user
// whose expiry has passed cannot authenticate, with the right password and every time, and a user
// whose expiry moves later can again. A wrong password, a name that no user has and a user that has
// no password are one refusal, which tells nothing of which names exist.
func TestExpiredUserCannotAuthenticate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.api.Apply(ctx, usersDoc(t,
		`{"kind": "User", "name": "fresh", "spec": {"expires": "2099-01-01T00:00:00Z"}}`,
		`{"kind": "User", "name": "expired", "spec": {"expires": "2020-01-01T00:00:00Z"}}`,
		`{"kind": "User", "name": "plain", "spec": {}}`,
		`{"kind": "User", "name": "nopass", "spec": {}}`,
	)); err != nil {
		t.Fatal(err)
	}
	const secret = "correct horse battery staple"
	for _, name := range []string{"fresh", "expired", "plain"} {
		if _, err := h.api.SetUserPassword(ctx, name, secret); err != nil {
			t.Fatal(err)
		}
	}
	users, err := h.api.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if want := u.Name == "expired"; u.Expired != want || u.HasPassword != (u.Name != "nopass") {
			t.Errorf("the user %s is listed with expired %v and a password %v", u.Name, u.Expired, u.HasPassword)
		}
	}

	for _, name := range []string{"fresh", "plain"} {
		acct, err := h.c.AuthenticateUser(ctx, controller.Login{User: name, Password: secret})
		if err != nil || acct.Name != name || len(acct.Devices) != 0 {
			t.Errorf("%s with the right password: %+v (%v), want its account", name, acct, err)
		}
	}
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "expired", Password: secret}); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("an expired user with the right password: %v, want ErrUserExpired", err)
	}
	for _, c := range []struct {
		user     string
		password string
	}{
		{"expired", "a wrong password"},
		{"fresh", "a wrong password"},
		{"fresh", ""},
		{"nopass", secret},
		{"nobody", secret},
	} {
		if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: c.user, Password: c.password}); !errors.Is(err, controller.ErrBadCredentials) {
			t.Errorf("%q with the password %q: %v, want ErrBadCredentials", c.user, c.password, err)
		}
	}
	// An expired user cannot change its password either
	if err := h.c.ChangeUserPassword(ctx, "expired", secret, "another password"); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("an expired user changes its password: %v, want ErrUserExpired", err)
	}

	// The expiry is the one of the intent: moved later, the user authenticates again
	if _, err := h.api.PutUser(ctx, "expired", intent.User{Expires: time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "expired", Password: secret}); err != nil {
		t.Errorf("the user whose expiry moved to 2099 authenticates: %v", err)
	}
}

// TestMaxDevicesRefusesOneTooMany is the second half of the third criterion of SDN-31 (#225): the
// maximum of devices of a user refuses the device that is one too many, with a message that names the
// devices, and changes nothing. A higher maximum takes it, and a lower one is refused while the user has
// more devices than it allows. users.json gives alice a maximum of 2 and one laptop.
func TestMaxDevicesRefusesOneTooMany(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("users.json")
	if _, err := h.api.Apply(ctx, usersDoc(t, userNode("alice-phone", "alice", 1))); err != nil {
		t.Fatalf("the second device of alice: %v", err)
	}
	before := h.resources()

	_, err := h.api.Apply(ctx, usersDoc(t, userNode("alice-tablet", "alice", 2)))
	if httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `User "alice": 3 devices (Node "alice-laptop", Node "alice-phone", Node "alice-tablet"), and the maximum is 2`) {
		t.Fatalf("the third device of alice: %v, want 400 Bad Request that names her three devices and the maximum", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused device changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	// The devices of another user count for that user
	if _, err := h.api.Apply(ctx, usersDoc(t, userNode("bob-phone", "bob", 3), userNode("bob-tablet", "bob", 4), userNode("bob-watch", "bob", 5))); err != nil {
		t.Errorf("three devices of bob, who has no maximum: %v", err)
	}

	// A lower maximum is refused while there are more devices, and a higher one takes the device
	if _, err := h.api.PutUser(ctx, "alice", intent.User{DisplayName: "Alice", Groups: []string{"staff"}, MaxDevices: 1}); httpStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), `User "alice": 2 devices (Node "alice-laptop", Node "alice-phone"), and the maximum is 1`) {
		t.Errorf("a maximum of 1 for alice, who has 2 devices: %v, want 400 Bad Request", err)
	}
	if _, err := h.api.PutUser(ctx, "alice", intent.User{DisplayName: "Alice", Groups: []string{"staff"}, MaxDevices: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Apply(ctx, usersDoc(t, userNode("alice-tablet", "alice", 2))); err != nil {
		t.Errorf("the third device of alice under a maximum of 3: %v", err)
	}
	if _, err := h.api.Apply(ctx, usersDoc(t, userNode("alice-watch", "alice", 6))); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("the fourth device of alice under a maximum of 3: %v, want 400 Bad Request", err)
	}
	users, err := h.api.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == "alice" && len(u.Devices) != 3 {
			t.Errorf("alice has the devices %+v, want 3", u.Devices)
		}
	}
}

// TestPasswordRules is the fourth criterion of SDN-31 (#225). A user that may not change its password
// keeps the one that an administrator set, and the administrator may still set it. A user that may
// not save its password is refused when a client says that the password came from its storage, and
// its login tells the client not to keep it. A password that is too short is refused.
func TestPasswordRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.api.Apply(ctx, usersDoc(t,
		`{"kind": "User", "name": "fixed", "spec": {"mayChangePassword": false}}`,
		`{"kind": "User", "name": "free", "spec": {}}`,
		`{"kind": "User", "name": "nosave", "spec": {"noSavedPassword": true}}`,
	)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fixed", "free", "nosave"} {
		if _, err := h.api.SetUserPassword(ctx, name, "first password"); err != nil {
			t.Fatal(err)
		}
	}
	login := func(user, secret string, saved bool) (controller.Account, error) {
		return h.c.AuthenticateUser(ctx, controller.Login{User: user, Password: secret, Saved: saved})
	}

	// may-change-password
	if err := h.c.ChangeUserPassword(ctx, "fixed", "first password", "second password"); !errors.Is(err, controller.ErrPasswordFixed) {
		t.Errorf("a user that may not change its password changes it: %v, want ErrPasswordFixed", err)
	}
	if _, err := login("fixed", "first password", false); err != nil {
		t.Errorf("the password of the fixed user after the refused change: %v, want the first one to work", err)
	}
	if _, err := h.api.SetUserPassword(ctx, "fixed", "administrator's password"); err != nil {
		t.Errorf("an administrator sets the password of the fixed user: %v", err)
	}
	if _, err := login("fixed", "administrator's password", false); err != nil {
		t.Errorf("the password that the administrator set for the fixed user: %v", err)
	}
	if err := h.c.ChangeUserPassword(ctx, "free", "a wrong password", "second password"); !errors.Is(err, controller.ErrBadCredentials) {
		t.Errorf("a change with the wrong current password: %v, want ErrBadCredentials", err)
	}
	if err := h.c.ChangeUserPassword(ctx, "free", "first password", "short"); !errors.Is(err, password.ErrInvalid) {
		t.Errorf("a change to a password that is too short: %v, want password.ErrInvalid", err)
	}
	if err := h.c.ChangeUserPassword(ctx, "free", "first password", "second password"); err != nil {
		t.Fatalf("a user that may change its password changes it: %v", err)
	}
	if _, err := login("free", "first password", false); !errors.Is(err, controller.ErrBadCredentials) {
		t.Errorf("the old password after a change: %v, want ErrBadCredentials", err)
	}
	if _, err := login("free", "second password", false); err != nil {
		t.Errorf("the new password after a change: %v", err)
	}

	// no-saved-password
	if _, err := login("nosave", "first password", true); !errors.Is(err, controller.ErrSavedPassword) {
		t.Errorf("a saved password of a user that may not save it: %v, want ErrSavedPassword", err)
	}
	if _, err := login("nosave", "a wrong password", true); !errors.Is(err, controller.ErrBadCredentials) {
		t.Errorf("a wrong saved password: %v, want ErrBadCredentials, which says nothing of the flag", err)
	}
	if acct, err := login("nosave", "first password", false); err != nil || !acct.NoSavedPassword || !acct.CanChangePassword() {
		t.Errorf("the typed password of a user that may not save it: %+v (%v), want its account with NoSavedPassword", acct, err)
	}
	if acct, err := login("free", "second password", true); err != nil || acct.NoSavedPassword {
		t.Errorf("a saved password of a user that may save it: %+v (%v), want its account without the flag", acct, err)
	}

	// The rules of a password
	if _, err := h.api.SetUserPassword(ctx, "free", "short"); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "at least 8 characters") {
		t.Errorf("a password of 5 characters: %v, want 400 Bad Request", err)
	}
	if _, err := h.api.SetUserPassword(ctx, "free", strings.Repeat("x", password.MaxLength+1)); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a password of %d bytes: %v, want 400 Bad Request", password.MaxLength+1, err)
	}
}

// TestPasswordsStayOutOfTheIntent checks where a password goes: it is kept as a PBKDF2 hash in the
// store and nowhere else, so the intent, an export and the list of users never show it or its hash; it
// survives a restart of the controller; it goes when the user goes, by a delete or by a rollback, so a
// user that is made again under the name starts with none.
func TestPasswordsStayOutOfTheIntent(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	h := newHarness(t)
	ctx := context.Background()
	const secret = "correct horse battery staple"
	if _, err := h.api.Apply(ctx, usersDoc(t,
		`{"kind": "User", "name": "alice", "spec": {}}`,
		`{"kind": "User", "name": "bob", "spec": {}}`,
	)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := h.api.SetUserPassword(ctx, name, secret); err != nil {
			t.Fatal(err)
		}
	}

	// Only the store holds the hash: the form of PBKDF2, with the count of the node and a salt, and not the password
	hash, ok, err := h.st.UserPassword(ctx, "alice")
	if err != nil || !ok || !strings.HasPrefix(hash, "$pbkdf2-sha256$i=600000$") || strings.Contains(hash, secret) {
		t.Fatalf("the stored password of alice is %q (%v, %v)", hash, ok, err)
	}
	exported, err := h.api.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exportedJSON, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	users, err := h.api.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	usersJSON, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	everything := h.resources() + string(exportedJSON) + string(usersJSON)
	for _, forbidden := range []string{secret, "pbkdf2", hash} {
		if strings.Contains(everything, forbidden) {
			t.Errorf("the intent, its export or the list of users holds %q", forbidden)
		}
	}

	// A restart of the controller and of its store keeps the password
	h.stop()
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "alice", Password: secret}); err != nil {
		t.Errorf("alice after a restart: %v", err)
	}

	// A delete takes the password with the user, and the user that is made again has none
	if _, err := h.api.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := h.st.UserPassword(ctx, "alice"); err != nil || ok {
		t.Errorf("the password of alice after her delete: %v (%v), want none", ok, err)
	}
	if _, err := h.api.PutUser(ctx, "alice", intent.User{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "alice", Password: secret}); !errors.Is(err, controller.ErrBadCredentials) {
		t.Errorf("a new alice with the password of the old one: %v, want ErrBadCredentials", err)
	}

	// A rollback that removes a user takes its password too
	if _, err := h.api.Rollback(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if names, err := h.st.UsersWithPassword(ctx); err != nil || len(names) != 0 {
		t.Errorf("the users with a password after a rollback to the empty intent: %v (%v), want none", names, err)
	}
}
