// Controller conformance for the self-service portal (SDN-58 #251), with the harness and the node simulator of
// conformance_test.go and the logins of logins_test.go: a User signs in with the scope self and sees only its
// own devices, adds one and removes one; a join token that the User makes enrols a device as a Node that the
// User owns, in the networks that a Node gets, with the tags of the groups of the User; the token is used once,
// ends, can be revoked, and goes with its User.
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

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// bobPassword is the password of the User bob of portalIntent.
const bobPassword = "bob keeps a long password too"

// portalIntent applies what the tests of the portal need beside the User alice of newLoginEnv: the Group staff,
// which alice belongs to, the User bob with a password and at most one device, the devices alice-laptop and
// bob-laptop, and the Node files, which no User owns.
func portalIntent(t *testing.T, e *loginEnv) {
	t.Helper()
	e.h.applyDoc(usersDoc(t,
		`{"kind": "Group", "name": "staff"}`,
		`{"kind": "User", "name": "alice", "spec": {"displayName": "Alice", "groups": ["staff"], "maxDevices": 2}}`,
		`{"kind": "User", "name": "bob", "spec": {"maxDevices": 1}}`,
		userNode("alice-laptop", "alice", 1),
		userNode("bob-laptop", "bob", 2),
		fmt.Sprintf(`{"kind": "Node", "name": "files", "spec": {"publicKey": %q}}`, base64.StdEncoding.EncodeToString(nodeKey(3).Public())),
	))
	if _, err := e.h.api.SetUserPassword(context.Background(), "bob", bobPassword); err != nil {
		t.Fatal(err)
	}
}

// portal signs the User user in to the portal with its password, as the web UI does, and returns a client of
// the API that calls with its token of the self scope, and the token.
func (e *loginEnv) portal(t *testing.T, user, password string) (*api.Client, login.SignedIn) {
	t.Helper()
	in, err := e.client.SignInSelf(context.Background(), user, password)
	if err != nil {
		t.Fatal(err)
	}
	if in.Role != rbac.Self || in.User != user || in.Name != audit.ActorUser(user) || !strings.HasPrefix(in.Secret, "ranz_s_") {
		t.Fatalf("the portal login of %s gave %+v, want a token of the scope self", user, in)
	}
	return e.caller(in.Secret), in
}

// loginStatus returns the HTTP status of an error of the logins: 200 for no error, 0 for an error that is
// not an answer.
func loginStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var e *login.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// waitSelfDevice polls the devices of the portal that c shows until the device name has the state state, and
// returns it.
func waitSelfDevice(t *testing.T, c *api.Client, name, state string) controller.SelfDevice {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		devices, err := c.SelfDevices(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devices {
			if d.Name == name && d.State == state {
				return d
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the device %s does not reach the state %q within %v: %+v", name, state, waitTimeout, devices)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// deviceNames returns the names of the devices.
func deviceNames(devices []controller.SelfDevice) []string {
	names := make([]string, len(devices))
	for i, d := range devices {
		names[i] = d.Name
	}
	return names
}

// TestAUserSeesOnlyItsOwnDevicesAndAddsAndRemovesThem is the first criterion of SDN-58 (#251): alice signs in
// to the portal with the scope self, and sees her laptop and no device of bob or of nobody, with how it stands;
// she adds a phone by its static key, which is a revision under her name that meets the maximum devices as an
// apply does, and removes it again; a device that is not hers is not found whatever she names; and her token
// reaches nothing of the API but the calls of her own.
func TestAUserSeesOnlyItsOwnDevicesAndAddsAndRemovesThem(t *testing.T) {
	e := newLoginEnv(t)
	portalIntent(t, e)
	ctx := context.Background()
	alice, in := e.portal(t, "alice", alicePassword)

	info, err := alice.Self(ctx)
	if err != nil || info.Name != "alice" || info.DisplayName != "Alice" || !slices.Equal(info.Groups, []string{"staff"}) || info.MaxDevices != 2 || info.Devices != 1 {
		t.Fatalf("the portal shows alice as %+v, %v", info, err)
	}
	devices, err := alice.SelfDevices(ctx)
	if err != nil || len(devices) != 1 {
		t.Fatalf("the devices of alice are %+v, %v, want her laptop alone", devices, err)
	}
	laptop := devices[0]
	if laptop.Kind != intent.KindNode || laptop.Name != "alice-laptop" || laptop.State != controller.DeviceOffline || laptop.Connected ||
		!slices.Equal(laptop.VRFs, []string{intent.DefaultVRF}) || !slices.Equal(laptop.Tags, []string{"staff"}) ||
		len(laptop.Addresses) != 1 || laptop.Addresses[0].Network != intent.DefaultNetwork || laptop.KeyExpires.IsZero() {
		t.Errorf("the laptop of alice, before it connects, is %+v", laptop)
	}

	// The laptop connects, and the portal says so
	e.h.sim("alice-laptop", nodeKey(1))
	if d := waitSelfDevice(t, alice, "alice-laptop", controller.DeviceConnected); !d.Connected || d.ConnectedSince.IsZero() || d.Generation == 0 {
		t.Errorf("the laptop of alice, connected, is %+v", d)
	}

	// Bob sees his laptop and nothing of alice, who sees nothing of his
	bob, _ := e.portal(t, "bob", bobPassword)
	if devices, err := bob.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"bob-laptop"}) {
		t.Errorf("the devices of bob are %+v, %v, want his laptop alone", devices, err)
	}
	if info, err := bob.Self(ctx); err != nil || info.Name != "bob" || info.Devices != 1 || info.MaxDevices != 1 || len(info.Groups) != 0 {
		t.Errorf("the portal shows bob as %+v, %v", info, err)
	}

	// A device of bob, a Node of nobody, a device that does not exist and a resource that is no device are
	// not found for alice, and nothing changes
	before := e.h.resources()
	for _, c := range []struct{ kind, name string }{{"Node", "bob-laptop"}, {"Node", "files"}, {"Node", "nothing"}, {"Device", "alice-laptop"}, {"VRF", "default"}} {
		if _, err := alice.RemoveSelfDevice(ctx, c.kind, c.name); httpStatus(err) != http.StatusNotFound {
			t.Errorf("alice removes %s %s: %v, want 404", c.kind, c.name, err)
		}
	}
	if after := e.h.resources(); after != before {
		t.Errorf("a removal of a device that is not hers changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}

	// She adds a phone by its static key, which ranz node key shows
	phoneKey := base64.StdEncoding.EncodeToString(nodeKey(4).Public())
	added, err := alice.AddSelfDevice(ctx, "alice-phone", phoneKey)
	if err != nil || added.Node != "alice-phone" || added.User != "alice" || added.Revision == 0 {
		t.Fatalf("alice adds her phone: %+v, %v", added, err)
	}
	if devices, err := alice.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"alice-laptop", "alice-phone"}) {
		t.Errorf("the devices of alice after the add are %+v, %v", devices, err)
	}
	if info, err := alice.Self(ctx); err != nil || info.Devices != 2 {
		t.Errorf("the portal shows alice with %d devices after the add (%v), want 2", info.Devices, err)
	}
	e.h.sim("alice-phone", nodeKey(4))
	waitSelfDevice(t, alice, "alice-phone", controller.DeviceConnected)

	// The maximum devices of alice holds for the portal as it holds for an apply, and what is no device of
	// hers to add is refused
	if _, err := alice.AddSelfDevice(ctx, "alice-tablet", base64.StdEncoding.EncodeToString(nodeKey(5).Public())); httpStatus(err) != http.StatusBadRequest ||
		!strings.Contains(errText(err), "the maximum is 2") {
		t.Errorf("a third device of alice: %v, want 400 and the refusal of ranz apply", err)
	}
	for _, c := range []struct {
		what, name, key string
		status          int
	}{
		{"the key of a Node of bob", "x", base64.StdEncoding.EncodeToString(nodeKey(2).Public()), http.StatusConflict},
		{"the key of a Node of nobody", "x", base64.StdEncoding.EncodeToString(nodeKey(3).Public()), http.StatusConflict},
		{"a key that is no key", "x", "not base64", http.StatusBadRequest},
		{"a key that is too short", "x", base64.StdEncoding.EncodeToString([]byte("short")), http.StatusBadRequest},
		{"a name that is no name", "Not A Name", phoneKey, http.StatusBadRequest},
	} {
		if _, err := alice.AddSelfDevice(ctx, c.name, c.key); httpStatus(err) != c.status {
			t.Errorf("alice adds %s: %v, want %d", c.what, err, c.status)
		}
	}

	// She removes the phone, which is a revision under her name, and it is gone
	removed, err := alice.RemoveSelfDevice(ctx, intent.KindNode, "alice-phone")
	if err != nil || removed.Revision <= added.Revision {
		t.Fatalf("alice removes her phone: %+v, %v", removed, err)
	}
	if devices, err := alice.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"alice-laptop"}) {
		t.Errorf("the devices of alice after the removal are %+v, %v", devices, err)
	}
	if strings.Contains(e.h.resources(), "alice-phone") {
		t.Error("the intent still holds the phone that alice removed")
	}

	// What alice did is hers in the audit log: the two revisions, and the two calls
	e.h.waitAudit(e.h.api, "the changes that alice made in the portal", func(rs []audit.Record) bool {
		var addedRev, removedRev, post, del bool
		for _, r := range auditOfKind(rs, audit.IntentChange) {
			addedRev = addedRev || r.Revision == added.Revision && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
			removedRev = removedRev || r.Revision == removed.Revision && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
		}
		for _, r := range auditOfKind(rs, audit.Operation) {
			post = post || r.Action == "POST /api/v1/self/devices" && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
			del = del || r.Action == "DELETE /api/v1/self/devices/Node/alice-phone" && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
		}
		return addedRev && removedRev && post && del
	})

	// The token of the self scope reaches the calls of the portal and nothing else of the API
	for what, call := range map[string]func() error{
		"whoami":    func() error { _, err := alice.Whoami(ctx); return err },
		"nodes":     func() error { _, err := alice.Nodes(ctx); return err },
		"resources": func() error { _, err := alice.Resources(ctx); return err },
		"users":     func() error { _, err := alice.Users(ctx); return err },
		"tokens":    func() error { _, err := alice.Tokens(ctx); return err },
		"apply":     func() error { _, err := alice.Apply(ctx, intent.Document{}); return err },
		"delete":    func() error { _, err := alice.Delete(ctx, intent.KindNode, "bob-laptop"); return err },
	} {
		if err := call(); httpStatus(err) != http.StatusForbidden {
			t.Errorf("%s with the token of the self scope: %v, want 403", what, err)
		}
	}
	// ... and an API token, which names no User, reaches none of the calls of the portal
	admin := e.caller(e.h.admin)
	if _, err := admin.SelfDevices(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the devices of the portal with an admin API token: %v, want 403", err)
	}
	if _, err := admin.MakeJoinToken(ctx, ""); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a join token with an admin API token: %v, want 403", err)
	}
	// A User that holds an API role is a User as well: its user token makes the calls of the portal, and
	// they are its own
	if _, err := e.h.api.SetUserRole(ctx, "bob", rbac.Viewer); err != nil {
		t.Fatal(err)
	}
	role, err := e.client.SignIn(ctx, "bob", bobPassword)
	if err != nil {
		t.Fatal(err)
	}
	if devices, err := e.caller(role.Secret).SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"bob-laptop"}) {
		t.Errorf("the devices of bob with the user token of his role are %+v, %v", devices, err)
	}

	// The logout ends the token
	if tok, err := e.client.SignOut(ctx, in.Secret); err != nil || tok.User != "alice" || tok.Role != rbac.Self {
		t.Errorf("the logout of alice: %+v, %v", tok, err)
	}
	if _, err := alice.Self(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the portal with the token after its logout: %v, want 401", err)
	}
}

// TestAJoinTokenFromThePortalEnrolsADevice is the second criterion of SDN-58 (#251): alice makes a join token
// in the portal, and a device that presents it with its static key becomes a Node that alice owns, in the
// networks that a Node gets (VRF default), with the tag of her group; it joins with the keys that the answer
// gives and its state is the one that the intent compiles to. The token is used once, and a device that the
// intent refuses leaves it with alice.
func TestAJoinTokenFromThePortalEnrolsADevice(t *testing.T) {
	e := newLoginEnv(t)
	portalIntent(t, e)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)
	alice, _ := e.portal(t, "alice", alicePassword)

	tok, err := alice.MakeJoinToken(ctx, "alice-nas")
	if err != nil {
		t.Fatal(err)
	}
	if !controller.ValidJoinToken(tok.Token) || tok.Name != "alice-nas" || len(tok.ID) != 16 ||
		!tok.Expires.After(time.Now().Add(23*time.Hour)) || !tok.Expires.Before(time.Now().Add(25*time.Hour)) {
		t.Fatalf("the join token of alice is %+v", tok)
	}
	list, err := alice.JoinTokens(ctx)
	if err != nil || len(list) != 1 || list[0].ID != tok.ID || list[0].Name != "alice-nas" || !list[0].Expires.Equal(tok.Expires) {
		t.Fatalf("the join tokens of alice are %+v, %v", list, err)
	}
	if listed, err := json.Marshal(list); err != nil || strings.Contains(string(listed), tok.Token) {
		t.Errorf("the list of the join tokens holds the secret: %s (%v)", listed, err)
	}
	bob, _ := e.portal(t, "bob", bobPassword)
	if list, err := bob.JoinTokens(ctx); err != nil || len(list) != 0 {
		t.Errorf("bob sees the join tokens %+v, %v, want none", list, err)
	}
	if strings.Contains(e.h.resources(), "alice-nas") {
		t.Fatal("the Node of the device exists before the device joined")
	}

	// The device joins with the token and its static key: the Node is made, and alice owns it
	key := nodeKey(6)
	res, err := e.client.Join(ctx, tok.Token, login.Device{Key: key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Node != "alice-nas" || res.User != "alice" || res.Revision == 0 || res.AccessToken != "" || res.Controller == nil ||
		res.Controller.PublicKey != base64.StdEncoding.EncodeToString(e.h.key.Public()) || res.Controller.TLSFingerprint != e.fingerprint {
		t.Fatalf("the join gave %+v (%+v), want the Node alice-nas of alice with the keys of the controller", res, res.Controller)
	}
	s := e.join(t, key, res)
	if n := e.nodeSpec(t, "alice-nas"); n.Owner != "alice" || n.PublicKey != base64.StdEncoding.EncodeToString(key.Public()) ||
		!slices.Equal(n.VRFs, []string{intent.DefaultVRF}) {
		t.Errorf("the Node resource of the device is %+v, want a device of alice in VRF default", n)
	}
	if self, _, _ := userHeld(s); !slices.Equal(self, []string{"staff"}) {
		t.Errorf("the device carries the tags %v, want the group of alice, staff", self)
	}
	d := waitSelfDevice(t, alice, "alice-nas", controller.DeviceConnected)
	if d.Kind != intent.KindNode || !slices.Equal(d.VRFs, []string{intent.DefaultVRF}) || len(d.Addresses) != 1 {
		t.Errorf("the portal shows the device as %+v", d)
	}

	// The token is spent: it is not listed, and it enrols no second device, by the key of the first or another
	if list, err := alice.JoinTokens(ctx); err != nil || len(list) != 0 {
		t.Errorf("the join tokens of alice after the join are %+v, %v, want none", list, err)
	}
	for _, k := range [][]byte{nodeKey(7).Public(), key.Public()} {
		if _, err := e.client.Join(ctx, tok.Token, login.Device{Key: k}); loginStatus(err) != http.StatusUnauthorized {
			t.Errorf("a second join with the token: %v, want 401", err)
		}
	}

	// The audit log holds the join as alice's enrolment and the revision as hers, and the refused ones as
	// failed authentications of nobody
	recs := e.h.waitAudit(e.h.api, "the join of the device of alice", func(rs []audit.Record) bool {
		var joined, revised, refused bool
		for _, r := range rs {
			joined = joined || r.Kind == audit.Enrolment && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
			revised = revised || r.Kind == audit.IntentChange && r.Revision == res.Revision && r.Actor == audit.ActorUser("alice")
			refused = refused || r.Kind == audit.AuthFailed && r.Actor == audit.ActorUnknown && strings.Contains(r.Message, "join token")
		}
		return joined && revised && refused
	})
	for _, r := range auditOfKind(recs, audit.Enrolment) {
		if r.Actor == audit.ActorUser("alice") {
			checkAuditRecord(t, r, since, audit.ActorUser("alice"), "127.0.0.1", audit.Success, "", 0)
			if strings.Contains(r.Message, tok.Token) || !strings.Contains(r.Message, "alice-nas") {
				t.Errorf("the record of the join says %q", r.Message)
			}
		}
	}

	// The maximum devices of alice holds: with two devices, a third is refused as `ranz apply` refuses it, and
	// the token is still hers. Once she removes one, the same token enrols it.
	third, err := alice.MakeJoinToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Join(ctx, third.Token, login.Device{Key: nodeKey(8).Public()}); loginStatus(err) != http.StatusBadRequest ||
		!strings.Contains(errText(err), "the maximum is 2") {
		t.Errorf("the join of a third device of alice: %v, want 400 and the refusal of ranz apply", err)
	}
	if list, err := alice.JoinTokens(ctx); err != nil || len(list) != 1 || list[0].ID != third.ID {
		t.Errorf("the join tokens of alice after the refusal are %+v, %v, want the one that was refused", list, err)
	}
	// A device with the key of a Node of bob is refused too, and the token stays
	if _, err := e.client.Join(ctx, third.Token, login.Device{Key: nodeKey(2).Public()}); loginStatus(err) != http.StatusConflict {
		t.Errorf("the join of a device with the key of a Node of bob: %v, want 409", err)
	}
	if _, err := alice.RemoveSelfDevice(ctx, intent.KindNode, "alice-nas"); err != nil {
		t.Fatal(err)
	}
	again, err := e.client.Join(ctx, third.Token, login.Device{Key: nodeKey(8).Public()})
	if err != nil || again.User != "alice" || again.Node == "" {
		t.Fatalf("the join with the token that was refused, once alice has room: %+v, %v", again, err)
	}
	if n := e.nodeSpec(t, again.Node); n.Owner != "alice" || n.PublicKey != base64.StdEncoding.EncodeToString(nodeKey(8).Public()) {
		t.Errorf("the Node of the device that the refused token enrolled is %+v", n)
	}
}

// joinHarness is a harness on the clock of the lives of the keys (newKeysHarness), which a test moves, with
// Users that hold up to twenty devices, and the means to give each a token of the self scope.
type joinHarness struct {
	h   *harness
	clk *keyClock
	// tokens issues the tokens of the self scope
	tokens *rbac.Tokens
}

func newJoinHarness(t *testing.T, users ...string) *joinHarness {
	t.Helper()
	h, clk := newKeysHarness(t)
	resources := make([]string, len(users))
	for i, u := range users {
		resources[i] = fmt.Sprintf(`{"kind": "User", "name": %q, "spec": {"maxDevices": 20}}`, u)
	}
	h.applyJSON(resources...)
	return &joinHarness{h: h, clk: clk, tokens: rbac.New(h.st)}
}

// self returns a client of the API that calls with a new token of the self scope of the User user.
func (j *joinHarness) self(user string) *api.Client {
	j.h.t.Helper()
	tok, err := j.tokens.IssueSelfToken(context.Background(), user, time.Now().Add(time.Hour))
	if err != nil {
		j.h.t.Fatal(err)
	}
	return j.h.client(tok.Secret)
}

// TestJoinTokensEndAndAreTheirUsersAlone checks the rest of the life of a join token against the clock of the
// controller: it ends after a day, its User revokes it and nobody else does, no User holds more than a few that
// wait, the name of the device must be a name, and a User that is banned or has expired can neither make one nor
// enrol a device with one, which stays with its User.
func TestJoinTokensEndAndAreTheirUsersAlone(t *testing.T) {
	j := newJoinHarness(t, "alice", "bob")
	ctx := context.Background()
	alice, bob := j.self("alice"), j.self("bob")
	key := func(i int) []byte { return nodeKey(i).Public() }

	// A join token ends a day after it was made, and nothing enrols with it from then
	tok, err := alice.MakeJoinToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	j.clk.Advance(controller.JoinTokenLife - time.Minute)
	if list, err := alice.JoinTokens(ctx); err != nil || len(list) != 1 {
		t.Errorf("the join tokens of alice a minute before the end are %+v, %v", list, err)
	}
	j.clk.Advance(2 * time.Minute)
	if list, err := alice.JoinTokens(ctx); err != nil || len(list) != 0 {
		t.Errorf("the join tokens of alice a minute after the end are %+v, %v, want none", list, err)
	}
	if _, err := j.h.c.JoinDevice(ctx, tok.Token, "", key(1)); !errors.Is(err, controller.ErrBadJoinToken) {
		t.Errorf("the join with a token that ended: %v, want ErrBadJoinToken", err)
	}

	// A User revokes its own token, and not the token of another User
	mine, err := alice.MakeJoinToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.RevokeJoinToken(ctx, mine.ID); httpStatus(err) != http.StatusNotFound {
		t.Errorf("bob revokes the token of alice: %v, want 404", err)
	}
	if got, err := alice.RevokeJoinToken(ctx, mine.ID); err != nil || got.ID != mine.ID {
		t.Errorf("alice revokes her token: %+v, %v", got, err)
	}
	if _, err := alice.RevokeJoinToken(ctx, mine.ID); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a second revocation: %v, want 404", err)
	}
	if _, err := j.h.c.JoinDevice(ctx, mine.Token, "", key(1)); !errors.Is(err, controller.ErrBadJoinToken) {
		t.Errorf("the join with a token that was revoked: %v, want ErrBadJoinToken", err)
	}
	// A secret that is no join token of the form, one that has the form and is none
	for _, s := range []string{"", "ranz_j_", "ranz_u_" + strings.Repeat("A", 26), controller.JoinTokenPrefix + strings.Repeat("Z", 26)} {
		if _, err := j.h.c.JoinDevice(ctx, s, "", key(1)); !errors.Is(err, controller.ErrBadJoinToken) {
			t.Errorf("the join with the secret %q: %v, want ErrBadJoinToken", s, err)
		}
	}

	// A User holds a few that wait, and the name of the device must be a name. The clock moves a second after
	// each token, which is the order that the list keeps them in.
	for i := range controller.MaxJoinTokens {
		if _, err := alice.MakeJoinToken(ctx, fmt.Sprintf("device-%d", i)); err != nil {
			t.Fatalf("join token %d of alice: %v", i, err)
		}
		j.clk.Advance(time.Second)
	}
	if _, err := alice.MakeJoinToken(ctx, ""); httpStatus(err) != http.StatusConflict {
		t.Errorf("a join token above the limit of %d: %v, want 409", controller.MaxJoinTokens, err)
	}
	if _, err := bob.MakeJoinToken(ctx, ""); err != nil {
		t.Errorf("the first join token of bob, while alice holds the most: %v", err)
	}
	if _, err := bob.MakeJoinToken(ctx, "Not A Name"); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a join token for a device whose name is no name: %v, want 400", err)
	}
	list, err := alice.JoinTokens(ctx)
	if err != nil || len(list) != controller.MaxJoinTokens || list[0].Name != "device-0" {
		t.Fatalf("the join tokens of alice are %d (%v), want %d, the oldest first", len(list), err, controller.MaxJoinTokens)
	}

	// A User that an operator banned makes no token and enrols no device with one, and the token waits for the
	// end of the ban
	waiting, err := bob.MakeJoinToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.h.api.Ban(ctx, "bob", "an incident"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.h.c.MakeJoinToken(ctx, "bob", ""); !errors.Is(err, controller.ErrUserBanned) {
		t.Errorf("a join token of a banned User: %v, want ErrUserBanned", err)
	}
	if _, err := j.h.c.JoinDevice(ctx, waiting.Token, "", key(2)); !errors.Is(err, controller.ErrUserBanned) {
		t.Errorf("a join with the token of a banned User: %v, want ErrUserBanned", err)
	}
	if _, err := j.h.api.Unban(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if e, err := j.h.c.JoinDevice(ctx, waiting.Token, "bob-phone", key(2)); err != nil || e.Node != "bob-phone" || e.User != "bob" {
		t.Errorf("the join with the token once the ban is lifted: %+v, %v", e, err)
	}

	// A User that has expired makes no token, and a token of it enrols nothing
	soon := j.clk.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	j.h.applyJSON(fmt.Sprintf(`{"kind": "User", "name": "carol", "spec": {"expires": %q}}`, soon))
	kept, err := j.h.c.MakeJoinToken(ctx, "carol", "")
	if err != nil {
		t.Fatal(err)
	}
	j.clk.Advance(2 * time.Hour)
	if _, err := j.h.c.MakeJoinToken(ctx, "carol", ""); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("a join token of a User that has expired: %v, want ErrUserExpired", err)
	}
	if _, err := j.h.c.JoinDevice(ctx, kept.Token, "", key(3)); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("a join with the token of a User that has expired: %v, want ErrUserExpired", err)
	}
}

// TestATokenOfTheSelfScopeEndsWithItsUser checks that what ends the user tokens of a User ends its token of the
// self scope too: a ban at once, an expiry that moves earlier at that expiry, and the removal of the User from
// the intent, which takes its join tokens along; and that the token of another User goes on.
func TestATokenOfTheSelfScopeEndsWithItsUser(t *testing.T) {
	j := newJoinHarness(t, "alice", "bob", "carol", "dave")
	ctx := context.Background()
	clients := map[string]*api.Client{}
	for _, u := range []string{"alice", "bob", "carol", "dave"} {
		clients[u] = j.self(u)
		if _, err := clients[u].MakeJoinToken(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := clients[u].Self(ctx); err != nil {
			t.Fatalf("the token of %s before anything happened: %v", u, err)
		}
	}
	if _, err := j.h.api.Ban(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	j.h.applyJSON(fmt.Sprintf(`{"kind": "User", "name": "bob", "spec": {"expires": %q}}`, j.clk.Now().Add(-time.Minute).UTC().Format(time.RFC3339)))
	if _, err := j.h.api.Delete(ctx, intent.KindUser, "carol"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if _, err := clients[u].Self(ctx); httpStatus(err) != http.StatusUnauthorized {
			t.Errorf("the token of %s after it was banned, expired or removed: %v, want 401", u, err)
		}
	}
	if _, err := clients["dave"].Self(ctx); err != nil {
		t.Errorf("the token of dave, whom nothing happened to: %v", err)
	}
	// The join tokens of the User that was removed went with it, and those of the others stay
	for user, want := range map[string]int{"carol": 0, "dave": 1} {
		ts, err := j.h.st.JoinTokens(ctx, user, j.clk.Now())
		if err != nil || len(ts) != want {
			t.Errorf("the join tokens of %s are %+v (%v), want %d", user, ts, err, want)
		}
	}
	// A User made again under the name starts with none
	j.h.applyJSON(`{"kind": "User", "name": "carol"}`)
	if ts, err := j.h.st.JoinTokens(ctx, "carol", j.clk.Now()); err != nil || len(ts) != 0 {
		t.Errorf("the join tokens of carol made again are %+v (%v)", ts, err)
	}
}
