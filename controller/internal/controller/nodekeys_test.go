// Controller conformance for the lives of the node keys (SDN-56 #249, ADR-0031 amendment of 2026-10-28), with the
// harness and the node simulator of conformance_test.go: the key of a node expires and stops the node until its user
// authenticates again, a user that is no longer valid cannot refresh the keys of its devices, a Network that holds new
// nodes for approval keeps each out until an operator approves it, and an admin marks a server nonExpiring. The
// controller of these tests runs on a clock that they move, and looks at the lives of the keys every 10 ms.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// keyDay is a day of the clock of the lives of the keys.
const keyDay = 24 * time.Hour

// keysVRF is the VRF corp of testdata/nodekeys.json, for the tests that apply their own resources.
const keysVRF = `{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}}`

// keysNetwork returns the Network corp-lan with the fields that extra adds to its spec, each after a comma.
func keysNetwork(extra string) string {
	return `{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"` + extra + `}}`
}

// keysNode returns a Node of VRF corp in Network corp-lan with the key key and the address address, and the fields
// that extra adds to its spec, each after a comma.
func keysNode(name string, key keys.Static, address, extra string) string {
	return fmt.Sprintf(`{"kind": "Node", "name": %q, "spec": {"publicKey": %q, "vrfs": ["corp"], "addresses": {"corp-lan": %q}%s}}`,
		name, base64.StdEncoding.EncodeToString(key.Public()), address, extra)
}

// keyClock is the clock of the controller of a harness from newKeysHarness, which a test moves.
type keyClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the time of the clock.
func (c *keyClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *keyClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newKeysHarness returns a harness whose controller runs on the clock that is returned, which starts now and which a
// test moves, and looks at the lives of the keys every 10 ms.
func newKeysHarness(t *testing.T) (*harness, *keyClock) {
	t.Helper()
	clk := &keyClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) {
		c.Now = clk.Now
		c.KeyCheck = 10 * time.Millisecond
	}}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h, clk
}

// applyJSON applies the resources that the JSON objects list, as ranz apply -f does.
func (h *harness) applyJSON(resources ...string) controller.ApplyResult {
	h.t.Helper()
	doc, err := intent.ParseDocument([]byte(`{"resources": [` + strings.Join(resources, ",") + `]}`))
	if err != nil {
		h.t.Fatal(err)
	}
	res, err := h.api.Apply(context.Background(), doc)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

// nodeKeys returns the keys of the nodes as the API lists them, by the name of the node.
func (h *harness) nodeKeys() map[string]controller.NodeKeyInfo {
	h.t.Helper()
	l, err := h.api.NodeKeys(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	out := make(map[string]controller.NodeKeyInfo, len(l))
	for _, k := range l {
		out[k.Node] = k
	}
	return out
}

// reauthenticate is the login of the user user with the device that has the static key key: the controller checks the
// password and then enrols the device again, which refreshes its key.
func (h *harness) reauthenticate(user, password string, key keys.Static) error {
	h.t.Helper()
	ctx := audit.NewContext(context.Background(), audit.Origin{Actor: audit.ActorUser(user), Source: "192.0.2.7"})
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: user, Password: password}); err != nil {
		return err
	}
	_, err := h.c.EnrolDevice(ctx, user, "", key.Public())
	return err
}

// setPasswords gives each of the users the password "a good password".
func (h *harness) setPasswords(users ...string) {
	h.t.Helper()
	for _, user := range users {
		if err := h.c.SetUserPassword(context.Background(), user, "a good password"); err != nil {
			h.t.Fatal(err)
		}
	}
}

// connect runs the nodes, each with the full state that the controller has for it, and waits until each acknowledged it.
func (h *harness) connect(t *testing.T, sims ...*sim) {
	t.Helper()
	for _, s := range sims {
		s.update(t)
		h.waitNode(s.name, 1, true)
	}
}

// noUpdate checks that no update reaches the node s and that its stream stays open within quietTimeout.
func noUpdate(t *testing.T, s *sim) {
	t.Helper()
	select {
	case u := <-s.Updates:
		t.Errorf("%s: got the update %s, which nothing should have made", s.name, show(u))
	case err := <-s.done:
		s.done = nil
		t.Errorf("%s: its stream ended: %v", s.name, err)
	case <-time.After(quietTimeout):
	}
}

// removedPeers returns the names of the Peers that the update u removes, in order.
func removedPeers(u *controlpb.Update) []string {
	var out []string
	for _, k := range u.GetRemove() {
		if k.GetKind() == controlpb.Kind_KIND_PEER {
			out = append(out, k.GetName())
		}
	}
	slices.Sort(out)
	return out
}

// checkKeyState checks the state of the key of the node name in the listing infos.
func checkKeyState(t *testing.T, infos map[string]controller.NodeKeyInfo, name, state string) {
	t.Helper()
	if got := infos[name].State; got != state {
		t.Errorf("the key of %s is %s, want %s: %+v", name, got, state, infos[name])
	}
}

// expiredMessage is the message of the Refuse for the node name whose key ended at the instant end, for a node of a
// user or for one that has none.
func expiredMessage(name string, end time.Time, owned bool) string {
	if owned {
		return fmt.Sprintf("the key of Node %q expired at %s: its user logs in again to refresh it", name, end.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("the key of Node %q expired at %s: an operator refreshes it, or marks the Node nonExpiring", name, end.UTC().Format(time.RFC3339))
}

// checkRefusal checks that the Refuse r has the reason of a node that is not admitted and the message want.
func checkRefusal(t *testing.T, who string, r *controlpb.Refuse, want string) {
	t.Helper()
	if r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE || r.GetMessage() != want {
		t.Errorf("%s was refused with %s %q, want the reason UNKNOWN_NODE and the message %q", who, r.GetReason(), r.GetMessage(), want)
	}
}

// TestAnExpiredKeyStopsTheNodeUntilItAuthenticatesAgain is the first criterion of SDN-56: the key of a node lives 90
// days from the moment that it was admitted or that its user logged in again, and the node whose key ended is refused
// on its control stream and left out of the states of every other node, until its user authenticates again (a device)
// or an operator refreshes the key (a node that has no user). The key that was refreshed on the way keeps its node.
func TestAnExpiredKeyStopsTheNodeUntilItAuthenticatesAgain(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys.json")
	h.setPasswords("alice", "bob")
	alice := h.sim("alice-laptop", keyBranch1)
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	h.connect(t, alice, bob, files)

	// A key lives 90 days from the apply that made its node, and a node that no Network holds for approval is admitted at once
	for name, k := range h.nodeKeys() {
		if k.State != controller.KeyValid || !k.Approved || k.ApprovedBy != audit.ActorSystem || !k.Refreshed.Equal(start) || !k.Expires.Equal(start.Add(90*keyDay)) || k.NonExpiring {
			t.Errorf("the key of %s is %+v, want a valid key that ends 90 days after %v, admitted by the system", name, k, start)
		}
	}

	// On day 60 bob logs in again: his key lives 90 days from then, and nothing else changes
	clk.Advance(60 * keyDay)
	if err := h.reauthenticate("bob", "a good password", keyBranch2); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["bob-laptop"]; !k.Refreshed.Equal(start.Add(60*keyDay)) || !k.Expires.Equal(start.Add(150*keyDay)) || k.State != controller.KeyValid {
		t.Errorf("the key of bob-laptop is %+v after bob logged in again on day 60, want it valid until day 150", k)
	}
	for _, s := range []*sim{alice, bob, files} {
		noUpdate(t, s)
	}

	// On day 91 the keys of alice-laptop and files have ended: both are refused, and bob-laptop is left without them as peers
	clk.Advance(31 * keyDay)
	ended := start.Add(90 * keyDay)
	aliceRefusal := refuseOf(t, alice)
	checkRefusal(t, "alice-laptop", aliceRefusal, expiredMessage("alice-laptop", ended, true))
	checkRefusal(t, "files", refuseOf(t, files), expiredMessage("files", ended, false))
	u := bob.update(t).GetUpdate()
	if got := removedPeers(u); u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 || !slices.Equal(got, []string{"alice-laptop", "files"}) {
		t.Errorf("bob-laptop got the update %s on day 91, want generation 2 on 1 that removes the peers alice-laptop and files", show(u))
	}
	h.waitNode("bob-laptop", 2, true)
	h.checkStateWithout(bob, "alice-laptop", "files")
	infos := h.nodeKeys()
	checkKeyState(t, infos, "alice-laptop", controller.KeyExpired)
	checkKeyState(t, infos, "files", controller.KeyExpired)
	checkKeyState(t, infos, "bob-laptop", controller.KeyValid)
	if n := h.node("alice-laptop"); n.Connected {
		t.Errorf("alice-laptop is %+v after its key ended, want it not connected", n)
	}

	// The node dials again and is refused again until its user authenticates
	alice.start(h)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", ended, true))
	if err := h.reauthenticate("alice", "a wrong password", keyBranch1); !errors.Is(err, controller.ErrBadCredentials) {
		t.Fatalf("a login of alice with a wrong password gave %v, want ErrBadCredentials", err)
	}
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyExpired {
		t.Errorf("the key of alice-laptop is %+v after a login that failed, want it still expired", k)
	}

	// alice authenticates again: her key lives 90 days from now and the others get her as a peer again
	if err := h.reauthenticate("alice", "a good password", keyBranch1); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyValid || !k.Refreshed.Equal(start.Add(91*keyDay)) || !k.Expires.Equal(start.Add(181*keyDay)) {
		t.Errorf("the key of alice-laptop is %+v after her login on day 91, want it valid until day 181", k)
	}
	u = bob.update(t).GetUpdate()
	if u.GetGeneration() != 3 || u.GetBaseGeneration() != 2 {
		t.Errorf("bob-laptop got the update %s when alice authenticated again, want generation 3 on 2", show(u))
	}
	h.waitNode("bob-laptop", 3, true)
	h.checkStateWithout(bob, "files")
	alice.start(h)
	u = alice.update(t).GetUpdate()
	if got := removedPeers(u); u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 || !slices.Equal(got, []string{"files"}) {
		t.Errorf("alice-laptop got the update %s when it connected again, want generation 2 on 1, the one that her key ending made it miss: files is still out", show(u))
	}
	h.waitNode("alice-laptop", 2, true)
	h.checkStateWithout(alice, "files")

	// files has no user to log in: an operator refreshes its key, and cannot refresh the key of a device of a user
	if _, err := h.api.RefreshNodeKey(ctx, "alice-laptop"); httpStatus(err) != http.StatusConflict {
		t.Errorf("an operator refreshing the key of alice-laptop gave %v, want 409: its user refreshes it", err)
	}
	if _, err := h.api.RefreshNodeKey(ctx, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("an operator refreshing the key of a node that does not exist gave %v, want 404", err)
	}
	k, err := h.api.RefreshNodeKey(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	if k.State != controller.KeyValid || !k.Refreshed.Equal(start.Add(91*keyDay)) || !k.Expires.Equal(start.Add(181*keyDay)) {
		t.Errorf("the key of files is %+v after an operator refreshed it on day 91, want it valid until day 181", k)
	}
	if u = bob.update(t).GetUpdate(); u.GetGeneration() != 4 || u.GetBaseGeneration() != 3 {
		t.Errorf("bob-laptop got the update %s when the key of files was refreshed, want generation 4 on 3", show(u))
	}
	if u = alice.update(t).GetUpdate(); u.GetGeneration() != 3 || u.GetBaseGeneration() != 2 {
		t.Errorf("alice-laptop got the update %s when the key of files was refreshed, want generation 3 on 2", show(u))
	}
	files.start(h)
	h.waitNode("files", 1, true)
	h.waitNode("bob-laptop", 4, true)
	h.waitNode("alice-laptop", 3, true)
	for _, s := range []*sim{alice, bob, files} {
		h.checkState(s)
	}
}

// TestAUserRemovedFromTheProviderLosesAccessAtTheNextRefresh is the second criterion of SDN-56. A user is removed where
// it comes from, which for the local accounts is an account that expired: it cannot authenticate any more, so its
// devices cannot refresh their keys, and each loses access when its key ends, while the devices of a user that is
// still valid are refreshed and go on. The removal itself cuts nobody off: that is what a ban is for.
func TestAUserRemovedFromTheProviderLosesAccessAtTheNextRefresh(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys.json")
	h.setPasswords("alice", "bob")
	alice := h.sim("alice-laptop", keyBranch1)
	bob := h.sim("bob-laptop", keyBranch2)
	h.connect(t, alice, bob)

	// alice is removed on day 30 of the clock of the controller, when her account expires. Her device keeps its access, as
	// every node does until its key ends
	res, err := h.api.PutUser(ctx, "alice", intent.User{Expires: start.Add(30 * keyDay)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 0 {
		t.Errorf("the removal of alice changed the states of %+v, want none", res.Nodes)
	}
	clk.Advance(45 * keyDay)
	noUpdate(t, alice)
	noUpdate(t, bob)
	h.waitNode("alice-laptop", 1, true)
	checkKeyState(t, h.nodeKeys(), "alice-laptop", controller.KeyValid)

	// On day 45 both devices try to refresh: bob's key is refreshed, alice's is not, and a caller that did not check her
	// password gets the same refusal from the enrolment of the device. The refresh reads the expiry of alice on the clock
	// of the controller, which this test moved 45 days past the wall clock that the check of her password reads, so the
	// refusal is the refresh's own
	if err := h.reauthenticate("alice", "a good password", keyBranch1); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("a login of the removed alice gave %v, want ErrUserExpired", err)
	}
	if _, err := h.c.EnrolDevice(ctx, "alice", "", keyBranch1.Public()); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("the enrolment of the device of the removed alice gave %v, want ErrUserExpired", err)
	}
	if err := h.reauthenticate("bob", "a good password", keyBranch2); err != nil {
		t.Fatal(err)
	}
	infos := h.nodeKeys()
	if k := infos["alice-laptop"]; !k.Expires.Equal(start.Add(90 * keyDay)) {
		t.Errorf("the key of alice-laptop is %+v after her login was refused, want it to end on day 90 as before", k)
	}
	if k := infos["bob-laptop"]; !k.Expires.Equal(start.Add(135 * keyDay)) {
		t.Errorf("the key of bob-laptop is %+v after bob refreshed it on day 45, want it to end on day 135", k)
	}

	// On day 91 the key of alice-laptop has ended and cannot be refreshed: it loses access, and bob-laptop goes on
	clk.Advance(46 * keyDay)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", start.Add(90*keyDay), true))
	u := bob.update(t).GetUpdate()
	if got := removedPeers(u); u.GetGeneration() != 2 || !slices.Equal(got, []string{"alice-laptop", "files"}) {
		t.Errorf("bob-laptop got the update %s on day 91, want generation 2 that removes the peers alice-laptop and files", show(u))
	}
	h.waitNode("bob-laptop", 2, true)
	infos = h.nodeKeys()
	checkKeyState(t, infos, "alice-laptop", controller.KeyExpired)
	if k := infos["bob-laptop"]; k.State != controller.KeyValid {
		t.Errorf("the key of bob-laptop is %+v on day 91, want it valid: bob is still a user", k)
	}
	alice.start(h)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", start.Add(90*keyDay), true))
	if err := h.reauthenticate("alice", "a good password", keyBranch1); !errors.Is(err, controller.ErrUserExpired) {
		t.Errorf("a login of the removed alice on day 91 gave %v, want ErrUserExpired", err)
	}
}

// A user that an operator banned, and one that does not exist, cannot refresh the key of a device either: the
// enrolment of the device refuses them whatever the caller checked, and a refresh that is refused changes no key.
func TestABannedUserCannotRefreshTheKeysOfItsDevices(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	h.apply("nodekeys.json")
	h.setPasswords("alice")
	clk.Advance(10 * keyDay)

	if _, err := h.api.Ban(ctx, "alice", "stolen laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.EnrolDevice(ctx, "alice", "", keyBranch1.Public()); !errors.Is(err, controller.ErrUserBanned) {
		t.Errorf("the enrolment of the device of the banned alice gave %v, want ErrUserBanned", err)
	}
	if _, err := h.c.EnrolDevice(ctx, "nobody", "", keyBranch1.Public()); !errors.Is(err, intent.ErrNotFound) {
		t.Errorf("the enrolment of a device of a user that does not exist gave %v, want ErrNotFound", err)
	}
	if k := h.nodeKeys()["alice-laptop"]; !k.Refreshed.Equal(clk.Now().Add(-10 * keyDay)) {
		t.Errorf("the key of alice-laptop is %+v after the refreshes that were refused, want it as it was", k)
	}
	if _, err := h.api.Unban(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := h.reauthenticate("alice", "a good password", keyBranch1); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["alice-laptop"]; !k.Refreshed.Equal(clk.Now()) {
		t.Errorf("the key of alice-laptop is %+v after the ban was lifted and she logged in, want it refreshed", k)
	}
}

// TestInApprovalModeANewNodeWaitsUntilItIsApproved is the third criterion of SDN-56: a Network that holds new nodes for
// approval keeps a new node out, refusing its control stream and leaving it out of the states of the others, until an
// operator approves it; the nodes that were admitted before are not touched.
func TestInApprovalModeANewNodeWaitsUntilItIsApproved(t *testing.T) {
	h, _ := newKeysHarness(t)
	ctx := context.Background()
	h.apply("nodekeys.json")
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	h.connect(t, bob, files)

	// The Network now holds new nodes for approval, and a new node joins it: only the new node gets a state
	res := h.applyJSON(keysNetwork(`, "approval": "manual"`), keysNode("newcomer", keyUnknown, "10.10.0.9", ""))
	if want := []controller.NodeGeneration{{Name: "newcomer", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the apply changed %+v, want %+v: the nodes that were admitted are not touched", res.Nodes, want)
	}
	newcomer := h.sim("newcomer", keyUnknown)
	checkRefusal(t, "newcomer", refuseOf(t, newcomer), `Node "newcomer" waits for an administrator to approve it in Network "corp-lan"`)
	noUpdate(t, bob)
	noUpdate(t, files)
	infos := h.nodeKeys()
	if k := infos["newcomer"]; k.State != controller.KeyPending || k.Network != "corp-lan" || k.Approved || k.ApprovedBy != "" {
		t.Errorf("the key of newcomer is %+v, want it pending in corp-lan and not approved", k)
	}
	for _, name := range []string{"alice-laptop", "bob-laptop", "files"} {
		if k := infos[name]; k.State != controller.KeyValid || !k.Approved {
			t.Errorf("the key of %s is %+v, want it valid and approved: it was admitted before the Network held new nodes", name, k)
		}
	}
	newcomer.start(h)
	checkRefusal(t, "newcomer", refuseOf(t, newcomer), `Node "newcomer" waits for an administrator to approve it in Network "corp-lan"`)

	// An operator approves it: it is admitted, the others get it as a peer, and it opens its stream at its next try
	ops := h.auditedAPI(h.token("ops-1", rbac.Operator))
	info, err := ops.ApproveNode(ctx, "newcomer")
	if err != nil {
		t.Fatal(err)
	}
	if info.State != controller.KeyValid || !info.Approved || info.ApprovedBy != audit.ActorToken("ops-1") || info.ApprovedAt.IsZero() || info.Network != "" {
		t.Errorf("the approval of newcomer answered %+v, want a valid key that token:ops-1 approved", info)
	}
	for _, s := range []*sim{bob, files} {
		u := s.update(t).GetUpdate()
		if u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 {
			t.Errorf("%s got the update %s when newcomer was approved, want generation 2 on 1", s.name, show(u))
		}
		h.waitNode(s.name, 2, true)
		h.checkState(s)
	}
	newcomer.start(h)
	if u := newcomer.update(t).GetUpdate(); u.GetGeneration() != 1 || u.GetBaseGeneration() != 0 {
		t.Errorf("newcomer got the update %s when it connected after its approval, want the full state at generation 1", show(u))
	}
	h.waitNode("newcomer", 1, true)
	h.checkState(newcomer)

	// A second approval leaves the first as it is, and a node that does not exist cannot be approved
	again, err := ops.ApproveNode(ctx, "newcomer")
	if err != nil || !again.ApprovedAt.Equal(info.ApprovedAt) || again.ApprovedBy != info.ApprovedBy || !again.Refreshed.Equal(info.Refreshed) {
		t.Errorf("a second approval of newcomer gave %+v (%v), want the first, %+v", again, err, info)
	}
	if _, err := ops.ApproveNode(ctx, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("the approval of a node that does not exist gave %v, want 404", err)
	}
}

// Turning on approval cuts off no node that was admitted, a node that joins while it is on waits, and the Network that
// admits at once again admits the nodes that waited: a node is admitted when no Network of its VRFs holds it.
func TestChangingTheApprovalModeAffectsOnlyTheNodesThatJoinAfter(t *testing.T) {
	h, _ := newKeysHarness(t)
	h.apply("nodekeys.json")
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	h.connect(t, bob, files)

	if res := h.applyJSON(keysNetwork(`, "approval": "manual"`)); len(res.Nodes) != 0 {
		t.Errorf("turning on the approval changed the states of %+v, want none", res.Nodes)
	}
	noUpdate(t, bob)
	noUpdate(t, files)
	for name, k := range h.nodeKeys() {
		if k.State != controller.KeyValid || !k.Approved {
			t.Errorf("the key of %s is %+v after the approval was turned on, want it valid and approved", name, k)
		}
	}

	h.applyJSON(keysNode("newcomer", keyUnknown, "10.10.0.9", ""))
	newcomer := h.sim("newcomer", keyUnknown)
	refuseOf(t, newcomer)
	checkKeyState(t, h.nodeKeys(), "newcomer", controller.KeyPending)

	h.applyJSON(keysNetwork(`, "approval": "auto"`))
	for _, s := range []*sim{bob, files} {
		if u := s.update(t).GetUpdate(); u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 {
			t.Errorf("%s got the update %s when the Network admitted newcomer, want generation 2 on 1", s.name, show(u))
		}
		h.waitNode(s.name, 2, true)
	}
	if k := h.nodeKeys()["newcomer"]; k.State != controller.KeyValid || !k.Approved || k.ApprovedBy != audit.ActorSystem {
		t.Errorf("the key of newcomer is %+v after the Network admitted it, want it valid and approved by the system", k)
	}
	newcomer.start(h)
	newcomer.update(t)
	h.waitNode("newcomer", 1, true)
	h.checkState(newcomer)
}

// An admin marks a server nonExpiring: its key has no end, while the keys of the nodes of users end. Taking the mark off
// starts a period from that moment, not one that has ended already.
func TestANodeMarkedNonExpiringKeepsItsKey(t *testing.T) {
	h, clk := newKeysHarness(t)
	start := clk.Now()
	h.apply("nodekeys.json")
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	h.connect(t, bob, files)

	if res := h.applyJSON(keysNode("files", keyLab1, "10.10.0.3", `, "nonExpiring": true`)); len(res.Nodes) != 0 {
		t.Errorf("marking files nonExpiring changed the states of %+v, want none", res.Nodes)
	}
	if k := h.nodeKeys()["files"]; k.State != controller.KeyValid || !k.NonExpiring || !k.Expires.IsZero() {
		t.Errorf("the key of files is %+v, want a valid key with no end", k)
	}

	// On day 200 the keys of the nodes of users have ended, and the key of files has not
	clk.Advance(200 * keyDay)
	ended := start.Add(90 * keyDay)
	checkRefusal(t, "bob-laptop", refuseOf(t, bob), expiredMessage("bob-laptop", ended, true))
	u := files.update(t).GetUpdate()
	if got := removedPeers(u); u.GetGeneration() != 2 || !slices.Equal(got, []string{"alice-laptop", "bob-laptop"}) {
		t.Errorf("files got the update %s on day 200, want generation 2 that removes the peers alice-laptop and bob-laptop", show(u))
	}
	h.waitNode("files", 2, true)
	checkKeyState(t, h.nodeKeys(), "files", controller.KeyValid)

	// Without the mark its key lives 90 days from now: it does not end at once, and it ends then
	h.applyJSON(keysNode("files", keyLab1, "10.10.0.3", ""))
	if k := h.nodeKeys()["files"]; k.State != controller.KeyValid || k.NonExpiring || !k.Expires.Equal(start.Add(290*keyDay)) {
		t.Errorf("the key of files is %+v after the mark was taken off on day 200, want it valid until day 290", k)
	}
	clk.Advance(80 * keyDay)
	noUpdate(t, files)
	clk.Advance(11 * keyDay)
	checkRefusal(t, "files", refuseOf(t, files), expiredMessage("files", start.Add(290*keyDay), false))
}

// A Network sets how many days the keys of its nodes live, and a change of that moves no key that exists: a key lives for
// the period that it was given when it was refreshed.
func TestKeyLifetimeFollowsTheNetwork(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.applyJSON(keysVRF, keysNetwork(`, "keyLifetimeDays": 7`), keysNode("files", keyLab1, "10.10.0.3", ""))
	files := h.sim("files", keyLab1)
	h.connect(t, files)
	if k := h.nodeKeys()["files"]; !k.Expires.Equal(start.Add(7 * keyDay)) {
		t.Errorf("the key of files is %+v in a Network of 7 days, want it to end on day 7", k)
	}

	clk.Advance(6 * keyDay)
	h.applyJSON(keysNetwork(`, "keyLifetimeDays": 30`))
	noUpdate(t, files)
	if k := h.nodeKeys()["files"]; k.State != controller.KeyValid || !k.Expires.Equal(start.Add(7*keyDay)) {
		t.Errorf("the key of files is %+v after the Network changed to 30 days on day 6, want it to end on day 7 still", k)
	}

	clk.Advance(2 * keyDay)
	checkRefusal(t, "files", refuseOf(t, files), expiredMessage("files", start.Add(7*keyDay), false))
	k, err := h.api.RefreshNodeKey(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	if !k.Refreshed.Equal(start.Add(8*keyDay)) || !k.Expires.Equal(start.Add(38*keyDay)) {
		t.Errorf("the key of files is %+v after it was refreshed on day 8 in a Network of 30 days, want it to end on day 38", k)
	}
	files.start(h)
	h.waitNode("files", 1, true)
}

// The lives of the keys are in the store, outside the intent: a restart of the controller and of its store keeps who was
// approved and who was not and when each key ends, and no change of the intent gives a key that ended another life. The
// store keeps the life of a key that no node holds any more, with when the key ends and without the approval, which went
// with its node: a rollback that makes the node again, a delete and a new apply of it, and another key and then its own
// key again all leave the key ended, and a Network that holds new nodes for approval holds the node again. Only the login
// of its user gives the key another life.
func TestTheLivesOfTheKeysSurviveARestartAndAreNotPartOfTheIntent(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys-manual.json")
	h.setPasswords("alice", "bob")
	for _, name := range []string{"alice-laptop", "bob-laptop", "files"} {
		checkKeyState(t, h.nodeKeys(), name, controller.KeyPending)
	}
	for _, name := range []string{"alice-laptop", "bob-laptop"} {
		if _, err := h.api.ApproveNode(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(60 * keyDay)
	if err := h.reauthenticate("bob", "a good password", keyBranch2); err != nil {
		t.Fatal(err)
	}
	clk.Advance(31 * keyDay)
	before := h.nodeKeys()
	checkKeyState(t, before, "alice-laptop", controller.KeyExpired)
	checkKeyState(t, before, "bob-laptop", controller.KeyValid)
	checkKeyState(t, before, "files", controller.KeyPending)

	h.stop()
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	after := h.nodeKeys()
	for _, name := range []string{"alice-laptop", "bob-laptop", "files"} {
		b, a := before[name], after[name]
		if a.State != b.State || a.Approved != b.Approved || a.ApprovedBy != b.ApprovedBy || !a.ApprovedAt.Equal(b.ApprovedAt) || !a.Refreshed.Equal(b.Refreshed) || !a.Expires.Equal(b.Expires) {
			t.Errorf("the key of %s is %+v after the restart, want %+v as before", name, a, b)
		}
	}
	if k := after["bob-laptop"]; !k.Expires.Equal(start.Add(150 * keyDay)) {
		t.Errorf("the key of bob-laptop is %+v after the restart, want it to end on day 150", k)
	}
	alice := h.sim("alice-laptop", keyBranch1)
	files := h.sim("files", keyLab1)
	bob := h.sim("bob-laptop", keyBranch2)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", start.Add(90*keyDay), true))
	checkRefusal(t, "files", refuseOf(t, files), `Node "files" waits for an administrator to approve it in Network "corp-lan"`)
	bob.update(t)
	h.checkStateWithout(bob, "alice-laptop", "files")

	// alice-laptop is deleted: the store keeps the life of its key, with the end of the key and without the approval of the node
	if _, err := h.api.Delete(ctx, intent.KindNode, "alice-laptop"); err != nil {
		t.Fatal(err)
	}
	ended := start.Add(90 * keyDay)
	if k, ok := h.storedKeyLife(keyBranch1); !ok || k.Approved || k.ApprovedBy != "" || !k.ApprovedAt.IsZero() || !k.Expires.Equal(ended) {
		t.Errorf("the store keeps the life %+v (%v) for the key of alice-laptop once the node is deleted, want the key that ended on day 90, not approved", k, ok)
	}

	// A rollback to revision 1, which holds alice-laptop, makes it again: its key gets no new life, and the Network, which
	// holds new nodes for approval, holds it again
	if _, err := h.api.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyPending || k.Approved || k.ApprovedBy != "" || !k.Refreshed.Equal(start) || !k.Expires.Equal(ended) {
		t.Errorf("the key of alice-laptop is %+v after the rollback made the node again on day 91, want the key that ended on day 90, waiting for approval", k)
	}
	alice.start(h)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), `Node "alice-laptop" waits for an administrator to approve it in Network "corp-lan"`)
	noUpdate(t, bob)

	// files is approved, and the Network admits at once again: alice-laptop is admitted, with the key that ended on day 90
	if _, err := h.api.ApproveNode(ctx, "files"); err != nil {
		t.Fatal(err)
	}
	bob.update(t)
	h.applyJSON(keysNetwork(`, "approval": "auto"`))
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyExpired || !k.Approved || k.ApprovedBy != audit.ActorSystem || !k.Expires.Equal(ended) {
		t.Errorf("the key of alice-laptop is %+v once its Network admits at once, want it admitted by the system with the key that ended on day 90", k)
	}
	alice.start(h)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", ended, true))

	// Deleting the node and making it again gives its key no new life either, and nor does another key and then its own key
	// again; the other key is a new key, which lives from now
	if _, err := h.api.Delete(ctx, intent.KindNode, "alice-laptop"); err != nil {
		t.Fatal(err)
	}
	h.applyJSON(keysNode("alice-laptop", keyBranch1, "10.10.0.1", `, "owner": "alice"`))
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyExpired || !k.Expires.Equal(ended) {
		t.Errorf("the key of alice-laptop is %+v after the node was deleted and made again on day 91, want the key that ended on day 90", k)
	}
	h.applyJSON(keysNode("alice-laptop", keyUnknown, "10.10.0.1", `, "owner": "alice"`))
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyValid || !k.Expires.Equal(start.Add(181*keyDay)) {
		t.Errorf("the key of alice-laptop is %+v after the node got another key on day 91, want that key valid until day 181", k)
	}
	bob.update(t)
	h.applyJSON(keysNode("alice-laptop", keyBranch1, "10.10.0.1", `, "owner": "alice"`))
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyExpired || !k.Expires.Equal(ended) {
		t.Errorf("the key of alice-laptop is %+v after the node got its own key back on day 91, want the key that ended on day 90", k)
	}
	bob.update(t)
	h.checkStateWithout(bob, "alice-laptop")

	// Only the login of alice gives the key another life
	if err := h.reauthenticate("alice", "a good password", keyBranch1); err != nil {
		t.Fatal(err)
	}
	if k := h.nodeKeys()["alice-laptop"]; k.State != controller.KeyValid || !k.Refreshed.Equal(start.Add(91*keyDay)) || !k.Expires.Equal(start.Add(181*keyDay)) {
		t.Errorf("the key of alice-laptop is %+v after her login on day 91, want it valid until day 181", k)
	}
	bob.update(t)
	h.checkState(bob)
}

// storedKeyLife returns the life that the store keeps for the static key key, and whether it keeps one.
func (h *harness) storedKeyLife(key keys.Static) (store.NodeKey, bool) {
	h.t.Helper()
	stored, err := h.st.NodeKeys(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, k := range stored {
		if bytes.Equal(k.Key, key.Public()) {
			return k, true
		}
	}
	return store.NodeKey{}, false
}

// TestNodeKeyOperationsAreAuditedAndNeedTheOperatorRole: the operations on the keys of the nodes are recorded in the audit
// log, once, with their actor, what they were done to and how they ended, a call that is refused for its role is no
// operation, and the refusal of a node whose key ended is a failed authentication.
func TestNodeKeyOperationsAreAuditedAndNeedTheOperatorRole(t *testing.T) {
	h, clk := newKeysHarness(t)
	ctx := context.Background()
	start := clk.Now()
	h.apply("nodekeys.json")
	h.applyJSON(keysNetwork(`, "approval": "manual"`), keysNode("newcomer", keyUnknown, "10.10.0.9", ""))
	since := time.Now().Add(-time.Second)
	ops := h.auditedAPI(h.token("ops-1", rbac.Operator))
	viewer := h.auditedAPI(h.token("viewer-1", rbac.Viewer))

	type step struct {
		action, subject, outcome, message string
		do                                func() error
	}
	steps := []step{
		{"node-key-list", "node keys", audit.Success, "node keys listed: 4", func() error { _, err := ops.NodeKeys(ctx); return err }},
		{"node-approve", "node newcomer", audit.Success, "the key of node newcomer is valid and ends at", func() error { _, err := ops.ApproveNode(ctx, "newcomer"); return err }},
		{"node-approve", "node nobody", audit.Failure, "no such resource", func() error { _, err := ops.ApproveNode(ctx, "nobody"); return httpErr(err, http.StatusNotFound) }},
		{"node-key-refresh", "node files", audit.Success, "the key of node files is valid and ends at", func() error { _, err := ops.RefreshNodeKey(ctx, "files"); return err }},
		{"node-key-refresh", "node alice-laptop", audit.Failure, "refreshes it by logging in again", func() error {
			_, err := ops.RefreshNodeKey(ctx, "alice-laptop")
			return httpErr(err, http.StatusConflict)
		}},
		{"node-key-refresh", "node nobody", audit.Failure, "no such resource", func() error { _, err := ops.RefreshNodeKey(ctx, "nobody"); return httpErr(err, http.StatusNotFound) }},
	}
	for i, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("step %d, %s: %v", i, s.action, err)
		}
	}

	// A call that is refused for its role, or for having no token, is no operation
	for _, caller := range []struct {
		who  string
		c    *api.Client
		want int
	}{{"a viewer", viewer, http.StatusForbidden}, {"no token", h.auditedAPI(""), http.StatusUnauthorized}} {
		if _, err := caller.c.NodeKeys(ctx); httpStatus(err) != caller.want {
			t.Errorf("%s listing the keys gave %v, want %d", caller.who, err, caller.want)
		}
		if _, err := caller.c.ApproveNode(ctx, "files"); httpStatus(err) != caller.want {
			t.Errorf("%s approving a node gave %v, want %d", caller.who, err, caller.want)
		}
		if _, err := caller.c.RefreshNodeKey(ctx, "files"); httpStatus(err) != caller.want {
			t.Errorf("%s refreshing a key gave %v, want %d", caller.who, err, caller.want)
		}
	}

	// The refusal of a node whose key ended is a failed authentication of that node, from the address it came from
	clk.Advance(91 * keyDay)
	alice := h.sim("alice-laptop", keyBranch1)
	checkRefusal(t, "alice-laptop", refuseOf(t, alice), expiredMessage("alice-laptop", start.Add(90*keyDay), true))
	refused := func(rs []audit.Record) *audit.Record {
		for i, r := range rs {
			if r.Kind == audit.AuthFailed && r.Actor == audit.ActorNode("alice-laptop") {
				return &rs[i]
			}
		}
		return nil
	}
	// The controller records the Events that it raises for the keys as operations of the system (nodekeys_events_test.go), which are
	// not the calls of the operator that this test counts
	recs := h.waitAudit(ops, "a record of each operation and of the refusal of alice-laptop", func(rs []audit.Record) bool {
		return len(operationsBy(rs, audit.ActorToken("ops-1"))) >= len(steps) && refused(rs) != nil
	})
	operations := operationsBy(recs, audit.ActorToken("ops-1"))
	if len(operations) != len(steps) {
		t.Fatalf("the audit log holds %d operations of ops-1, want %d, one for each call that was served:\n%s", len(operations), len(steps), auditLines(recs))
	}
	for i, s := range steps {
		r := operations[i]
		checkAuditRecord(t, r, since, audit.ActorToken("ops-1"), "127.0.0.1", s.outcome, s.action, 0)
		if r.Subject != s.subject || !strings.Contains(r.Message, s.message) {
			t.Errorf("the operation %d is %+v, want the subject %q and a message that says %q", i, r, s.subject, s.message)
		}
	}
	r := refused(recs)
	checkAuditRecord(t, *r, since, audit.ActorNode("alice-laptop"), "127.0.0.1", audit.Failure, "", 0)
	if want := expiredMessage("alice-laptop", start.Add(90*keyDay), true); r.Message != want {
		t.Errorf("the refusal of alice-laptop is recorded with the message %q, want %q", r.Message, want)
	}
}
