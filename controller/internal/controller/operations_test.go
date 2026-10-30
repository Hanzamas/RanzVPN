// Controller conformance for the live operations (SDN-50 #243, ADR-0031 amendment of 2026-10-27), with
// the harness and the node simulator of conformance_test.go: an operator lists the sessions, ends one,
// bans and unbans a user, and reads and clears the MAC table and the IP table of an L2 Network. Each
// call works within the role of its caller and is refused outside it; a user that is kicked or banned
// is cut off at once; and every operation is in the audit log, once. The nodes that answer the tables
// are simulated nodes that report the Capability operations (nodesim.Tables).
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// capsOperations is capsServer with the Capability operations: a node that answers the requests of an
// operator for the tables of its L2 Networks.
var capsOperations = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
	HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT, Operations: true}

// operationTimeout is how long the controller of newOperationsHarness waits for the answer of a node.
const operationTimeout = time.Second

// scripted answers the Operations of a simulated node as its test says: from its Tables, with a failure,
// or not at all, like a node that is too slow.
type scripted struct {
	nodesim.Tables
	mu   sync.Mutex
	mode string // "" answers from the tables, "fail" with a failure, "mute" with nothing
}

// setMode makes the node answer as mode says from now on.
func (s *scripted) setMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// handle is the OperationHandler of the node.
func (s *scripted) handle(op *controlpb.Operation) *controlpb.OperationResult {
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	switch mode {
	case "mute":
		return nil
	case "fail":
		return &controlpb.OperationResult{Id: op.GetId(), Status: controlpb.OperationStatus_OPERATION_STATUS_FAILED, Message: "the switch is down"}
	}
	return s.Handle(op)
}

// newOperationsHarness returns a harness whose controller waits operationTimeout for the answer of a node.
func newOperationsHarness(t *testing.T) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) { c.OperationTimeout = operationTimeout }}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

// opSim returns a simulated node that reports the Capability operations and answers the Operations of the
// controller as the returned scripted node says; it has no stream yet, start runs one.
func (h *harness) opSim(name string, key keys.Static) (*sim, *scripted) {
	s := h.newSim(name, key)
	sc := &scripted{}
	s.Capabilities = capsOperations
	s.Operations = sc.handle
	return s, sc
}

// sessions returns the sessions that the API lists for the user and the node that are given.
func (h *harness) sessions(user, node string) []controller.Session {
	h.t.Helper()
	l, err := h.api.Sessions(context.Background(), user, node)
	if err != nil {
		h.t.Fatal(err)
	}
	return l
}

// sessionOf returns the session of the node name, which must have one.
func (h *harness) sessionOf(name string) controller.Session {
	h.t.Helper()
	l := h.sessions("", name)
	if len(l) != 1 {
		h.t.Fatalf("the controller lists %d sessions of node %s, want 1: %+v", len(l), name, l)
	}
	return l[0]
}

// checkStateWithout checks that the state that the simulated node s built from its updates is the full
// state that the controller's intent compiles to for it without the Nodes banned, which no Node has as a
// Peer while their user is banned.
func (h *harness) checkStateWithout(s *sim, banned ...string) {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		h.t.Fatal(err)
	}
	lic, err := h.api.Licence(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	states, err := desired.Compile(in.Capped(lic.Nodes).Without(banned))
	if err != nil {
		h.t.Fatal(err)
	}
	gen, got := s.State()
	if want := states[s.name]; !desired.Equal(got, want) {
		h.t.Errorf("%s: the state at generation %d differs from the compiled intent without %v:\n--- node\n%s\n--- intent\n%s",
			s.name, gen, banned, show(desired.Full(got, gen)), show(desired.Full(want, gen)))
	}
}

// operationsOf returns the Operations that s received from the controller, in order.
func operationsOf(s *sim) []*controlpb.Operation {
	var out []*controlpb.Operation
	for _, m := range received(s) {
		if op := m.GetOperation(); op != nil {
			out = append(out, op)
		}
	}
	return out
}

// waitOperations waits until s has received n Operations, and returns them.
func waitOperations(t *testing.T, s *sim, n int) []*controlpb.Operation {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if ops := operationsOf(s); len(ops) >= n {
			return ops
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not receive %d Operations within %v", s.name, n, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// refuseOf waits for the controller to refuse the node s and returns the Refuse.
func refuseOf(t *testing.T, s *sim) *controlpb.Refuse {
	t.Helper()
	return s.refusal(t).GetRefuse()
}

// sessionNames returns the names of the nodes of sessions.
func sessionNames(sessions []controller.Session) []string {
	names := make([]string, len(sessions))
	for i, s := range sessions {
		names[i] = s.Node
	}
	return names
}

// TestSessionsListUserNodeAddressesAndTraffic is the listing of the sessions of SDN-50: each session has its
// user, its node, the address that it came from, the addresses of the node, its VRFs and the traffic that the
// node reported. The list narrows to a user or a node, and a node that left is no session.
func TestSessionsListUserNodeAddressesAndTraffic(t *testing.T) {
	h := newOperationsHarness(t)
	h.apply("operations.json")
	if got := h.sessions("", ""); len(got) != 0 {
		t.Fatalf("the controller lists the sessions %+v before a node connected, want none", got)
	}

	started := time.Now().Add(-time.Second)
	alice, _ := h.opSim("alice-laptop", keyBranch1)
	alice.start(h)
	bob := h.sim("bob-laptop", keyBranch2)
	h.sim("files", keyLab1)
	for _, name := range []string{"alice-laptop", "bob-laptop", "files"} {
		h.waitNode(name, 1, true)
	}
	if err := alice.Telemetry(&controlpb.Telemetry{Vrfs: []*controlpb.VrfCounters{{VrfId: 10, TxPackets: 3, TxBytes: 300, RxPackets: 2, RxBytes: 200}}}); err != nil {
		t.Fatal(err)
	}
	h.waitTelemetry("alice-laptop")

	sessions := h.sessions("", "")
	if names := sessionNames(sessions); !slices.Equal(names, []string{"alice-laptop", "bob-laptop", "files"}) {
		t.Fatalf("the sessions are of the nodes %v, want alice-laptop, bob-laptop and files in that order", names)
	}
	idForm := regexp.MustCompile(`^[0-9a-f]{16}$`)
	ids := map[string]bool{}
	for _, s := range sessions {
		if !idForm.MatchString(s.ID) || ids[s.ID] {
			t.Errorf("the session of %s has the id %q, want 16 hex digits that no other session has", s.Node, s.ID)
		}
		ids[s.ID] = true
		if s.Source != "127.0.0.1" || s.Since.Before(started) || s.Since.After(time.Now()) || !slices.Equal(s.VRFs, []string{"corp"}) ||
			s.Generation != 1 || s.AckedGeneration != 1 {
			t.Errorf("the session of %s is %+v, want it from 127.0.0.1 since the node connected, in the VRF corp at generation 1", s.Node, s)
		}
	}
	a, b, f := sessions[0], sessions[1], sessions[2]
	if a.User != "alice" || !slices.Equal(a.Addresses, []string{"10.10.0.1"}) || !a.Operations ||
		a.TxPackets != 3 || a.TxBytes != 300 || a.RxPackets != 2 || a.RxBytes != 200 || a.TrafficReported.IsZero() {
		t.Errorf("the session of alice-laptop is %+v, want the user alice, its address and the traffic it reported", a)
	}
	if b.User != "bob" || !slices.Equal(b.Addresses, []string{"10.10.0.2"}) || b.Operations || b.TxBytes != 0 || b.RxBytes != 0 || !b.TrafficReported.IsZero() {
		t.Errorf("the session of bob-laptop is %+v, want the user bob, its address, no operations and no traffic", b)
	}
	if f.User != "" || !slices.Equal(f.Addresses, []string{"10.10.0.3"}) {
		t.Errorf("the session of files is %+v, want no user and its address", f)
	}

	for _, c := range []struct {
		user, node string
		want       []string
	}{
		{"alice", "", []string{"alice-laptop"}},
		{"", "files", []string{"files"}},
		{"alice", "files", []string{}},
		{"nobody", "", []string{}},
		{"", "lab-box", []string{}},
	} {
		if got := sessionNames(h.sessions(c.user, c.node)); !slices.Equal(got, c.want) {
			t.Errorf("the sessions of user %q and node %q are of %v, want %v", c.user, c.node, got, c.want)
		}
	}

	bob.halt()
	h.waitNode("bob-laptop", 1, false)
	if names := sessionNames(h.sessions("", "")); !slices.Equal(names, []string{"alice-laptop", "files"}) {
		t.Errorf("the sessions after bob-laptop left are of %v, want alice-laptop and files", names)
	}
}

// TestDisconnectEndsASessionAtOnce is the kick of the second criterion: the session that an operator names
// ends at once, the node is told why, and the controller no longer lists it as connected before the call
// returns. The node is not kept off: it connects again, with a session of its own. A session that does not
// exist, or ended, is 404, and the sessions of a user end together.
func TestDisconnectEndsASessionAtOnce(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice := h.sim("alice-laptop", keyBranch1)
	bob := h.sim("bob-laptop", keyBranch2)
	for _, s := range []*sim{alice, bob} {
		s.update(t)
		h.waitNode(s.name, 1, true)
	}

	first := h.sessionOf("alice-laptop")
	ended, err := h.api.Disconnect(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.ID != first.ID || ended.Node != "alice-laptop" || ended.User != "alice" {
		t.Errorf("the disconnect answered with the session %+v, want the one that ended: %+v", ended, first)
	}
	if n := h.node("alice-laptop"); n.Connected {
		t.Errorf("alice-laptop is still connected when the disconnect has returned: %+v", n)
	}
	refused := refuseOf(t, alice)
	if refused.GetReason() != controlpb.RefuseReason_REFUSE_REASON_OPERATOR || refused.GetMessage() != "an operator disconnected this session" {
		t.Errorf("alice-laptop was refused with %s %q, want the reason OPERATOR and the message that an operator ended the session", refused.GetReason(), refused.GetMessage())
	}
	if got := sessionNames(h.sessions("", "")); !slices.Equal(got, []string{"bob-laptop"}) {
		t.Errorf("the sessions after the disconnect are of %v, want bob-laptop alone", got)
	}
	if n := h.node("bob-laptop"); !n.Connected || n.Generation != 1 {
		t.Errorf("a disconnect of alice-laptop changed bob-laptop: %+v", n)
	}

	// The same id again, and one that never was, name no session
	for _, id := range []string{first.ID, "0123456789abcdef"} {
		if _, err := h.api.Disconnect(ctx, id); httpStatus(err) != http.StatusNotFound {
			t.Errorf("disconnecting the session %q gave %v, want 404", id, err)
		}
	}

	// The node dials again, as a node does, and is a session of its own
	alice.start(h)
	h.waitNode("alice-laptop", 1, true)
	if second := h.sessionOf("alice-laptop"); second.ID == first.ID {
		t.Errorf("the session of alice-laptop after it connected again has the id of the one that ended: %s", second.ID)
	}

	// Every session of a user ends together; a user with none is no error, and one that does not exist is 404
	gone, err := h.api.DisconnectUser(ctx, "alice")
	if err != nil || len(gone) != 1 || gone[0].Node != "alice-laptop" {
		t.Fatalf("disconnecting the user alice gave %+v, %v, want the session of alice-laptop", gone, err)
	}
	if refused := refuseOf(t, alice); refused.GetReason() != controlpb.RefuseReason_REFUSE_REASON_OPERATOR {
		t.Errorf("alice-laptop was refused with %s after its user was disconnected, want OPERATOR", refused.GetReason())
	}
	if gone, err := h.api.DisconnectUser(ctx, "carol"); err != nil || len(gone) != 0 {
		t.Errorf("disconnecting the user carol, who has no node, gave %+v, %v, want no session and no error", gone, err)
	}
	if _, err := h.api.DisconnectUser(ctx, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("disconnecting a user that does not exist gave %v, want 404", err)
	}
	if n := h.node("bob-laptop"); !n.Connected {
		t.Errorf("bob-laptop was disconnected with the user alice: %+v", n)
	}
}

// TestBanCutsAUserOffAtOnce is the ban of the second criterion. The Nodes of the banned user are
// disconnected at once and refused when they dial again, the other Nodes get a generation that has no Peer
// for them, and a change of the intent that adds another Node of the user leaves it out too. A login of the
// user is refused. Lifting the ban gives the other Nodes their Peers back and lets the user's Nodes in
// again, on the generations that they applied before, so that they receive what they missed.
func TestBanCutsAUserOffAtOnce(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice := h.sim("alice-laptop", keyBranch1)
	bob := h.sim("bob-laptop", keyBranch2)
	files := h.sim("files", keyLab1)
	for _, s := range []*sim{alice, bob, files} {
		s.update(t)
		h.waitNode(s.name, 1, true)
	}
	if err := h.c.SetUserPassword(ctx, "alice", "a good password"); err != nil {
		t.Fatal(err)
	}

	res, err := h.api.Ban(ctx, "alice", "stolen laptop")
	if err != nil {
		t.Fatal(err)
	}
	if res.User != "alice" || res.Reason != "stolen laptop" || res.By == "" || res.Since.IsZero() || len(res.Disconnected) != 1 || res.Disconnected[0].Node != "alice-laptop" {
		t.Errorf("the ban answered with %+v, want the ban of alice for the reason that was given and the session of alice-laptop that it ended", res)
	}
	refused := refuseOf(t, alice)
	if refused.GetReason() != controlpb.RefuseReason_REFUSE_REASON_OPERATOR || refused.GetMessage() != `User "alice" is banned: stolen laptop` {
		t.Errorf("alice-laptop was refused with %s %q, want the reason OPERATOR and the message that names the user and the reason", refused.GetReason(), refused.GetMessage())
	}
	for _, s := range []*sim{bob, files} {
		u := s.update(t).GetUpdate()
		gone := false
		for _, k := range u.GetRemove() {
			gone = gone || (k.GetKind() == controlpb.Kind_KIND_PEER && k.GetName() == "alice-laptop")
		}
		if u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 || !gone {
			t.Errorf("%s got the update %s after the ban, want generation 2 that removes the Peer alice-laptop", s.name, show(u))
		}
		h.waitNode(s.name, 2, true)
		h.checkStateWithout(s, "alice-laptop")
	}
	if n := h.node("alice-laptop"); !n.Banned || n.Connected || n.Unlicensed {
		t.Errorf("alice-laptop is %+v after the ban, want it banned and not connected", n)
	}
	if n := h.node("bob-laptop"); n.Banned {
		t.Errorf("bob-laptop is %+v, want it not banned", n)
	}

	// The node dials again and is refused again, and a login of the user is refused too, with the right password only
	alice.start(h)
	if refused := refuseOf(t, alice); refused.GetReason() != controlpb.RefuseReason_REFUSE_REASON_OPERATOR || !strings.Contains(refused.GetMessage(), `User "alice" is banned`) {
		t.Errorf("alice-laptop was refused with %s %q when it dialled again, want the reason OPERATOR and the ban", refused.GetReason(), refused.GetMessage())
	}
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "alice", Password: "a good password"}); !errors.Is(err, controller.ErrUserBanned) {
		t.Errorf("a login of the banned user gave %v, want ErrUserBanned", err)
	}
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "alice", Password: "a wrong password"}); !errors.Is(err, controller.ErrBadCredentials) {
		t.Errorf("a login of the banned user with a wrong password gave %v, want ErrBadCredentials, which tells nothing of the ban", err)
	}

	// The ban is listed, and a second ban of the user leaves the first as it is
	bans, err := h.api.Bans(ctx)
	if err != nil || len(bans) != 1 || bans[0].User != "alice" || bans[0].Reason != "stolen laptop" || !bans[0].Since.Equal(res.Since) || bans[0].By != res.By {
		t.Errorf("the bans are %+v (%v), want the ban of alice that was made", bans, err)
	}
	again, err := h.api.Ban(ctx, "alice", "another reason")
	if err != nil || again.Reason != "stolen laptop" || !again.Since.Equal(res.Since) || len(again.Disconnected) != 0 {
		t.Errorf("a second ban of alice gave %+v (%v), want the first ban and no session", again, err)
	}

	// A new device of the banned user is left out as well: the other Nodes get nothing of it
	phone := fmt.Sprintf(`{"resources": [{"kind": "Node", "name": "alice-phone", "spec": {"publicKey": %q, "vrfs": ["corp"], "owner": "alice"}}]}`,
		base64.StdEncoding.EncodeToString(keyUnknown.Public()))
	doc, err := intent.ParseDocument([]byte(phone))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := h.api.Apply(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "alice-laptop", Generation: 2}, {Name: "alice-phone", Generation: 1}}; !equalGenerations(applied.Nodes, want) {
		t.Errorf("an apply of a Node of the banned user changed %+v, want %+v: the Nodes of other users are left alone", applied.Nodes, want)
	}
	if n := h.node("bob-laptop"); n.Generation != 2 {
		t.Errorf("bob-laptop is at generation %d after an apply of a Node of the banned user, want 2", n.Generation)
	}

	// Lifting the ban: the other Nodes get their Peers back, and the user's Node the update it missed
	lifted, err := h.api.Unban(ctx, "alice")
	if err != nil || lifted.User != "alice" || !lifted.Since.Equal(res.Since) {
		t.Errorf("lifting the ban gave %+v (%v), want the ban that was lifted", lifted, err)
	}
	for _, s := range []*sim{bob, files} {
		u := s.update(t).GetUpdate()
		if u.GetGeneration() != 3 || u.GetBaseGeneration() != 2 {
			t.Errorf("%s got the update %s after the ban was lifted, want generation 3 on 2", s.name, show(u))
		}
		h.waitNode(s.name, 3, true)
		h.checkState(s)
	}
	if n := h.node("alice-laptop"); n.Banned {
		t.Errorf("alice-laptop is %+v after the ban was lifted, want it not banned", n)
	}
	alice.start(h)
	if u := alice.update(t).GetUpdate(); u.GetGeneration() != 2 || u.GetBaseGeneration() != 1 {
		t.Errorf("alice-laptop got the update %s when it connected after the ban, want generation 2 on 1, the one that the ban made it miss", show(u))
	}
	h.waitNode("alice-laptop", 2, true)
	h.checkState(alice)
	if _, err := h.c.AuthenticateUser(ctx, controller.Login{User: "alice", Password: "a good password"}); err != nil {
		t.Errorf("a login of the user after the ban was lifted gave %v, want it to work", err)
	}
	if bans, err := h.api.Bans(ctx); err != nil || len(bans) != 0 {
		t.Errorf("the bans after the ban was lifted are %+v (%v), want none", bans, err)
	}

	// What an operator may not ask
	if _, err := h.api.Unban(ctx, "alice"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("lifting a ban that is none gave %v, want 404", err)
	}
	if _, err := h.api.Ban(ctx, "nobody", ""); httpStatus(err) != http.StatusNotFound {
		t.Errorf("banning a user that does not exist gave %v, want 404", err)
	}
	// A reason that is no UTF-8 cannot be sent: JSON has no way to carry it, and the client writes U+FFFD for the
	// byte, so TestCheckBanReason and FuzzCheckBanReason refuse it where the controller checks it
	for _, reason := range []string{"two\nlines", strings.Repeat("x", controller.MaxBanReason+1), "next\u0085line"} {
		if _, err := h.api.Ban(ctx, "carol", reason); httpStatus(err) != http.StatusBadRequest {
			t.Errorf("banning with the reason %q gave %v, want 400", reason, err)
		}
	}
	if bans, err := h.api.Bans(ctx); err != nil || len(bans) != 0 {
		t.Errorf("a ban that was refused left the bans %+v (%v)", bans, err)
	}
}

// A ban is kept in the store: it holds across a restart of the controller and of its store, and the Node
// of the banned user is refused after it. It goes with the user: a user that is deleted and made again is
// not banned.
func TestBanSurvivesARestartAndGoesWithItsUser(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice := h.sim("alice-laptop", keyBranch1)
	alice.update(t)
	h.waitNode("alice-laptop", 1, true)
	if _, err := h.api.Ban(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if refused := refuseOf(t, alice); refused.GetMessage() != `User "alice" is banned` {
		t.Errorf("alice-laptop was refused with %q, want the message that names the user alone", refused.GetMessage())
	}

	h.stop()
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	if bans, err := h.api.Bans(ctx); err != nil || len(bans) != 1 || bans[0].User != "alice" {
		t.Fatalf("the bans after the restart are %+v (%v), want the ban of alice", bans, err)
	}
	alice.start(h)
	if refused := refuseOf(t, alice); refused.GetReason() != controlpb.RefuseReason_REFUSE_REASON_OPERATOR {
		t.Errorf("alice-laptop was refused with %s after the restart, want the reason OPERATOR", refused.GetReason())
	}
	if n := h.node("alice-laptop"); !n.Banned {
		t.Errorf("alice-laptop is %+v after the restart, want it banned", n)
	}

	// carol owns no Node: the ban of a user goes when the user is deleted
	if _, err := h.api.Ban(ctx, "carol", "left"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.DeleteUser(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	if bans, err := h.api.Bans(ctx); err != nil || len(bans) != 1 || bans[0].User != "alice" {
		t.Errorf("the bans after the user carol was deleted are %+v (%v), want the ban of alice alone", bans, err)
	}
	if _, err := h.api.PutUser(ctx, "carol", intent.User{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Unban(ctx, "carol"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a user that was made again under the name of a banned one is banned: lifting its ban gave %v, want 404", err)
	}
}

// tableLine writes the result of one node for a test to compare: how it ended, its total, and each entry as
// its VLAN, MAC address, address and member.
func tableLine(n controller.NodeTable) string {
	entries := make([]string, len(n.Entries))
	for i, e := range n.Entries {
		entries[i] = strings.Join(strings.Fields(fmt.Sprintf("%d %s %s %s", e.VLAN, e.MAC, e.Address, e.Member)), " ")
	}
	return fmt.Sprintf("%s %s total=%d [%s]", n.Node, n.Status, n.Total, strings.Join(entries, "; "))
}

// macEntry returns the entry of the MAC table for the MAC address that ends in last, learnt on the member.
func macEntry(vlan uint32, last byte, member string, seen time.Time) *controlpb.TableEntry {
	e := &controlpb.TableEntry{Vlan: vlan, Mac: []byte{0x02, 0x00, 0x5e, 0x10, 0x00, last}, Member: member}
	if !seen.IsZero() {
		e.LastSeenMs = uint64(seen.UnixMilli())
	}
	return e
}

// ipEntry returns the entry of the IP table for the address, which the MAC address that ends in last used.
func ipEntry(address string, last byte, member string) *controlpb.TableEntry {
	return &controlpb.TableEntry{Mac: []byte{0x02, 0x00, 0x5e, 0x10, 0x00, last}, Address: netip.MustParseAddr(address).AsSlice(), Member: member}
}

// TestTablesReadAndClear is the tables of SDN-50: an operator reads the MAC table and the IP table of an L2
// Network on each node that holds it, or on the node that he names, and clears one entry of them or every
// entry. The nodes are asked with the Operation of the control protocol, each with an id of its own.
func TestTablesReadAndClear(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	seen := time.Date(2026, time.October, 27, 12, 0, 0, 0, time.UTC)
	alice, aliceTables := h.opSim("alice-laptop", keyBranch1)
	bob, bobTables := h.opSim("bob-laptop", keyBranch2)
	files, filesTables := h.opSim("files", keyLab1)
	aliceTables.SetMAC("corp-dmz", macEntry(0, 0x0b, "bob-phone", seen), macEntry(0, 0x0a, "alice-phone", seen), macEntry(20, 0x0c, "lab", time.Time{}))
	aliceTables.SetIP("corp-dmz", ipEntry("10.20.0.10", 0x0b, "bob-phone"), ipEntry("fd00::5", 0x0c, "lab"), ipEntry("10.20.0.9", 0x0a, "alice-phone"))
	bobTables.SetMAC("corp-dmz", macEntry(0, 0x0d, "bob-laptop", seen))
	bobTables.SetIP("corp-dmz")
	filesTables.SetMAC("corp-dmz")
	filesTables.SetIP("corp-dmz")
	for _, s := range []*sim{alice, bob, files} {
		s.start(h)
		h.waitNode(s.name, 1, true)
	}

	// A read asks every node that holds the Network, and lists them by name
	res, err := h.api.MACTable(ctx, "corp-dmz", "")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, n := range res.Nodes {
		lines = append(lines, tableLine(n))
	}
	want := []string{
		"alice-laptop ok total=3 [0 02:00:5e:10:00:0a alice-phone; 0 02:00:5e:10:00:0b bob-phone; 20 02:00:5e:10:00:0c lab]",
		"bob-laptop ok total=1 [0 02:00:5e:10:00:0d bob-laptop]",
		"files ok total=0 []",
	}
	if !slices.Equal(lines, want) || res.Network != "corp-dmz" || res.Table != controller.TableMAC || res.Cleared {
		t.Fatalf("the MAC table of corp-dmz is %+v\n%s\nwant\n%s", res, strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if first, last := res.Nodes[0].Entries[0], res.Nodes[0].Entries[2]; !first.LastSeen.Equal(seen) || !last.LastSeen.IsZero() {
		t.Errorf("the entries of alice-laptop have the last frames %v and %v, want %v for the first and none for the last", first.LastSeen, last.LastSeen, seen)
	}
	only, err := h.api.MACTable(ctx, "corp-dmz", "bob-laptop")
	if err != nil || len(only.Nodes) != 1 || tableLine(only.Nodes[0]) != want[1] {
		t.Errorf("the MAC table on bob-laptop alone is %+v (%v), want %s", only, err, want[1])
	}
	ip, err := h.api.IPTable(ctx, "corp-dmz", "alice-laptop")
	wantIP := "alice-laptop ok total=3 [0 02:00:5e:10:00:0a 10.20.0.9 alice-phone; 0 02:00:5e:10:00:0b 10.20.0.10 bob-phone; 0 02:00:5e:10:00:0c fd00::5 lab]"
	if err != nil || ip.Table != controller.TableIP || len(ip.Nodes) != 1 || tableLine(ip.Nodes[0]) != wantIP {
		t.Errorf("the IP table on alice-laptop is %+v (%v), want %s", ip, err, wantIP)
	}

	// A clear that names an entry removes that one, and says how many it removed
	cleared, err := h.api.ClearMACTable(ctx, "corp-dmz", "alice-laptop", "02:00:5e:10:00:0a")
	if err != nil || !cleared.Cleared || len(cleared.Nodes) != 1 || tableLine(cleared.Nodes[0]) != "alice-laptop ok total=1 []" {
		t.Errorf("clearing one entry of the MAC table gave %+v (%v), want alice-laptop to have removed 1", cleared, err)
	}
	if left := aliceTables.MAC("corp-dmz"); len(left) != 2 || slices.ContainsFunc(left, func(e *controlpb.TableEntry) bool { return e.GetMac()[5] == 0x0a }) {
		t.Errorf("the MAC table of alice-laptop holds %v after one entry was cleared, want the other two", left)
	}
	if cleared, err = h.api.ClearIPTable(ctx, "corp-dmz", "alice-laptop", "::ffff:10.20.0.10"); err != nil || len(cleared.Nodes) != 1 || tableLine(cleared.Nodes[0]) != "alice-laptop ok total=1 []" {
		t.Errorf("clearing an IPv4 address written as an IPv6 one gave %+v (%v), want one entry removed", cleared, err)
	}
	if left := aliceTables.IP("corp-dmz"); len(left) != 2 {
		t.Errorf("the IP table of alice-laptop holds %d entries after one was cleared, want 2", len(left))
	}

	// A clear that names no entry removes them all, on every node that holds the Network
	cleared, err = h.api.ClearMACTable(ctx, "corp-dmz", "", "")
	lines = nil
	for _, n := range cleared.Nodes {
		lines = append(lines, tableLine(n))
	}
	if err != nil || !slices.Equal(lines, []string{"alice-laptop ok total=2 []", "bob-laptop ok total=1 []", "files ok total=0 []"}) {
		t.Errorf("clearing the MAC table on every node gave\n%s (%v)\nwant alice-laptop 2, bob-laptop 1 and files 0", strings.Join(lines, "\n"), err)
	}
	if left := aliceTables.MAC("corp-dmz"); len(left) != 0 {
		t.Errorf("the MAC table of alice-laptop holds %d entries after a clear of every entry", len(left))
	}
	if left := bobTables.MAC("corp-dmz"); len(left) != 0 {
		t.Errorf("the MAC table of bob-laptop holds %d entries after a clear of every entry", len(left))
	}
	if left := aliceTables.IP("corp-dmz"); len(left) != 2 {
		t.Errorf("a clear of the MAC tables changed the IP table of alice-laptop: it holds %d entries, want 2", len(left))
	}

	// What the nodes were sent: an Operation of the right kind for each call, each with an id of its own
	ops := waitOperations(t, alice, 5)
	kinds := []controlpb.OperationKind{
		controlpb.OperationKind_OPERATION_KIND_MAC_TABLE, controlpb.OperationKind_OPERATION_KIND_IP_TABLE,
		controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE, controlpb.OperationKind_OPERATION_KIND_CLEAR_IP_TABLE,
		controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE,
	}
	var got []controlpb.OperationKind
	ids := map[uint64]bool{}
	for _, op := range ops {
		got = append(got, op.GetKind())
		if op.GetId() == 0 || ids[op.GetId()] || op.GetNetwork() != "corp-dmz" {
			t.Errorf("alice-laptop was sent %v with the id %d and the Network %q, want an id of its own and corp-dmz", op.GetKind(), op.GetId(), op.GetNetwork())
		}
		ids[op.GetId()] = true
	}
	if !slices.Equal(got, kinds) {
		t.Fatalf("alice-laptop was sent the Operations %v, want %v", got, kinds)
	}
	if !slices.Equal(ops[2].GetMac(), []byte{0x02, 0x00, 0x5e, 0x10, 0x00, 0x0a}) || len(ops[2].GetAddress()) != 0 {
		t.Errorf("the clear of one MAC address was sent as %v, want the 6 bytes of the address", ops[2])
	}
	if !slices.Equal(ops[3].GetAddress(), netip.MustParseAddr("10.20.0.10").AsSlice()) || len(ops[3].GetMac()) != 0 {
		t.Errorf("the clear of one IP address was sent as %v, want the 4 bytes of the address", ops[3])
	}
	if len(ops[4].GetMac()) != 0 || len(ops[4].GetAddress()) != 0 {
		t.Errorf("the clear of every entry was sent as %v, want it with no MAC address and no address", ops[4])
	}
	if ops := operationsOf(files); len(ops) != 2 {
		t.Errorf("files was sent %d Operations, want the read and the clear of every entry that asked every node", len(ops))
	}
}

// A node that cannot be asked, or does not answer, is a status of its own, and the other nodes still
// answer: a node without the Capability is not sent an Operation, one that is not connected neither, one
// that has no such Network, one that fails and one that stays silent are each told as they are. An answer
// that no operation of the node waits for is dropped, whoever sends it.
func TestTablesGiveEachNodeItsOwnStatus(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice, aliceTables := h.opSim("alice-laptop", keyBranch1)
	bob, bobTables := h.opSim("bob-laptop", keyBranch2)
	aliceTables.SetMAC("lab-dmz")
	bobTables.SetMAC("corp-dmz", macEntry(0, 0x0d, "bob-laptop", time.Time{}))
	bobTables.setMode("mute")
	for _, s := range []*sim{alice, bob} {
		s.start(h)
		h.waitNode(s.name, 1, true)
	}
	files := h.sim("files", keyLab1)
	h.waitNode("files", 1, true)

	statuses := func() []string {
		t.Helper()
		res, err := h.api.MACTable(ctx, "corp-dmz", "")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, n := range res.Nodes {
			out = append(out, n.Node+" "+n.Status+" "+n.Message)
		}
		return out
	}
	started := time.Now()
	want := []string{
		"alice-laptop no-network no L2 Network of that name",
		"bob-laptop timeout " + controller.ErrOperationTimeout.Error(),
		"files unsupported the node does not report the Capability operations",
	}
	if got := statuses(); !slices.Equal(got, want) {
		t.Errorf("the statuses of the nodes are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if took := time.Since(started); took < operationTimeout/2 || took > 10*operationTimeout {
		t.Errorf("the call that waited for a node that stays silent took %v, want about %v", took, operationTimeout)
	}
	if ops := operationsOf(files); len(ops) != 0 {
		t.Errorf("files, which does not report the Capability operations, was sent %d Operations", len(ops))
	}

	// A node that fails says so; a node that has no stream is not asked
	bobTables.setMode("fail")
	files.halt()
	h.waitConnected("files", false)
	want = []string{
		"alice-laptop no-network no L2 Network of that name",
		"bob-laptop failed the switch is down",
		"files not-connected the node has no control stream",
	}
	if got := statuses(); !slices.Equal(got, want) {
		t.Errorf("the statuses of the nodes are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// An answer that arrives too late is dropped, and so is one that a node sends for the Operation of another
	bobTables.setMode("mute")
	done := make(chan controller.TableResult, 1)
	go func() {
		res, err := h.api.MACTable(ctx, "corp-dmz", "bob-laptop")
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	pending := waitOperations(t, bob, 3)[2]
	if err := alice.OperationResult(&controlpb.OperationResult{Id: pending.GetId(), Status: controlpb.OperationStatus_OPERATION_STATUS_OK, Total: 99}); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if len(res.Nodes) != 1 || res.Nodes[0].Status != controller.TableTimeout || res.Nodes[0].Total != 0 {
		t.Errorf("the call that alice-laptop answered for bob-laptop gave %+v, want the status timeout: only a node answers what it was asked", res)
	}
	if err := bob.OperationResult(&controlpb.OperationResult{Id: pending.GetId(), Status: controlpb.OperationStatus_OPERATION_STATUS_OK, Total: 99}); err != nil {
		t.Fatal(err)
	}
	if err := bob.OperationResult(&controlpb.OperationResult{Id: 1 << 40, Status: controlpb.OperationStatus_OPERATION_STATUS_OK}); err != nil {
		t.Fatal(err)
	}
	bobTables.setMode("")
	if res, err := h.api.MACTable(ctx, "corp-dmz", "bob-laptop"); err != nil || len(res.Nodes) != 1 || tableLine(res.Nodes[0]) != "bob-laptop ok total=1 [0 02:00:5e:10:00:0d bob-laptop]" {
		t.Errorf("the MAC table of bob-laptop after answers that nobody waited for is %+v (%v), want its entry", res, err)
	}
}

// What an operator may not ask of the tables is refused with the reason, before any node is asked: a
// Network that does not exist, one that is no L2 Network, a node that does not exist or does not hold the
// Network, an entry that is none, and a call that would ask more nodes than one call may.
func TestTablesRefuseWhatTheyCannotDo(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice, aliceTables := h.opSim("alice-laptop", keyBranch1)
	aliceTables.SetMAC("corp-dmz", macEntry(0, 0x0a, "alice-phone", time.Time{}))
	alice.start(h)
	h.waitNode("alice-laptop", 1, true)

	for _, c := range []struct {
		what string
		call func() error
		want int
		says string
	}{
		{"a Network that does not exist", func() error { _, err := h.api.MACTable(ctx, "nowhere", ""); return err }, http.StatusNotFound, `Network "nowhere"`},
		{"an L3 Network", func() error { _, err := h.api.MACTable(ctx, "corp-lan", ""); return err }, http.StatusBadRequest, "L3 Network"},
		{"an L3 Network, for its IP table", func() error { _, err := h.api.ClearIPTable(ctx, "corp-lan", "", ""); return err }, http.StatusBadRequest, "L3 Network"},
		{"a node that does not exist", func() error { _, err := h.api.MACTable(ctx, "corp-dmz", "nobody"); return err }, http.StatusNotFound, `Node "nobody"`},
		{"a node of another VRF", func() error { _, err := h.api.IPTable(ctx, "corp-dmz", "lab-box"); return err }, http.StatusBadRequest, `does not hold Network "corp-dmz"`},
		{"a MAC address that is none", func() error { _, err := h.api.ClearMACTable(ctx, "corp-dmz", "", "02:00:5e"); return err }, http.StatusBadRequest, "no MAC address"},
		{"a MAC address of 8 bytes", func() error {
			_, err := h.api.ClearMACTable(ctx, "corp-dmz", "", "02:00:5e:10:00:0a:0b:0c")
			return err
		}, http.StatusBadRequest, "no MAC address of 6 bytes"},
		{"an address that is none", func() error { _, err := h.api.ClearIPTable(ctx, "corp-dmz", "", "10.20.0"); return err }, http.StatusBadRequest, "no IP address"},
	} {
		if err := c.call(); httpStatus(err) != c.want || !strings.Contains(fmt.Sprint(err), c.says) {
			t.Errorf("%s: the call gave %v, want %d that says %q", c.what, err, c.want, c.says)
		}
	}
	if ops := operationsOf(alice); len(ops) != 0 {
		t.Errorf("alice-laptop was sent %d Operations for calls that were refused, want none", len(ops))
	}
	if left := aliceTables.MAC("corp-dmz"); len(left) != 1 {
		t.Errorf("the MAC table of alice-laptop holds %d entries after refused calls, want its one", len(left))
	}

	// One call asks at most 32 nodes: a Network on more needs the call to name one
	h.setLicence(licence.Licence{ID: "business-ops", Licensee: "Test", Tier: licence.Business, Nodes: 100, Expires: time.Now().Add(year)})
	var doc intent.Document
	for i := 0; i < 30; i++ {
		spec := fmt.Sprintf(`{"publicKey": %q, "vrfs": ["corp"]}`, base64.StdEncoding.EncodeToString(fixedKey(byte(150+i)).Public()))
		doc.Resources = append(doc.Resources, intent.Resource{Kind: intent.KindNode, Name: fmt.Sprintf("extra-%02d", i), Spec: []byte(spec)})
	}
	h.applyDoc(doc)
	if _, err := h.api.MACTable(ctx, "corp-dmz", ""); httpStatus(err) != http.StatusBadRequest || !strings.Contains(fmt.Sprint(err), "name a node") {
		t.Errorf("a read of a Network on 33 nodes gave %v, want 400 that asks for a node", err)
	}
	if res, err := h.api.MACTable(ctx, "corp-dmz", "alice-laptop"); err != nil || len(res.Nodes) != 1 || res.Nodes[0].Status != controller.TableOK {
		t.Errorf("a read that names the node gave %+v (%v), want its answer", res, err)
	}
}

// TestOperationsNeedTheOperatorRole is the first criterion of SDN-50: each live operation works within the
// role of its caller and is refused outside it. Every call runs with each role, with no token and with a
// token that the controller does not know; an operator and an admin are served, a viewer is refused with
// 403, the reads too, and nobody else with 401, and a refused call changes nothing: it ends no session, bans
// nobody and clears no table. The scope of a role is the whole controller until the roles that are scoped to
// a Network (SDN-38) exist.
func TestOperationsNeedTheOperatorRole(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice, aliceTables := h.opSim("alice-laptop", keyBranch1)
	files := h.sim("files", keyLab1)
	reset := func() {
		aliceTables.SetMAC("corp-dmz", macEntry(0, 0x0a, "alice-phone", time.Time{}))
		aliceTables.SetIP("corp-dmz", ipEntry("10.20.0.9", 0x0a, "alice-phone"))
	}
	reset()
	alice.start(h)
	h.waitNode("alice-laptop", 1, true)
	h.waitNode("files", 1, true)

	viewer := h.client(h.token("viewer-1", rbac.Viewer))
	operator := h.client(h.token("operator-1", rbac.Operator))
	var id string // the session that a disconnect names
	// reconnect brings files back after a disconnect, and names its session
	reconnect := func() {
		if !h.node("files").Connected {
			files.halt()
			files.start(h)
			h.waitConnected("files", true)
		}
		id = h.sessionOf("files").ID
	}
	actions := []struct {
		name  string
		setup func()
		do    func(c *api.Client) error
	}{
		{"list the sessions", nil, func(c *api.Client) error { _, err := c.Sessions(ctx, "", ""); return err }},
		{"disconnect a session", reconnect, func(c *api.Client) error { _, err := c.Disconnect(ctx, id); return err }},
		{"disconnect a user", nil, func(c *api.Client) error { _, err := c.DisconnectUser(ctx, "carol"); return err }},
		{"list the bans", nil, func(c *api.Client) error { _, err := c.Bans(ctx); return err }},
		{"ban a user", func() { _, _ = h.api.Unban(ctx, "carol") }, func(c *api.Client) error { _, err := c.Ban(ctx, "carol", "test"); return err }},
		{"lift a ban", func() { _, _ = h.api.Ban(ctx, "carol", "test") }, func(c *api.Client) error { _, err := c.Unban(ctx, "carol"); return err }},
		{"read the MAC table", reset, func(c *api.Client) error { _, err := c.MACTable(ctx, "corp-dmz", "alice-laptop"); return err }},
		{"clear the MAC table", reset, func(c *api.Client) error { _, err := c.ClearMACTable(ctx, "corp-dmz", "alice-laptop", ""); return err }},
		{"read the IP table", reset, func(c *api.Client) error { _, err := c.IPTable(ctx, "corp-dmz", "alice-laptop"); return err }},
		{"clear the IP table", reset, func(c *api.Client) error { _, err := c.ClearIPTable(ctx, "corp-dmz", "alice-laptop", ""); return err }},
	}
	callers := []struct {
		name string
		role rbac.Role // none for a caller without a known token
		c    *api.Client
	}{
		{"no token", "", h.client("")},
		{"an unknown token", "", h.client("ranz_NOTATOKENOFTHISCONTROLLER")},
		{"viewer", rbac.Viewer, viewer},
		{"operator", rbac.Operator, operator},
		{"admin", rbac.Admin, h.api},
	}
	state := func() string {
		sessions, err := h.api.Sessions(ctx, "", "")
		if err != nil {
			t.Fatal(err)
		}
		bans, err := h.api.Bans(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%s\n%v %d bans, %d MAC and %d IP entries", h.snapshot(), sessionNames(sessions), len(bans), len(aliceTables.MAC("corp-dmz")), len(aliceTables.IP("corp-dmz")))
	}
	for _, a := range actions {
		for _, who := range callers {
			if a.setup != nil {
				a.setup()
			}
			before := state()
			err := a.do(who.c)
			if who.role.Allows(rbac.Operator) {
				if err != nil {
					t.Errorf("%s: %s was refused: %v", who.name, a.name, err)
				}
				continue
			}
			want := http.StatusForbidden
			if who.role == "" {
				want = http.StatusUnauthorized
			}
			if httpStatus(err) != want {
				t.Errorf("%s: %s gave %v, want the status %d", who.name, a.name, err, want)
				continue
			}
			if after := state(); after != before {
				t.Errorf("%s: the refused %s changed the controller:\n--- after\n%s\n--- before\n%s", who.name, a.name, after, before)
			}
		}
	}
	if ops := operationsOf(alice); len(ops) != 8 {
		t.Errorf("alice-laptop was sent %d Operations, want 8: the four calls on a table of the operator and of the admin, and none of the callers that were refused", len(ops))
	}
}

// httpErr returns nil when err is an answer of the API with the status want, and err otherwise, for a step
// that expects the API to refuse.
func httpErr(err error, want int) error {
	if httpStatus(err) == want {
		return nil
	}
	return fmt.Errorf("want the status %d, got %v", want, err)
}

// TestOperationsAreAudited is the second half of the second criterion of SDN-50: every operation is in the
// audit log, once, as an operation with its actor, its time, its source and its outcome, and says what it
// was done to. An operation that fails is a record with the outcome failure and the reason, and a call that
// is refused for its role makes none, since nothing was done. The records are the controller's own: the
// audit of the API does not make a second one for a call.
func TestOperationsAreAudited(t *testing.T) {
	h := newOperationsHarness(t)
	ctx := context.Background()
	h.apply("operations.json")
	alice, aliceTables := h.opSim("alice-laptop", keyBranch1)
	aliceTables.SetMAC("corp-dmz", macEntry(0, 0x0a, "alice-phone", time.Time{}))
	aliceTables.SetIP("corp-dmz", ipEntry("10.20.0.9", 0x0a, "alice-phone"))
	alice.start(h)
	bob := h.sim("bob-laptop", keyBranch2)
	h.waitNode("alice-laptop", 1, true)
	h.waitNode("bob-laptop", 1, true)

	ops := h.auditedAPI(h.token("ops-1", rbac.Operator))
	viewer := h.auditedAPI(h.token("viewer-1", rbac.Viewer))
	since := time.Now().Add(-time.Second)
	bobSession := h.sessionOf("bob-laptop")

	type step struct {
		action, subject, outcome, message string
		do                                func() error
	}
	steps := []step{
		{"session-list", "sessions", audit.Success, "sessions listed: 2", func() error { _, err := ops.Sessions(ctx, "", ""); return err }},
		{"session-list", "sessions of user alice", audit.Success, "sessions listed: 1", func() error { _, err := ops.Sessions(ctx, "alice", ""); return err }},
		{"session-disconnect", "session " + bobSession.ID, audit.Success, "node bob-laptop of user bob, from 127.0.0.1", func() error {
			if _, err := ops.Disconnect(ctx, bobSession.ID); err != nil {
				return err
			}
			// bob-laptop connects again, as a node does, so that the steps that follow find its session
			refuseOf(t, bob)
			bob.start(h)
			h.waitConnected("bob-laptop", true)
			return nil
		}},
		{"mac-table", "network corp-dmz on node alice-laptop", audit.Success, "alice-laptop: ok, 1 entries", func() error { _, err := ops.MACTable(ctx, "corp-dmz", "alice-laptop"); return err }},
		{"ip-table", "network corp-dmz on node alice-laptop", audit.Success, "alice-laptop: ok, 1 entries", func() error { _, err := ops.IPTable(ctx, "corp-dmz", "alice-laptop"); return err }},
		{"mac-table-clear", "network corp-dmz on node alice-laptop, entry 02:00:5e:10:00:0a", audit.Success, "alice-laptop: ok, 1 removed",
			func() error {
				_, err := ops.ClearMACTable(ctx, "corp-dmz", "alice-laptop", "02:00:5e:10:00:0a")
				return err
			}},
		{"ip-table-clear", "network corp-dmz on node alice-laptop, entry 10.20.0.9", audit.Success, "alice-laptop: ok, 1 removed",
			func() error { _, err := ops.ClearIPTable(ctx, "corp-dmz", "alice-laptop", "10.20.0.9"); return err }},
		// bob-laptop reports no Capability operations, and files has no stream, so a call that asks every node
		// did not do what was asked on them
		{"mac-table", "network corp-dmz", audit.Failure, "alice-laptop: ok, 0 entries; bob-laptop: unsupported (the node does not report the Capability operations); files: not-connected",
			func() error { _, err := ops.MACTable(ctx, "corp-dmz", ""); return err }},
		{"mac-table", "network corp-lan", audit.Failure, "L3 Network", func() error { _, err := ops.MACTable(ctx, "corp-lan", ""); return httpErr(err, http.StatusBadRequest) }},
		{"ban-list", "bans", audit.Success, "bans listed: 0", func() error { _, err := ops.Bans(ctx); return err }},
		{"user-ban", "user bob", audit.Success, "sessions ended: 1; reason: left the company", func() error { _, err := ops.Ban(ctx, "bob", "left the company"); return err }},
		{"ban-list", "bans", audit.Success, "bans listed: 1", func() error { _, err := ops.Bans(ctx); return err }},
		{"user-unban", "user bob", audit.Success, "banned since", func() error { _, err := ops.Unban(ctx, "bob"); return err }},
		{"user-unban", "user bob", audit.Failure, "is not banned", func() error { _, err := ops.Unban(ctx, "bob"); return httpErr(err, http.StatusNotFound) }},
		{"user-ban", "user nobody", audit.Failure, `User "nobody"`, func() error { _, err := ops.Ban(ctx, "nobody", ""); return httpErr(err, http.StatusNotFound) }},
		{"user-disconnect", "user alice", audit.Success, "sessions ended: 1 (alice-laptop)", func() error { _, err := ops.DisconnectUser(ctx, "alice"); return err }},
		{"session-disconnect", "session 0123456789abcdef", audit.Failure, "no such resource", func() error {
			_, err := ops.Disconnect(ctx, "0123456789abcdef")
			return httpErr(err, http.StatusNotFound)
		}},
	}
	for i, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("step %d, %s: %v", i, s.action, err)
		}
	}

	// A call that is refused for its role is no operation
	if _, err := viewer.Sessions(ctx, "", ""); httpStatus(err) != http.StatusForbidden {
		t.Fatalf("the sessions as a viewer gave %v, want 403", err)
	}
	if _, err := viewer.Ban(ctx, "alice", ""); httpStatus(err) != http.StatusForbidden {
		t.Fatalf("a ban as a viewer gave %v, want 403", err)
	}

	// The first record is the one of h.sessionOf above: it found the session of bob-laptop with the client of the
	// harness, which carries no origin, so the controller records it for the system, at the source local. The
	// others are one for each call that was served and none for the calls that were refused.
	recs := h.waitAudit(ops, "a record of each operation", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Operation)) >= len(steps)+1 })
	operations := auditOfKind(recs, audit.Operation)
	if len(operations) != len(steps)+1 {
		t.Fatalf("the audit log holds %d operations, want %d: the one that found the session of bob-laptop, and one for each call that was served:\n%s",
			len(operations), len(steps)+1, auditLines(recs))
	}
	checkAuditRecord(t, operations[0], since, audit.ActorSystem, audit.SourceLocal, audit.Success, "session-list", 0)
	for i, s := range steps {
		r := operations[i+1]
		checkAuditRecord(t, r, since, audit.ActorToken("ops-1"), "127.0.0.1", s.outcome, s.action, 0)
		if r.Subject != s.subject || !strings.Contains(r.Message, s.message) {
			t.Errorf("the operation %d is %+v, want the subject %q and a message that says %q", i, r, s.subject, s.message)
		}
	}
}
