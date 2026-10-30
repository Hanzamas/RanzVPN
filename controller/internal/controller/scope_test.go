package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/scope"
)

// Roles scoped to one Network with quotas and permissions (SDN-38, #231), through the HTTP API and the simulated
// nodes: a role that is held for a Network changes the intent through the calls of that Network and nothing else,
// the delegation of the Network says which kinds it may change and how much the Network may hold, and the groups of
// an identity provider that are mapped to a role give exactly that role and its scope.

// scopeNodeRes returns the JSON of the Node name in VRF corp that has the key of nodeKey(i), with the fields of extra,
// which start with a comma when there are any.
func scopeNodeRes(name string, i int, extra string) string {
	return `{"kind": "Node", "name": "` + name + `", "spec": {"publicKey": "` + base64.StdEncoding.EncodeToString(nodeKey(i).Public()) + `", "vrfs": ["corp"]` + extra + `}}`
}

// scopeBase is the intent that the tests of SDN-38 start from: the VRFs corp and lab, the Networks branch-a and
// branch-b in corp, the Node hub that is in the scope of no Network and the Node b-server of branch-b, the Group
// branch-a-staff and the User alice of branch-a, and the User bob of branch-b.
func scopeBase(t *testing.T) intent.Document {
	t.Helper()
	return usersDoc(t,
		`{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}}`,
		`{"kind": "VRF", "name": "lab", "spec": {"id": 20, "ula": "fd12:3456:789b::/48"}}`,
		`{"kind": "Network", "name": "branch-a", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}}`,
		`{"kind": "Network", "name": "branch-b", "spec": {"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}}`,
		`{"kind": "Group", "name": "branch-a-staff", "spec": {"scope": "branch-a"}}`,
		`{"kind": "User", "name": "alice", "spec": {"groups": ["branch-a-staff"], "scope": "branch-a"}}`,
		`{"kind": "User", "name": "bob", "spec": {"scope": "branch-b"}}`,
		scopeNodeRes("hub", 1, ""),
		scopeNodeRes("b-server", 2, `, "scope": "branch-b"`))
}

// scopedClient returns a client that calls with a new API token that holds the role role for the Network network.
func (h *harness) scopedClient(name string, role rbac.Role, network string) *api.Client {
	h.t.Helper()
	tok, err := h.api.CreateTokenRequest(context.Background(), api.TokenRequest{Name: name, Role: role, Network: network})
	if err != nil {
		h.t.Fatal(err)
	}
	return h.client(tok.Secret)
}

// delegate sets the delegation of the Network network with the permissions perms and the quotas q.
func (h *harness) delegate(network string, q scope.Quotas, perms ...string) {
	h.t.Helper()
	if _, err := h.api.SetDelegation(context.Background(), network, q, perms); err != nil {
		h.t.Fatal(err)
	}
}

// refused checks that err is a refusal of the API with the status 403 Forbidden whose message holds each of want.
func refused(t *testing.T, what string, err error, want ...string) {
	t.Helper()
	if httpStatus(err) != http.StatusForbidden {
		t.Errorf("%s: gave %v, want 403", what, err)
		return
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%s: the refusal\n%v\ndoes not say %q", what, err, w)
		}
	}
}

// resourceNames returns the kind and the name of each resource, ordered.
func resourceNames(rs []intent.Resource) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Kind+"/"+r.Name)
	}
	slices.Sort(out)
	return out
}

// userNamed returns the User name of the intent, as the API shows it.
func (h *harness) userNamed(name string) (intent.User, bool) {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		h.t.Fatal(err)
	}
	u, ok := in.Users[name]
	return u, ok
}

// problemOf returns the message of the Problem that the answer w holds.
func problemOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var p api.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("the answer %q is no Problem: %v", w.Body, err)
	}
	return p.Error
}

// asUser calls the path with the token secret as the Guard of the API sees the request, and returns the answer.
func (h *harness) asUser(secret, method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://ctl.example"+target, nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.port.HTTP.ServeHTTP(w, r)
	return w
}

// TestAScopedAdminChangesOnlyItsNetworkAndThePermittedKinds is the first criterion of SDN-38 (#231): a network-scoped
// admin can change only their network and only the permitted kinds. The admin of branch-a makes a User and a Node in its
// scope, and the nodes that share the VRF learn of the new Node; it cannot change what is in the scope of branch-b or of
// no Network, nor a VRF, nor the Network itself before its delegation permits it, nor a kind that the delegation leaves
// out; every call of the whole API is refused it; and a refusal changes nothing and sends the nodes nothing.
func TestAScopedAdminChangesOnlyItsNetworkAndThePermittedKinds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.applyDoc(scopeBase(t))
	hub, bsrv := h.sim("hub", nodeKey(1)), h.sim("b-server", nodeKey(2))
	h.connect(t, hub, bsrv)

	h.delegate("branch-a", scope.Quotas{}, scope.PermUsers, scope.PermGroups, scope.PermNodes, scope.PermRules, scope.PermSessions)
	admin := h.scopedClient("a-admin", rbac.Admin, "branch-a")
	operator := h.scopedClient("a-operator", rbac.Operator, "branch-a")
	viewer := h.scopedClient("a-viewer", rbac.Viewer, "branch-a")
	if who, err := admin.Whoami(ctx); err != nil || who.Name != "a-admin" || who.Role != rbac.Admin || who.Network != "branch-a" {
		t.Fatalf("whoami of the scoped token: %+v, %v", who, err)
	}

	// The admin makes a User and a Node in its scope: the apply is checked and made, and the other nodes of the VRF
	// get the new Node as a peer, with the tag of the Group of its owner
	res, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t,
		`{"kind": "User", "name": "carol", "spec": {"displayName": "Carol", "groups": ["branch-a-staff"], "scope": "branch-a"}}`,
		scopeNodeRes("a-server", 3, `, "scope": "branch-a", "owner": "carol"`)))
	if err != nil {
		t.Fatalf("the apply of the admin of branch-a in its own scope: %v", err)
	}
	if want := []controller.NodeGeneration{{Name: "a-server", Generation: 1}, {Name: "b-server", Generation: 2}, {Name: "hub", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the apply of the scoped admin changed %+v, want %+v", res.Nodes, want)
	}
	hub.update(t)
	bsrv.update(t)
	h.waitNode("hub", 2, true)
	h.waitNode("b-server", 2, true)
	for _, s := range []*sim{hub, bsrv} {
		if _, peers, _ := userHeld(s); !slices.Equal(peers["a-server"], []string{"branch-a-staff"}) {
			t.Errorf("%s holds the peers %v, want a-server with the tag branch-a-staff, which its owner's Group gives it", s.name, peers)
		}
	}
	server := h.sim("a-server", nodeKey(3))
	server.update(t)
	h.waitNode("a-server", 1, true)
	if _, peers, _ := userHeld(server); !slices.Equal(slices.Sorted(maps.Keys(peers)), []string{"b-server", "hub"}) {
		t.Errorf("a-server holds the peers %v, want hub and b-server", peers)
	}

	// What it cannot change: each refusal is 403 with the reasons, and changes nothing
	before := h.resources()
	otherVRF := `{"kind": "Node", "name": "a-lab", "spec": {"publicKey": "` + base64.StdEncoding.EncodeToString(nodeKey(5).Public()) + `", "vrfs": ["lab"], "scope": "branch-a"}}`
	for _, c := range []struct {
		name string
		rs   []string
		want string
	}{
		{"a User of the scope of another Network", []string{`{"kind": "User", "name": "dave", "spec": {"scope": "branch-b"}}`}, `User "dave" must be in the scope of Network "branch-a"`},
		{"a User of no scope", []string{`{"kind": "User", "name": "dave", "spec": {}}`}, `User "dave" must be in the scope of Network "branch-a"`},
		{"a User of another Network that exists", []string{`{"kind": "User", "name": "bob", "spec": {"scope": "branch-a"}}`}, `User "bob" is not in the scope of Network "branch-a"`},
		{"a Node of another Network", []string{scopeNodeRes("b-server", 2, `, "scope": "branch-a"`)}, `Node "b-server" is not in the scope of Network "branch-a"`},
		{"a Node that is in no scope", []string{scopeNodeRes("hub", 1, `, "scope": "branch-a"`)}, `Node "hub" is not in the scope of Network "branch-a"`},
		{"a Node that is a relay", []string{scopeNodeRes("a-relay", 4, `, "scope": "branch-a", "relay": "192.0.2.1:3478"`)}, `a scoped role cannot set relay`},
		{"a Node of another VRF", []string{otherVRF}, `a Node of the scope is in the VRF "corp" of Network "branch-a" and in no other`},
		{"the Network of another", []string{`{"kind": "Network", "name": "branch-b", "spec": {"vrf": "corp", "ipv4Pool": "10.20.0.0/24", "keyLifetimeDays": 30}}`}, `Network "branch-b" is not the Network of the scope, "branch-a"`},
		{"a VRF", []string{`{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}}`}, `a VRF is none of them`},
		{"a Network of its own", []string{`{"kind": "Network", "name": "branch-c", "spec": {"vrf": "corp", "ipv4Pool": "10.30.0.0/24"}}`}, `Network "branch-c" is not the Network of the scope`},
		{"the Network itself, which its delegation does not permit", []string{`{"kind": "Network", "name": "branch-a", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "keyLifetimeDays": 30}}`},
			`Network "branch-a" does not permit its scoped roles to change network, and it permits nodes, users, groups, rules, sessions`},
	} {
		_, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, c.rs...))
		refused(t, c.name, err, `the change is outside the scope of Network "branch-a"`, c.want)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused change changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	noUpdate(t, hub)
	noUpdate(t, bsrv)
	noUpdate(t, server)

	// Another Network's role is another's: it reads and changes its own Network and refuses this one
	bAdmin := h.scopedClient("b-admin", rbac.Admin, "branch-b")
	_, err = bAdmin.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "dave", "spec": {"scope": "branch-a"}}`))
	refused(t, "the admin of branch-b applying in branch-a", err, `holds the role admin for Network "branch-b" only`)
	if _, err := bAdmin.NetworkInfo(ctx, "branch-a"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the admin of branch-b reading branch-a: %v, want 403", err)
	}
	if _, err := bAdmin.NetworkInfo(ctx, "branch-b"); err != nil {
		t.Errorf("the admin of branch-b reading branch-b: %v", err)
	}
	// A role of the whole API has the calls of the intent, and these are for the roles of a Network
	_, err = h.api.NetworkInfo(ctx, "branch-a")
	refused(t, "the admin of the whole API on the calls of a Network", err, "the calls of a Network are for the roles that are held for it")

	// The calls of the whole API are refused to the scoped admin, the reads too
	doc := usersDoc(t, `{"kind": "User", "name": "dave", "spec": {"scope": "branch-a"}}`)
	for _, c := range []struct {
		name string
		call func() error
	}{
		{"apply", func() error { _, err := admin.Apply(ctx, doc); return err }},
		{"delete", func() error { _, err := admin.Delete(ctx, intent.KindUser, "carol"); return err }},
		{"get resources", func() error { _, err := admin.Resources(ctx); return err }},
		{"get nodes", func() error { _, err := admin.Nodes(ctx); return err }},
		{"get status", func() error { _, err := admin.Status(ctx); return err }},
		{"get revisions", func() error { _, err := admin.Revisions(ctx); return err }},
		{"rollback", func() error { _, err := admin.Rollback(ctx, 1); return err }},
		{"get users", func() error { _, err := admin.Users(ctx); return err }},
		{"set the password of a user", func() error { _, err := admin.SetUserPassword(ctx, "carol", "a password of eight"); return err }},
		{"list the tokens", func() error { _, err := admin.Tokens(ctx); return err }},
		{"create a token", func() error { _, err := admin.CreateToken(ctx, "spare", rbac.Admin); return err }},
		{"set a delegation", func() error {
			_, err := admin.SetDelegation(ctx, "branch-a", scope.Quotas{}, []string{scope.PermNetwork})
			return err
		}},
		{"list the delegations", func() error { _, err := admin.Delegations(ctx); return err }},
		{"give itself the role of the whole API", func() error { _, err := admin.SetTokenGrant(ctx, "a-admin", rbac.Grant{Role: rbac.Admin}); return err }},
		{"read the admin sources", func() error { _, err := admin.AdminSources(ctx); return err }},
		{"list the sessions of the operations", func() error { _, err := admin.Sessions(ctx, "", ""); return err }},
		{"ban a user", func() error { _, err := admin.Ban(ctx, "alice", "no reason"); return err }},
	} {
		refused(t, "the scoped admin: "+c.name, c.call(), `holds the role admin for Network "branch-a" only`)
	}
	// A path that climbs out of the Network's own is the path that it climbs to; a name that holds a slash is not the
	// name of this Network, which the handler of the call sees though the Guard let the path through
	for _, p := range []string{"/api/v1/networks/branch-a/../branch-b/resources", "/api/v1/networks/branch-a/../../resources", "/api/v1/networks/branch-a%2f..%2fbranch-b"} {
		if w := h.asUser(admin.Token, http.MethodGet, p); w.Code != http.StatusForbidden || !strings.Contains(problemOf(t, w), `holds the role admin for Network "branch-a" only`) {
			t.Errorf("GET %s with the scoped token got %d, want 403 from the Guard: %s", p, w.Code, w.Body)
		}
	}
	if w := h.asUser(admin.Token, http.MethodGet, "/api/v1/networks/branch-a%2Fx/resources"); w.Code != http.StatusForbidden || !strings.Contains(problemOf(t, w), `holds its role for Network "branch-a", not "branch-a/x"`) {
		t.Errorf("GET of a Network whose name holds a slash with the scoped token got %d, want 403 from the handler: %s", w.Code, w.Body)
	}

	// It reads what is in its scope, and only that
	rs, err := admin.NetworkResources(ctx, "branch-a")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resourceNames(rs), []string{"Group/branch-a-staff", "Network/branch-a", "Node/a-server", "User/alice", "User/carol"}; !slices.Equal(got, want) {
		t.Errorf("the resources in the scope of branch-a are %v, want %v", got, want)
	}
	info, err := admin.NetworkInfo(ctx, "branch-a")
	if err != nil || info.Network.Name != "branch-a" || info.Delegation.Usage != (scope.Usage{Users: 2, Groups: 1, Nodes: 1}) || info.Delegation.Sessions != 1 ||
		!slices.Equal(info.Delegation.Permissions, []string{scope.PermNodes, scope.PermUsers, scope.PermGroups, scope.PermRules, scope.PermSessions}) {
		t.Errorf("the Network as its admin sees it: %+v, %v", info, err)
	}

	// The permissions are the delegation's: with the Network permitted, an admin changes it and an operator does not,
	// and the VRF and the pools of a Network are the global roles' to the end
	h.delegate("branch-a", scope.Quotas{}, scope.PermNetwork, scope.PermUsers, scope.PermNodes)
	network := usersDoc(t, `{"kind": "Network", "name": "branch-a", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "keyLifetimeDays": 30}}`)
	_, err = operator.NetworkApply(ctx, "branch-a", network)
	refused(t, "the operator changing the Network", err, `changing the Network itself needs the role admin`)
	if _, err := admin.NetworkApply(ctx, "branch-a", network); err != nil {
		t.Errorf("the admin changing its Network, which the delegation permits: %v", err)
	}
	_, err = admin.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "Network", "name": "branch-a", "spec": {"vrf": "corp", "ipv4Pool": "10.11.0.0/24"}}`))
	refused(t, "the admin changing the pool of its Network", err, `the vrf, the mode and the pools of a Network are the global roles' to change`)
	// A kind that the delegation leaves out is refused, one that it names is not
	_, err = admin.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "Group", "name": "branch-a-sales", "spec": {"scope": "branch-a"}}`))
	refused(t, "a Group, which the delegation leaves out", err, `Group "branch-a-sales": Network "branch-a" does not permit its scoped roles to change groups, and it permits network, nodes, users`)
	if _, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "erin", "spec": {"scope": "branch-a"}}`)); err != nil {
		t.Errorf("a User, which the delegation names: %v", err)
	}

	// A viewer reads and an operator changes what the delegation permits; a viewer changes nothing
	if _, err := viewer.NetworkResources(ctx, "branch-a"); err != nil {
		t.Errorf("the viewer of branch-a reading: %v", err)
	}
	if _, err := viewer.NetworkApply(ctx, "branch-a", doc); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the viewer of branch-a applying: %v, want 403", err)
	}
	if _, err := viewer.NetworkSessions(ctx, "branch-a"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the viewer of branch-a listing the sessions: %v, want 403", err)
	}
	if _, err := operator.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "frank", "spec": {"scope": "branch-a"}}`)); err != nil {
		t.Errorf("the operator of branch-a making a User: %v", err)
	}

	// It deletes what is in its scope and nothing else, and the refusal is the scope's and tells nothing that the intent
	// knows of what depends on a resource
	for _, c := range []struct{ kind, name, want string }{
		{intent.KindUser, "bob", `User "bob" is not in the scope of Network "branch-a"`},
		{intent.KindNode, "b-server", `Node "b-server" is not in the scope of Network "branch-a"`},
		{intent.KindNode, "hub", `Node "hub" is not in the scope of Network "branch-a"`},
		{intent.KindNetwork, "branch-a", `Network "branch-a" cannot be deleted by a scoped role`},
		{intent.KindVRF, "corp", `a VRF is none of them`},
	} {
		_, err := admin.NetworkDelete(ctx, "branch-a", c.kind, c.name)
		refused(t, "deleting "+c.kind+" "+c.name, err, c.want)
		if err != nil && strings.Contains(err.Error(), "is used by") {
			t.Errorf("the refusal of deleting %s %s says what depends on it: %v", c.kind, c.name, err)
		}
	}
	if _, err := admin.NetworkDelete(ctx, "branch-a", intent.KindUser, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("deleting a User that does not exist: %v, want 404", err)
	}
	if _, err := admin.NetworkDelete(ctx, "branch-a", intent.KindNode, "a-server"); err != nil {
		t.Errorf("deleting a Node of the scope: %v", err)
	}
	if _, err := admin.NetworkDelete(ctx, "branch-a", intent.KindUser, "carol"); err != nil {
		t.Errorf("deleting a User of the scope: %v", err)
	}
	for _, name := range []string{"bob", "alice", "erin", "frank"} {
		if _, ok := h.userNamed(name); !ok {
			t.Errorf("the User %s is not in the intent after the scoped changes", name)
		}
	}
	if _, ok := h.userNamed("carol"); ok {
		t.Error("the User carol is still in the intent after the admin of her Network deleted her")
	}
}

// quotaDoc returns the document of the n resources that one makes for i from first to first+n-1.
func quotaDoc(t *testing.T, first, n int, one func(i int) string) intent.Document {
	t.Helper()
	var rs []string
	for i := first; i < first+n; i++ {
		rs = append(rs, one(i))
	}
	return usersDoc(t, rs...)
}

// TestExceedingAQuotaIsRefusedWithAClearError is the second criterion of SDN-38 (#231): exceeding a quota is refused
// with a clear error. The Network branch-a has quotas of 3 users, 2 groups, 2 nodes, 1 rule, a bandwidth and one
// session: the apply that takes it over one is refused with 403, and the answer names the quota, the Network and the
// count that the change would make; an apply that stays within the quota passes, as does one after a delete; the
// control stream of a second Node of the Network is refused by the controller, and the one of a Node outside the
// Network is not.
func TestExceedingAQuotaIsRefusedWithAClearError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.applyDoc(scopeBase(t))
	h.delegate("branch-a", scope.Quotas{Users: 3, Groups: 2, Nodes: 2, Rules: 1, Sessions: 1, Bandwidth: 1_000_000},
		scope.PermUsers, scope.PermGroups, scope.PermNodes, scope.PermRules, scope.PermSessions)
	admin := h.scopedClient("a-admin", rbac.Admin, "branch-a")
	over := func(what string, err error, count string) {
		t.Helper()
		refused(t, what, err, `the change is over a quota of Network "branch-a"`, count)
	}

	// Users: alice is the first of 3, so two more fit and a third does not
	user := func(i int) string {
		return `{"kind": "User", "name": "user-` + string(rune('a'+i)) + `", "spec": {"scope": "branch-a"}}`
	}
	if _, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 0, 2, user)); err != nil {
		t.Fatalf("two Users, which the quota of 3 allows beside alice: %v", err)
	}
	_, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 2, 1, user))
	over("a fourth User", err, `Network "branch-a" allows 3 users at most, and the change would make 4`)
	if _, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "user-a", "spec": {"scope": "branch-a", "displayName": "A"}}`)); err != nil {
		t.Errorf("changing a User of a Network that is at its quota: %v", err)
	}
	if _, err := admin.NetworkDelete(ctx, "branch-a", intent.KindUser, "user-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 2, 1, user)); err != nil {
		t.Errorf("a User after one was deleted: %v", err)
	}

	// Groups: branch-a-staff is the first of 2
	group := func(i int) string {
		return `{"kind": "Group", "name": "branch-a-g` + string(rune('a'+i)) + `", "spec": {"scope": "branch-a"}}`
	}
	if _, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 0, 1, group)); err != nil {
		t.Fatalf("a Group, which the quota of 2 allows beside branch-a-staff: %v", err)
	}
	_, err = admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 1, 1, group))
	over("a third Group", err, `Network "branch-a" allows 2 groups at most, and the change would make 3`)

	// Rules: one allowed
	rule := func(i int) string {
		return `{"kind": "Policy", "name": "rule-` + string(rune('a'+i)) + `", "spec": {"vrf": "corp", "scope": "branch-a", "action": "allow", "from": {"tags": ["branch-a-staff"]}, "to": {"addresses": ["10.10.0.0/24"]}}}`
	}
	if _, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 0, 1, rule)); err != nil {
		t.Fatalf("a rule, which the quota of 1 allows: %v", err)
	}
	_, err = admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 1, 1, rule))
	over("a second rule", err, `Network "branch-a" allows 1 rules at most, and the change would make 2`)

	// Nodes: two allowed, each with a rate limit within the bandwidth quota
	node := func(i int) string {
		return scopeNodeRes("a-node-"+string(rune('a'+i)), 10+i, `, "scope": "branch-a", "rateLimit": 1000000`)
	}
	if _, err := admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 0, 2, node)); err != nil {
		t.Fatalf("two Nodes, which the quota of 2 allows: %v", err)
	}
	_, err = admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 2, 1, node))
	over("a third Node", err, `Network "branch-a" allows 2 nodes at most, and the change would make 3`)
	// The bandwidth quota bounds the rate limit of a Node that the admin changes
	_, err = admin.NetworkApply(ctx, "branch-a", usersDoc(t, scopeNodeRes("a-node-a", 10, `, "scope": "branch-a", "rateLimit": 2000000`)))
	over("a Node over the bandwidth", err, `Node "a-node-a" has the rate limit 2000000 bit/s, and Network "branch-a" allows its Nodes 1000000 bit/s at most`)
	_, err = admin.NetworkApply(ctx, "branch-a", usersDoc(t, scopeNodeRes("a-node-a", 10, `, "scope": "branch-a"`)))
	over("a Node with no rate limit", err, `Node "a-node-a" has no rate limit, and Network "branch-a" allows its Nodes 1000000 bit/s at most: set rateLimit to that or less`)
	if _, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, scopeNodeRes("a-node-a", 10, `, "scope": "branch-a", "rateLimit": 500000`))); err != nil {
		t.Errorf("a Node under the bandwidth quota: %v", err)
	}
	info, err := admin.NetworkInfo(ctx, "branch-a")
	if err != nil || info.Delegation.Usage != (scope.Usage{Users: 3, Groups: 2, Nodes: 2, Rules: 1}) || info.Delegation.Quotas.Bandwidth != 1_000_000 {
		t.Errorf("the Network says %+v, %v, want the usage that the quotas were reached with", info.Delegation, err)
	}

	// A quota that is lowered below what the Network holds stops what adds and leaves what changes or removes
	h.delegate("branch-a", scope.Quotas{Nodes: 1, Sessions: 1}, scope.PermUsers, scope.PermNodes, scope.PermSessions)
	_, err = admin.NetworkApply(ctx, "branch-a", quotaDoc(t, 2, 1, node))
	over("a Node over a quota that was lowered", err, `allows 1 nodes at most, and the change would make 3`)
	if _, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, scopeNodeRes("a-node-b", 11, `, "scope": "branch-a", "rateLimit": 777`))); err != nil {
		t.Errorf("changing a Node of a Network that is over its quota: %v", err)
	}
	if _, err := admin.NetworkDelete(ctx, "branch-a", intent.KindNode, "a-node-b"); err != nil {
		t.Errorf("deleting a Node of a Network that is over its quota: %v", err)
	}

	// Sessions: the Network allows one control stream at a time. The second Node is refused with a message that names
	// the quota; the Node of no Network is not, whatever the Network has open; and the Node is admitted when the session
	// of the first one has ended
	h.delegate("branch-a", scope.Quotas{Nodes: 2, Sessions: 1}, scope.PermUsers, scope.PermNodes, scope.PermSessions)
	first, second := h.sim("a-node-a", nodeKey(10)), h.newSim("a-node-c", nodeKey(12))
	first.update(t)
	h.waitConnected("a-node-a", true)
	if _, err := admin.NetworkApply(ctx, "branch-a", usersDoc(t, scopeNodeRes("a-node-c", 12, `, "scope": "branch-a"`))); err != nil {
		t.Fatalf("the second Node of the Network: %v", err)
	}
	first.update(t)
	second.start(h)
	refusal := second.refusal(t).GetRefuse()
	if refusal.GetReason() != controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE || !strings.Contains(refusal.GetMessage(), `Network "branch-a" allows 1 sessions at most, and they are all open`) {
		t.Errorf("the second Node of the Network was refused with %v: %q", refusal.GetReason(), refusal.GetMessage())
	}
	hub := h.sim("hub", nodeKey(1))
	hub.update(t)
	h.waitConnected("hub", true)
	// The admin of the Network sees its one session, and ends it
	sessions, err := admin.NetworkSessions(ctx, "branch-a")
	if err != nil || len(sessions) != 1 || sessions[0].Node != "a-node-a" {
		t.Fatalf("the sessions of branch-a are %+v, %v, want the one of a-node-a", sessions, err)
	}
	if got, err := admin.NetworkInfo(ctx, "branch-a"); err != nil || got.Delegation.Sessions != 1 || got.Delegation.Quotas.Sessions != 1 {
		t.Errorf("the Network says %+v, %v, want one session of one", got.Delegation, err)
	}
	// A session of a Node of no scope is not its to end
	other, err := h.api.Sessions(ctx, "", "hub")
	if err != nil || len(other) != 1 {
		t.Fatalf("the session of hub: %+v, %v", other, err)
	}
	_, err = admin.NetworkDisconnect(ctx, "branch-a", other[0].ID)
	refused(t, "ending the session of a Node that is in no scope", err, `Node "hub" is not in the scope of Network "branch-a"`)
	if _, err := admin.NetworkDisconnect(ctx, "branch-a", "0123456789abcdef"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("ending a session that does not exist: %v, want 404", err)
	}
	ended, err := admin.NetworkDisconnect(ctx, "branch-a", sessions[0].ID)
	if err != nil || ended.Node != "a-node-a" {
		t.Fatalf("ending the session of a-node-a: %+v, %v", ended, err)
	}
	first.refusal(t)
	h.waitConnected("a-node-a", false)
	second.start(h)
	second.update(t)
	h.waitConnected("a-node-c", true)
}

// TestAProviderGroupMappedToAScopedRoleGrantsExactlyThatScope is the third criterion of SDN-38 (#231): a provider group
// mapped to a scoped role grants exactly that scope. An admin maps groups of the provider okta to the role admin of
// branch-a, the role admin of branch-b and the role viewer of the whole API; a login through the provider whose groups
// hold the first gets a user token that is admin of branch-a, which changes branch-a and cannot read or change branch-b
// or anything of the whole API; the others get theirs; and groups that no mapping names get none.
func TestAProviderGroupMappedToAScopedRoleGrantsExactlyThatScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.applyDoc(scopeBase(t))
	h.delegate("branch-a", scope.Quotas{}, scope.PermUsers)
	h.delegate("branch-b", scope.Quotas{}, scope.PermUsers)

	// The mappings are the admin's: a role that is held for a Network that does not exist is refused, and an operator
	// does not read or set them
	operator := h.client(h.token("operator-1", rbac.Operator))
	if _, err := operator.GroupMappings(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator reading the mappings: %v, want 403", err)
	}
	if _, err := operator.SetGroupMapping(ctx, rbac.GroupMapping{Provider: "okta", Group: "x", Role: rbac.Viewer}); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator mapping a group: %v, want 403", err)
	}
	if _, err := h.api.SetGroupMapping(ctx, rbac.GroupMapping{Provider: "okta", Group: "ghosts", Role: rbac.Admin, Network: "nowhere"}); httpStatus(err) != http.StatusNotFound {
		t.Errorf("mapping a group to a Network that does not exist: %v, want 404", err)
	}
	for _, m := range []rbac.GroupMapping{
		{Provider: "okta", Group: "net-a-admins", Role: rbac.Admin, Network: "branch-a"},
		{Provider: "okta", Group: "net-b-admins", Role: rbac.Admin, Network: "branch-b"},
		{Provider: "okta", Group: "auditors", Role: rbac.Viewer},
	} {
		if got, err := h.api.SetGroupMapping(ctx, m); err != nil || got != m {
			t.Fatalf("mapping %+v: %+v, %v", m, got, err)
		}
	}
	if ms, err := h.api.GroupMappings(ctx); err != nil || len(ms) != 3 || ms[0].Group != "auditors" || ms[1].Network != "branch-a" {
		t.Errorf("the mappings are %+v, %v", ms, err)
	}
	if _, err := h.api.SetGroupMapping(ctx, rbac.GroupMapping{Provider: "Okta", Group: "x", Role: rbac.Viewer}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a provider that is no name: %v, want 400", err)
	}

	// The login of a person in the group of branch-a gets exactly the scope of branch-a. The identity provider itself
	// is SDN-34 to SDN-36's: here its answer, the groups of the person, goes to the mapping as the provider's login does
	tokens := rbac.New(h.st)
	expires := time.Now().Add(time.Hour)
	login := func(user string, network string, groups ...string) (*api.Client, error) {
		tok, err := tokens.IssueProviderToken(ctx, user, "okta", groups, network, expires)
		if err != nil {
			return nil, err
		}
		return h.client(tok.Secret), nil
	}
	alice, err := login("alice", "", "net-a-admins", "staff", "everyone")
	if err != nil {
		t.Fatal(err)
	}
	if who, err := alice.Whoami(ctx); err != nil || who.Name != "user:alice" || who.Role != rbac.Admin || who.Network != "branch-a" || who.User != "alice" {
		t.Fatalf("whoami of the login of the group of branch-a: %+v, %v", who, err)
	}
	if _, err := alice.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "carol", "spec": {"scope": "branch-a"}}`)); err != nil {
		t.Errorf("the admin of branch-a, by its group, changing branch-a: %v", err)
	}
	if rs, err := alice.NetworkResources(ctx, "branch-a"); err != nil || !slices.Contains(resourceNames(rs), "User/carol") {
		t.Errorf("the admin of branch-a reading branch-a: %v, %v", resourceNames(rs), err)
	}
	// Nothing beside it: not branch-b, not what is in the scope of another Network, not a call of the whole API
	_, err = alice.NetworkApply(ctx, "branch-b", usersDoc(t, `{"kind": "User", "name": "dave", "spec": {"scope": "branch-b"}}`))
	refused(t, "the admin of branch-a, by its group, changing branch-b", err, `holds the role admin for Network "branch-a" only`)
	_, err = alice.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "dave", "spec": {"scope": "branch-b"}}`))
	refused(t, "the admin of branch-a, by its group, making a User of branch-b", err, `User "dave" must be in the scope of Network "branch-a"`)
	if _, err := alice.NetworkInfo(ctx, "branch-b"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the admin of branch-a, by its group, reading branch-b: %v, want 403", err)
	}
	for name, call := range map[string]func() error{
		"get resources": func() error { _, err := alice.Resources(ctx); return err },
		"apply": func() error {
			_, err := alice.Apply(ctx, usersDoc(t, `{"kind": "User", "name": "dave", "spec": {}}`))
			return err
		},
		"list tokens":  func() error { _, err := alice.Tokens(ctx); return err },
		"get mappings": func() error { _, err := alice.GroupMappings(ctx); return err },
	} {
		refused(t, "the admin of branch-a, by its group: "+name, call(), `holds the role admin for Network "branch-a" only`)
	}

	// The group of branch-b gives branch-b and not branch-a; a person in both groups is asked for the Network
	bob, err := login("bob", "", "net-b-admins")
	if err != nil {
		t.Fatal(err)
	}
	if who, err := bob.Whoami(ctx); err != nil || who.Network != "branch-b" || who.Role != rbac.Admin {
		t.Errorf("whoami of the login of the group of branch-b: %+v, %v", who, err)
	}
	if _, err := bob.NetworkInfo(ctx, "branch-a"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the admin of branch-b, by its group, reading branch-a: %v, want 403", err)
	}
	if _, err := login("carol", "", "net-a-admins", "net-b-admins"); err == nil || !strings.Contains(err.Error(), "branch-a, branch-b") {
		t.Errorf("a login in the groups of two Networks that names none: %v, want a refusal that names both", err)
	}
	both, err := login("carol", "branch-b", "net-a-admins", "net-b-admins")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := both.NetworkInfo(ctx, "branch-b"); err != nil {
		t.Errorf("the login in both groups, for branch-b, reading branch-b: %v", err)
	}
	if _, err := both.NetworkInfo(ctx, "branch-a"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the login in both groups, for branch-b, reading branch-a: %v, want 403", err)
	}

	// A group that is mapped to a role of the whole API gives the whole API, and groups that none names give nothing
	auditor, err := login("dave", "", "auditors")
	if err != nil {
		t.Fatal(err)
	}
	if who, err := auditor.Whoami(ctx); err != nil || who.Role != rbac.Viewer || who.Network != "" {
		t.Errorf("whoami of the login of the group of auditors: %+v, %v", who, err)
	}
	if _, err := auditor.Resources(ctx); err != nil {
		t.Errorf("the viewer by its group reading the intent: %v", err)
	}
	if _, err := auditor.Apply(ctx, usersDoc(t, `{"kind": "User", "name": "dave", "spec": {}}`)); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the viewer by its group applying: %v, want 403", err)
	}
	if _, err := login("erin", "", "staff", "everyone"); err == nil || !strings.Contains(err.Error(), "no group of the login is mapped to a role") {
		t.Errorf("a login in groups that no mapping names: %v, want no token", err)
	}

	// A mapping that is taken away gives its role to no login after it
	if m, err := h.api.DeleteGroupMapping(ctx, "okta", "net-a-admins"); err != nil || m.Network != "branch-a" {
		t.Errorf("taking away the mapping of net-a-admins: %+v, %v", m, err)
	}
	if _, err := h.api.DeleteGroupMapping(ctx, "okta", "net-a-admins"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("taking away a mapping twice: %v, want 404", err)
	}
	if _, err := login("alice", "", "net-a-admins"); err == nil {
		t.Error("a login in the group of a mapping that was taken away got a token")
	}
}

// TestARoleHeldForANetworkIsHeldByUsersAndTokensAlike checks the other holders of a role for one Network: an API token,
// and a User through the user token of its login, which carries the role of the User as it is when the token is used.
// A change of the role of a token keeps its scope; widening it is a call of its own, which only an admin makes; and a
// Network that goes takes what was held for it along.
func TestARoleHeldForANetworkIsHeldByUsersAndTokensAlike(t *testing.T) {
	e := newLoginEnv(t)
	h := e.h
	ctx := context.Background()
	h.applyDoc(usersDoc(t, `{"kind": "Network", "name": "branch-a", "spec": {"vrf": "default", "ipv4Pool": "10.99.0.0/24"}}`))
	if _, err := h.api.PutUser(ctx, "alice", intent.User{DisplayName: "Alice", MaxDevices: 2, Scope: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	h.delegate("branch-a", scope.Quotas{}, scope.PermUsers)

	// A role that is held for a Network that does not exist is refused, for a token and for a User
	if _, err := h.api.CreateTokenRequest(ctx, api.TokenRequest{Name: "ghost", Role: rbac.Admin, Network: "nowhere"}); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a token for a Network that does not exist: %v, want 404", err)
	}
	if _, err := h.api.SetUserGrant(ctx, "alice", rbac.Grant{Role: rbac.Admin, Network: "nowhere"}); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a role of a User for a Network that does not exist: %v, want 404", err)
	}
	if _, err := h.api.CreateTokenRequest(ctx, api.TokenRequest{Name: "bad", Role: rbac.Admin, Network: "Branch A"}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a token for a Network that is no name: %v, want 400", err)
	}

	// The User alice holds the role admin for branch-a: her login gives a user token of that role and scope
	if ur, err := h.api.SetUserGrant(ctx, "alice", rbac.Grant{Role: rbac.Admin, Network: "branch-a"}); err != nil || ur != (rbac.UserRole{User: "alice", Role: rbac.Admin, Network: "branch-a"}) {
		t.Fatalf("giving alice the role admin for branch-a: %+v, %v", ur, err)
	}
	if rs, err := h.api.UserRoles(ctx); err != nil || len(rs) != 1 || rs[0].Network != "branch-a" {
		t.Errorf("the API roles of users are %+v, %v", rs, err)
	}
	in, err := e.client.SignIn(ctx, "alice", alicePassword)
	if err != nil || in.Role != rbac.Admin || in.Network != "branch-a" {
		t.Fatalf("the login of alice gave %+v, %v, want a user token of the role admin for branch-a", in.Token, err)
	}
	alice := e.caller(in.Secret)
	if who, err := alice.Whoami(ctx); err != nil || who.Network != "branch-a" || who.Role != rbac.Admin || who.User != "alice" {
		t.Errorf("whoami with the user token: %+v, %v", who, err)
	}
	// She holds a role, so a scoped role does not change her, nor set her password
	_, err = alice.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "alice", "spec": {"scope": "branch-a", "displayName": "Alice A"}}`))
	refused(t, "the admin of branch-a changing herself", err, `User "alice" holds an API role, and only the global roles change a User that does`)
	if _, err := alice.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "carol", "spec": {"scope": "branch-a"}}`)); err != nil {
		t.Fatalf("the admin of branch-a making a User: %v", err)
	}
	if _, err := alice.NetworkPassword(ctx, "branch-a", "carol", "a password of eight"); err != nil {
		t.Errorf("the admin of branch-a setting the password of a User of its scope: %v", err)
	}
	_, err = alice.NetworkPassword(ctx, "branch-a", "alice", "another password of eight")
	refused(t, "the admin of branch-a setting her own password", err, `holds an API role, and only the global roles set the password of a User that does`)
	if _, err := alice.NetworkPassword(ctx, "branch-a", "carol", "short"); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a password that is too short: %v, want 400", err)
	}
	if _, err := alice.NetworkPassword(ctx, "branch-a", "nobody", "a password of eight"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("the password of a User that does not exist: %v, want 404", err)
	}
	h.applyDoc(usersDoc(t,
		`{"kind": "Network", "name": "branch-b", "spec": {"vrf": "default", "ipv4Pool": "10.98.0.0/24"}}`,
		`{"kind": "User", "name": "bob", "spec": {"scope": "branch-b"}}`))
	_, err = alice.NetworkPassword(ctx, "branch-a", "bob", "a password of eight")
	refused(t, "the admin of branch-a setting the password of a User of branch-b", err, `User "bob" is not in the scope of Network "branch-a"`)

	// The role of the User changes in place, and a role for the whole API replaces the scope
	if _, err := h.api.SetUserGrant(ctx, "alice", rbac.Grant{Role: rbac.Viewer, Network: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.NetworkApply(ctx, "branch-a", usersDoc(t, `{"kind": "User", "name": "dave", "spec": {"scope": "branch-a"}}`)); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the user token of alice, a viewer of branch-a now, applying: %v, want 403", err)
	}
	if _, err := h.api.SetUserRole(ctx, "alice", rbac.Operator); err != nil {
		t.Fatal(err)
	}
	if who, err := alice.Whoami(ctx); err != nil || who.Network != "" || who.Role != rbac.Operator {
		t.Errorf("whoami after the role for the whole API: %+v, %v", who, err)
	}
	if _, err := alice.NetworkInfo(ctx, "branch-a"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a role of the whole API on the calls of a Network: %v, want 403", err)
	}
	if _, err := alice.Resources(ctx); err != nil {
		t.Errorf("a role of the whole API reading the intent: %v", err)
	}

	// An API token: its role changes and its scope stays; widening is a call that says so
	tok := h.scopedClient("ops", rbac.Operator, "branch-a")
	if changed, err := h.api.SetTokenRole(ctx, "ops", rbac.Admin); err != nil || changed.Role != rbac.Admin || changed.Network != "branch-a" {
		t.Errorf("changing the role of a scoped token: %+v, %v", changed, err)
	}
	if _, err := tok.Resources(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the token, an admin of branch-a, reading the intent: %v, want 403", err)
	}
	if _, err := h.api.SetTokenGrant(ctx, "ops", rbac.Grant{Role: rbac.Admin, Network: "nowhere"}); httpStatus(err) != http.StatusNotFound {
		t.Errorf("scoping a token to a Network that does not exist: %v, want 404", err)
	}
	if changed, err := h.api.SetTokenGrant(ctx, "ops", rbac.Grant{Role: rbac.Viewer}); err != nil || changed.Network != "" {
		t.Errorf("widening a scoped token to the whole API: %+v, %v", changed, err)
	}
	if _, err := tok.Resources(ctx); err != nil {
		t.Errorf("the token, a viewer of the whole API now, reading the intent: %v", err)
	}
	if _, err := h.api.SetTokenGrant(ctx, "ops", rbac.Grant{Role: rbac.Admin, Network: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.SetTokenGrant(ctx, rbac.FirstAdmin, rbac.Grant{Role: rbac.Admin, Network: "branch-a"}); httpStatus(err) != http.StatusConflict {
		t.Errorf("scoping the last admin token away: %v, want 409", err)
	}
	if list, err := h.api.Tokens(ctx); err != nil || len(list) != 2 || list[1].Name != "ops" || list[1].Network != "branch-a" {
		t.Errorf("the tokens are %+v, %v, want the token ops held for branch-a", list, err)
	}

	// A Network that goes takes the roles that were held for it, and its delegation: a Network made again under the name
	// starts with none. The Network goes when what is in its scope has gone.
	for _, d := range []struct{ kind, name string }{{intent.KindUser, "carol"}, {intent.KindUser, "alice"}} {
		if _, err := h.api.Delete(ctx, d.kind, d.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.api.Delete(ctx, intent.KindNetwork, "branch-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := tok.Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the token held for a Network that was deleted: %v, want 401", err)
	}
	if ds, err := h.api.Delegations(ctx); err != nil || len(ds) != 0 {
		t.Errorf("the delegations after the Network went are %+v, %v", ds, err)
	}
}
