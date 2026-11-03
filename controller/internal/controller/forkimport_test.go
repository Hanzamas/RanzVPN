package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/forkimport"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// The import of a Config file of the fork through the controller (SDN-27, #203; ADR-0031 decision 11): the document that
// the importer makes, which `ranz import-config` writes and `ranz apply -f` takes, is applied through the HTTP API, and
// the tests check what the controller makes of it and what the simulated nodes receive. The vpntest harness runs the
// scenarios forkimport and forkimport-exact of tests/explain through the data plane of real nodes, and the test
// TestExplainScenarios of this package runs them through the API.

// sampleConfigFile is the sample Config file of the import, whose Virtual Hubs are LAB and OFFICE.
const sampleConfigFile = "../../../tests/golden/configimport/sample.config"

// defaultHubConfig is a Config file with the Virtual Hub DEFAULT, which every server has: one user and an access list of
// one entry, which denies Telnet.
const defaultHubConfig = `declare root
{
declare ServerConfiguration
{
}
declare VirtualHUB
{
declare DEFAULT
{
declare AccessList
{
declare 1
{
bool Active true
bool Discard true
uint Priority 100
uint Protocol 6
uint DestPortStart 23
uint DestPortEnd 23
}
}
declare SecurityAccountDatabase
{
declare UserList
{
declare admin
{
}
}
}
}
}
}
`

// newImportHarness returns a harness whose controller made the intent of a first install at its first start (SDN-3,
// #179), the controller that an importer meets. The ULAs of the VRFs that the import makes are drawn from crypto/rand.
func newImportHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, rq: rqlitetest.Fresh(t), defaults: true}
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

// importOf imports the Config file whose text is b, with opts.
func importOf(t *testing.T, b []byte, opts forkimport.Options) forkimport.Result {
	t.Helper()
	root, err := forkimport.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	res, err := forkimport.Import(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// importedNode returns the JSON of the Node name, a device of the User owner with the key of nodeKey(i), in the VRF vrf at
// the address address; the Network of an imported hub is named like its VRF.
func importedNode(name, owner string, i int, vrf, address string) string {
	return fmt.Sprintf(`{"kind": "Node", "name": %q, "spec": {"publicKey": %q, "owner": %q, "vrfs": [%q], "addresses": {%q: %q}}}`,
		name, base64.StdEncoding.EncodeToString(nodeKey(i).Public()), owner, vrf, vrf, address)
}

// checkFirstInstallKept checks that every resource of first, the intent of a first install, is in rs as it was.
func checkFirstInstallKept(t *testing.T, first, rs []intent.Resource) {
	t.Helper()
	have := map[string]intent.Resource{}
	for _, r := range rs {
		have[r.Kind+"/"+r.Name] = r
	}
	for _, r := range first {
		if got, ok := have[r.Kind+"/"+r.Name]; !ok || string(got.Spec) != string(r.Spec) {
			t.Errorf("%s %s of the first install is %s after the import, was %s", r.Kind, r.Name, got.Spec, r.Spec)
		}
	}
}

// The first criterion of #203: the sample Config file imports into an intent that applies cleanly, to a controller of a
// first install, which is where an importer meets one. The controller makes the revision, holds each resource that the
// document names and leaves those of the first install as they were. The users and groups are those of the fork, a User
// has no password, and applying the document again changes nothing.
func TestTheImportOfTheSampleConfigAppliesToAFirstInstall(t *testing.T) {
	ctx := context.Background()
	h := newImportHarness(t)
	first, err := h.api.Resources(ctx)
	if err != nil || len(first) != 3 {
		t.Fatalf("the first install is %+v (%v), want its three resources", first, err)
	}
	b, err := os.ReadFile(sampleConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	imported := importOf(t, b, forkimport.Options{Pools: map[string]string{"LAB": "10.0.0.0/24", "OFFICE": "10.1.0.0/24"}})

	res, err := h.api.Apply(ctx, imported.Document)
	if err != nil {
		t.Fatalf("the import of the sample Config file does not apply to a controller of a first install: %v", err)
	}
	if res.Revision != 2 || len(res.Nodes) != 0 {
		t.Errorf("the apply made revision %d and changed %+v, want revision 2, after the one of the first start, and no node", res.Revision, res.Nodes)
	}
	rs, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range rs {
		have[r.Kind+"/"+r.Name] = true
	}
	for _, r := range imported.Document.Resources {
		if !have[r.Kind+"/"+r.Name] {
			t.Errorf("the intent has no %s %s after the apply", r.Kind, r.Name)
		}
	}
	checkFirstInstallKept(t, first, rs)

	users, err := h.api.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	groupsOf := map[string][]string{}
	for _, u := range users {
		groupsOf[u.Name] = u.Groups
		if u.HasPassword {
			t.Errorf("User %s has a password after the import, and the passwords of the fork are not imported", u.Name)
		}
	}
	if len(users) != 11 {
		t.Errorf("the controller lists %d users, want the 8 of LAB and the 3 of OFFICE", len(users))
	}
	for name, want := range map[string][]string{"alice": {"alice", "staff"}, "bob": {"staff"}, "carol": {"carol"}, "dave": {"ops"}, "erin": {"guests"},
		"frank": {"guests"}, "ops": {"ops"}, "srv": nil, "kim": nil, "lee": nil, "max": nil} {
		if got := groupsOf[name]; !slices.Equal(got, want) {
			t.Errorf("User %s belongs to %v, want %v", name, got, want)
		}
	}
	groups, err := h.api.Groups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	membersOf := map[string][]string{}
	for _, g := range groups {
		membersOf[g.Name] = g.Members
	}
	for name, want := range map[string][]string{"alice": {"alice"}, "carol": {"carol"}, "guests": {"erin", "frank"}, "ops": {"dave", "ops"}, "staff": {"alice", "bob"}} {
		if got := membersOf[name]; !slices.Equal(got, want) {
			t.Errorf("Group %s has the members %v, want %v", name, got, want)
		}
	}
	if len(groups) != 5 {
		t.Errorf("the controller lists %d groups, want the 3 of LAB and the 2 that its access list names", len(groups))
	}

	before := h.resources()
	if _, err := h.api.Apply(ctx, imported.Document); err != nil {
		t.Fatalf("the second apply of the import: %v", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a second apply of the same import changed the intent:\n--- before\n%s\n--- after\n%s", before, after)
	}
}

// The Virtual Hub DEFAULT, which every server has, does not replace the VRF default of a controller of a first install:
// the hub is VRF default-2 with its own Network and Policies, the VRF default, its Network and the starter rule that allows
// all in it are as they were, and the access list of the hub judges the Nodes of its VRF alone.
func TestAnImportedHubNamedDefaultLeavesTheFirstInstallAlone(t *testing.T) {
	ctx := context.Background()
	h := newImportHarness(t)
	first, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	imported := importOf(t, []byte(defaultHubConfig), forkimport.Options{Pools: map[string]string{"DEFAULT": "10.7.0.0/24"}})
	if _, err := h.api.Apply(ctx, imported.Document); err != nil {
		t.Fatalf("the import of the hub DEFAULT does not apply to a controller of a first install: %v", err)
	}
	rs, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkFirstInstallKept(t, first, rs)
	have := map[string]bool{}
	for _, r := range rs {
		have[r.Kind+"/"+r.Name] = true
	}
	for _, want := range []string{"VRF/default-2", "Network/default-2", "Policy/default-2-acl-1", "Policy/default-2-default-allow", "User/admin"} {
		if !have[want] {
			t.Errorf("the intent has no %s after the import of the hub DEFAULT", want)
		}
	}

	if _, err := h.api.Apply(ctx, usersDoc(t,
		importedNode("a", "admin", 1, "default-2", "10.7.0.1"),
		importedNode("b", "admin", 2, "default-2", "10.7.0.2"))); err != nil {
		t.Fatal(err)
	}
	telnet, err := h.api.Explain(ctx, explain.Query{From: "a", To: "b", Protocol: "tcp", SourcePort: 40001, Port: 23})
	if err != nil {
		t.Fatal(err)
	}
	if telnet.Verdict.Delivered || telnet.Verdict.Node != "a" || telnet.Verdict.Reason != explain.DropPolicy || telnet.Rules()["a"] != "default-2-acl-1" {
		t.Errorf("Telnet from a to b ends %+v with the rules %v, want it dropped by a with the rule default-2-acl-1 of the access list", telnet.Verdict, telnet.Rules())
	}
	ssh, err := h.api.Explain(ctx, explain.Query{From: "a", To: "b", Protocol: "tcp", SourcePort: 40002, Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if !ssh.Verdict.Delivered || ssh.Verdict.Node != "b" || ssh.Rules()["a"] != "default-2-default-allow" || ssh.Rules()["b"] != "default-2-default-allow" {
		t.Errorf("SSH from a to b ends %+v with the rules %v, want it delivered to b by the rule that lets through what no entry matches", ssh.Verdict, ssh.Rules())
	}
}

// The second criterion of #203 at the control protocol: the Groups of an imported hub are the tags that the nodes of its
// users hold, in their own object and in the Peer object that each other node holds of them, and the access list is the
// rules that they hold. Nodes that are connected and have acknowledged their state judge a flow as the fork judged it:
// alice may use SSH to the server, which an entry denies to every other, and what no entry matches is let through.
func TestTheGroupsOfAnImportedHubAreTheTagsOfItsNodes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	imported := importOf(t, mustRead(t, sampleConfigFile), forkimport.Options{Hubs: []string{"LAB"}, Pools: map[string]string{"LAB": "10.0.0.0/24"}})
	if _, err := h.api.Apply(ctx, imported.Document); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Apply(ctx, usersDoc(t,
		importedNode("alice", "alice", 1, "lab", "10.0.0.1"),
		importedNode("bob", "bob", 2, "lab", "10.0.0.2"),
		importedNode("srv", "srv", 3, "lab", "10.0.0.10"))); err != nil {
		t.Fatal(err)
	}
	alice, bob, srv := h.sim("alice", nodeKey(1)), h.sim("bob", nodeKey(2)), h.sim("srv", nodeKey(3))
	for _, s := range []*sim{alice, bob, srv} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	for _, c := range []struct {
		node  *sim
		self  []string
		peers string
	}{
		{alice, []string{"alice", "staff"}, "map[bob:[staff] srv:[]]"},
		{bob, []string{"staff"}, "map[alice:[alice staff] srv:[]]"},
		{srv, nil, "map[alice:[alice staff] bob:[staff]]"},
	} {
		self, peers, rules := userHeld(c.node)
		if !slices.Equal(self, c.self) || fmt.Sprint(peers) != c.peers {
			t.Errorf("%s holds the tags %v and the peers %v, want %v and %s", c.node.name, self, peers, c.self, c.peers)
		}
		if len(rules) == 0 {
			t.Errorf("%s holds no rule, and the access list of its hub is rules", c.node.name)
		}
		for _, name := range rules {
			if !strings.HasPrefix(name, "lab-") {
				t.Errorf("%s holds the rule %s, which is no Policy of the imported hub", c.node.name, name)
			}
		}
	}

	for _, c := range []struct {
		name       string
		q          explain.Query
		delivered  bool
		node, rule string
	}{
		{"alice uses SSH to the server", explain.Query{From: "alice", To: "srv", Protocol: "tcp", SourcePort: 40001, Port: 22}, true, "srv", "lab-acl-1"},
		{"bob does not", explain.Query{From: "bob", To: "srv", Protocol: "tcp", SourcePort: 40002, Port: 22}, false, "bob", "lab-acl-2"},
		{"what no entry matches is let through", explain.Query{From: "bob", To: "alice"}, true, "alice", "lab-default-allow"},
	} {
		r, err := h.api.Explain(ctx, c.q)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if r.Verdict.Delivered != c.delivered || r.Verdict.Node != c.node || r.Rules()[c.q.From] != c.rule {
			t.Errorf("%s: the verdict is %+v with the rules %v, want delivered %v at %s by the rule %s", c.name, r.Verdict, r.Rules(), c.delivered, c.node, c.rule)
		}
	}
}

// mustRead returns the contents of the file name.
func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
