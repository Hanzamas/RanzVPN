// Licence enforcement in the controller conformance seam (SDN-30 #206, ADR-0036): the node cap
// of the licence in force (an apply that adds a Node above it is refused, and a node above it
// is refused on its control stream), the Enterprise features (the EVPN and BGP resources, and
// changes of the intent while the store is a cluster), and the perpetual fallback licence of an
// expired subscription. The licence keys are signed with testVendor, the vendor key that the
// harness's controller verifies.
package controller_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// testVendor stands in for the vendor key that release builds verify licence keys with.
var testVendor = ed25519.NewKeyFromSeed(slices.Repeat([]byte{0x5a}, ed25519.SeedSize))

// year is a subscription that runs for the whole test.
const year = 365 * 24 * time.Hour

// TestPersonalKeyRefusesNodesAboveItsCap is the first criterion of SDN-30: with a Personal key
// of 2 nodes, an apply that adds a third Node is refused with a message that names the cap and
// the node, and changes nothing. When the intent holds more Nodes than the cap (here after a
// Business key of 3 nodes gave way to the Personal key again), the node above the cap is refused
// on its control stream, also when it connects again, and loses its desired state.
func TestPersonalKeyRefusesNodesAboveItsCap(t *testing.T) {
	h := newHarness(t)
	if st := h.licence(); st.Tier != licence.Personal || st.State != licence.StateNone || st.Nodes != licence.PersonalNodes {
		t.Errorf("without a licence key the licence in force is %+v, want the Personal tier of %d nodes", st, licence.PersonalNodes)
	}
	personal := licence.Licence{ID: "personal-1", Licensee: "Test", Tier: licence.Personal, Nodes: 2, Expires: time.Now().Add(year)}
	if st := h.setLicence(personal); st.Tier != licence.Personal || st.State != licence.StateActive || st.Nodes != 2 {
		t.Errorf("the licence in force with the Personal key is %+v", st)
	}
	h.applyDoc(nodesDoc(2))
	before := h.resources()
	_, err := h.api.Apply(context.Background(), nodesDoc(3))
	want := `refused by the licence: the Personal licence in force allows 2 nodes, and this apply would make 3 (new: Node "node-03"); a Business or Enterprise licence key raises the cap`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("an apply above the cap gave %v, want an error that says %q", err, want)
	}
	if after := h.resources(); after != before {
		t.Errorf("an apply above the cap changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}

	h.setLicence(licence.Licence{ID: "business-1", Licensee: "Test", Tier: licence.Business, Nodes: 3, Expires: time.Now().Add(year)})
	h.applyDoc(nodesDoc(3))
	n3 := h.sim(nodeName(3), nodeKey(3))
	n3.update(t)
	h.waitNode(nodeName(3), 1, true)
	// node-01 got node-03 as a peer in generation 2, and receives it in full.
	n1 := h.sim(nodeName(1), nodeKey(1))
	n1.update(t)
	h.waitNode(nodeName(1), 2, true)

	h.setLicence(personal)
	golden(t, "refuse-licence-cap", n3.refusal(t))
	// node-01 loses its peer node-03, as the next generation.
	n1.update(t)
	h.waitNode(nodeName(1), 3, true)
	h.checkState(n1)
	nodes, err := h.api.Nodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(nodes, func(n controller.NodeStatus) bool { return n.Name == nodeName(3) }); i < 0 || !nodes[i].Unlicensed {
		t.Errorf("the nodes are %+v, want %s listed as unlicensed", nodes, nodeName(3))
	}
	n3.start(h)
	golden(t, "refuse-licence-cap", n3.refusal(t))
}

// TestRollbackRefusesNodesAboveTheCap checks a rollback against the node cap like an apply
// (SDN-13 #189 with ADR-0036): a rollback to a revision with more Nodes than the licence in force
// allows, made under a larger licence, is refused with a message that names the cap and the
// node, and makes no revision.
func TestRollbackRefusesNodesAboveTheCap(t *testing.T) {
	h := newHarness(t)
	h.setLicence(licence.Licence{ID: "business-1", Licensee: "Test", Tier: licence.Business, Nodes: 3, Expires: time.Now().Add(year)})
	h.applyDoc(nodesDoc(3))
	if _, err := h.api.Delete(context.Background(), intent.KindNode, nodeName(3)); err != nil {
		t.Fatal(err)
	}
	h.setLicence(licence.Licence{ID: "personal-1", Licensee: "Test", Tier: licence.Personal, Nodes: 2, Expires: time.Now().Add(year)})
	before := h.resources()

	_, err := h.api.Rollback(context.Background(), 1)
	want := `refused by the licence: the Personal licence in force allows 2 nodes, and this rollback would make 3 (new: Node "node-03"); a Business or Enterprise licence key raises the cap`
	if httpStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), want) {
		t.Errorf("a rollback above the cap gave %v, want a 403 that says %q", err, want)
	}
	if after := h.resources(); after != before {
		t.Errorf("a rollback above the cap changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if got, want := h.revisionLog(), "1 apply\n2 delete\n"; got != want {
		t.Errorf("the revisions are\n%s\nwant\n%s", got, want)
	}
}

// TestEnterpriseFeaturesNeedEnterpriseKey is the second criterion of SDN-30 for EVPN and BGP:
// without a licence key, and with a Personal or a Business one, an apply that declares a BgpPeer
// or an EvpnPeer is refused by the licence. With an Enterprise key it passes the licence, and the
// intent refuses the kinds it does not hold yet (SDN-25 brings them).
func TestEnterpriseFeaturesNeedEnterpriseKey(t *testing.T) {
	h := newHarness(t)
	h.apply("apply1.json")
	for _, tier := range []licence.Tier{"", licence.Personal, licence.Business} {
		if tier != "" {
			h.setLicence(licence.Licence{ID: "lic-1", Licensee: "Test", Tier: tier, Nodes: 5, Expires: time.Now().Add(year)})
		}
		inForce := tier
		if inForce == "" {
			inForce = licence.Personal
		}
		checkEVPNRefused(t, h, inForce)
	}
	st := h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)})
	if !st.Allows(licence.FeatureEVPN) || !st.Allows(licence.FeatureHA) {
		t.Errorf("the Enterprise licence in force has the features %v", st.Features)
	}
	checkEVPNAllowed(t, h)
}

// TestControllerHANeedsEnterpriseKey is the second criterion of SDN-30 for controller high
// availability: once the controller's store is a cluster of two members, a Business licence
// refuses every change of the intent, and an Enterprise licence allows it again.
func TestControllerHANeedsEnterpriseKey(t *testing.T) {
	rqlitetest.Own(t) // it joins a second member to rqlited
	h := newHarness(t)
	h.apply("apply1.json")
	h.setLicence(licence.Licence{ID: "biz-1", Licensee: "Test", Tier: licence.Business, Nodes: 50, Expires: time.Now().Add(year)})
	rqlitetest.Join(t, h.rq, "2")
	h.waitMembers(2)

	want := "refused by the licence: the store of this controller is a cluster of 2 members, and controller high availability is an Enterprise feature; the licence in force is Business"
	if _, err := h.api.Apply(context.Background(), h.document("apply2.json")); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("an apply in a cluster gave %v, want an error that says %q", err, want)
	}
	if _, err := h.api.Delete(context.Background(), intent.KindNetwork, "corp-lan"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a delete in a cluster gave %v, want an error that says %q", err, want)
	}

	h.setLicence(licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 50, Expires: time.Now().Add(year)})
	res := h.apply("apply2.json")
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "branch-2", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("apply2.json in the cluster changed %+v, want %+v", res.Nodes, want)
	}
	b2 := h.sim("branch-2", keyBranch2)
	golden(t, "apply2-branch-2", b2.update(t))
	h.waitNode("branch-2", 1, true)
	// Stop the controller while both members still run, so no write waits for a lost quorum.
	h.stop()
}

// TestExpiredSubscriptionKeepsFallbackVersion is the third criterion of SDN-30: an Enterprise
// subscription of 11 nodes that expired keeps its tier and node count on a controller whose
// version its perpetual fallback licence covers (0.2 for a controller of 0.2.3, a bugfix release
// of it). A fallback licence for an older version, or none, leaves the Personal tier: the
// eleventh node is refused on its stream and the Enterprise features are refused.
func TestExpiredSubscriptionKeepsFallbackVersion(t *testing.T) {
	h := newHarnessAt(t, "0.2.3")
	sub := licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 11, Expires: time.Now().Add(-24 * time.Hour), FallbackVersion: "0.2"}
	st := h.setLicence(sub)
	if st.State != licence.StateFallback || st.Tier != licence.Enterprise || st.Nodes != 11 || st.Version != "0.2.3" {
		t.Errorf("the licence in force is %+v, want the fallback licence of the Enterprise subscription with 11 nodes", st)
	}
	h.applyDoc(nodesDoc(11))
	n11 := h.sim(nodeName(11), nodeKey(11))
	n11.update(t)
	h.waitNode(nodeName(11), 1, true)
	h.checkState(n11)
	checkEVPNAllowed(t, h)

	sub.FallbackVersion = "0.1"
	st = h.setLicence(sub)
	if st.State != licence.StateExpired || st.Tier != licence.Personal || st.Nodes != licence.PersonalNodes {
		t.Errorf("with a fallback licence for 0.1 the licence in force is %+v, want the Personal tier", st)
	}
	golden(t, "refuse-licence-expired", n11.refusal(t))
	checkEVPNRefused(t, h, licence.Personal)

	sub.FallbackVersion = ""
	if st = h.setLicence(sub); st.State != licence.StateExpired || st.Tier != licence.Personal {
		t.Errorf("without a fallback licence the licence in force is %+v, want the Personal tier", st)
	}
	n11.start(h)
	golden(t, "refuse-licence-expired", n11.refusal(t))
}

// TestSubscriptionExpiresWhileRunning: when an active subscription expires while the controller
// runs, its fallback licence takes over and the eleventh node stays served; when a subscription
// without one expires, the Personal tier takes over and the eleventh node is refused.
func TestSubscriptionExpiresWhileRunning(t *testing.T) {
	h := newHarness(t)
	sub := licence.Licence{ID: "biz-1", Licensee: "Test", Tier: licence.Business, Nodes: 11, Expires: time.Now().Add(year)}
	h.setLicence(sub)
	h.applyDoc(nodesDoc(11))
	n11 := h.sim(nodeName(11), nodeKey(11))
	n11.update(t)
	h.waitNode(nodeName(11), 1, true)

	sub.Expires, sub.FallbackVersion = time.Now().Add(3*time.Second), version.Version
	if st := h.setLicence(sub); st.State != licence.StateActive {
		t.Fatalf("the subscription is %s, want it active until it expires", st.State)
	}
	h.waitLicence(licence.StateFallback)
	doc := nodesDoc(0)
	doc.Resources[0].Spec = json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}`)
	h.applyDoc(doc)
	n11.update(t)
	h.waitNode(nodeName(11), 2, true)
	h.checkState(n11)

	sub.Expires, sub.FallbackVersion = time.Now().Add(3*time.Second), ""
	if st := h.setLicence(sub); st.State != licence.StateActive {
		t.Fatalf("the subscription is %s, want it active until it expires", st.State)
	}
	golden(t, "refuse-licence-expired", n11.refusal(t))
	if st := h.licence(); st.State != licence.StateExpired || st.Tier != licence.Personal {
		t.Errorf("after the expiry the licence in force is %+v, want the Personal tier", st)
	}
}

// TestRevocationListRefusesAKey is the second criterion of SEC-5 (#283): the controller refuses a
// licence key whose id is on the revocation list, and accepts an equivalent key that is not on it.
func TestRevocationListRefusesAKey(t *testing.T) {
	h := newHarnessRevocations(t)
	leaked := licence.Licence{ID: "biz-leaked", Licensee: "Example Ltd", Tier: licence.Business, Nodes: 20, Expires: time.Now().Add(year)}
	h.writeRevocations(licence.Revocations{Issued: time.Now(), IDs: []string{leaked.ID}})
	h.reloadRevocations()

	key, err := licence.Sign(testVendor, leaked)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("refused by the licence: the Business licence key biz-leaked of Example Ltd is on the revocation list and cannot be installed (watermark %s)",
		licence.WatermarkFor(leaked.Licensee))
	if _, err := h.api.SetLicence(context.Background(), key); httpStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), want) {
		t.Errorf("installing the revoked key gave %v, want a 403 that says %q", err, want)
	}
	if st := h.licence(); st.State != licence.StateNone {
		t.Errorf("after the refused install the licence in force is %+v, want no key installed", st)
	}

	// An equivalent key with another id is not on the list: it installs and is active.
	equivalent := leaked
	equivalent.ID = "biz-fresh"
	if st := h.setLicence(equivalent); st.State != licence.StateActive || st.Tier != licence.Business || st.Nodes != 20 {
		t.Errorf("the equivalent key is %+v, want an active Business licence of 20 nodes", st)
	}
}

// TestRevocationListDeliveredByUpdateIsApplied is the third criterion of SEC-5 (#283): a signed
// revocation list delivered through the update channel is applied by the controller, so an installed
// key the list revokes drops to the Personal tier while the core tunnel keeps working. A list that
// is not vendor-signed is ignored, so only a signed list takes effect.
func TestRevocationListDeliveredByUpdateIsApplied(t *testing.T) {
	h := newHarnessRevocations(t)
	leaked := licence.Licence{ID: "biz-leaked", Licensee: "Example Ltd", Tier: licence.Business, Nodes: 20, Expires: time.Now().Add(year)}
	if st := h.setLicence(leaked); st.State != licence.StateActive {
		t.Fatalf("before any revocation the installed key is %s, want active", st.State)
	}

	// The update delivers a list that is not signed by a vendor key: the controller ignores it.
	foreign := ed25519.NewKeyFromSeed(slices.Repeat([]byte{0x09}, ed25519.SeedSize))
	unsigned, err := licence.SignRevocations(foreign, licence.Revocations{Issued: time.Now(), IDs: []string{leaked.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.revPath, []byte(unsigned), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := h.c.ReloadRevocations(context.Background()); err != nil || st.State != licence.StateActive {
		t.Errorf("a list not signed by the vendor changed the licence to %+v (err %v), want it still active", st, err)
	}

	// The update delivers the vendor-signed list: the controller applies it and the installed key
	// is revoked, so the Personal tier is in force.
	h.writeRevocations(licence.Revocations{Issued: time.Now(), IDs: []string{leaked.ID}})
	st := h.reloadRevocations()
	if st.State != licence.StateRevoked || st.Tier != licence.Personal || st.Nodes != licence.PersonalNodes {
		t.Errorf("after the signed list the licence in force is %+v, want the Personal tier, revoked", st)
	}
	if st.Key == nil || st.Key.ID != leaked.ID {
		t.Errorf("the revoked licence in force does not name the key: %+v", st.Key)
	}
	if got := h.licence(); got.State != licence.StateRevoked {
		t.Errorf("the API reports %+v, want the key revoked", got)
	}
}

// writeRevocations signs r with testVendor and writes it to the update channel's path, as an update
// delivers the revocation list (SEC-5 #283).
func (h *harness) writeRevocations(r licence.Revocations) {
	h.t.Helper()
	signed, err := licence.SignRevocations(testVendor, r)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.revPath, []byte(signed), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// reloadRevocations applies the revocation list the update channel delivered and returns the licence
// in force then.
func (h *harness) reloadRevocations() licence.Status {
	h.t.Helper()
	st, err := h.c.ReloadRevocations(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

// checkEVPNRefused checks that the licence in force, of tier inForce, refuses the EVPN and BGP
// resources.
func checkEVPNRefused(t *testing.T, h *harness, inForce licence.Tier) {
	t.Helper()
	_, err := h.api.Apply(context.Background(), peersDoc())
	for _, want := range []string{
		"refused by the licence:",
		fmt.Sprintf(`BgpPeer "fabric-1": EVPN and BGP is an Enterprise feature, and the licence in force is %s`, inForce),
		fmt.Sprintf(`EvpnPeer "fabric-2": EVPN and BGP is an Enterprise feature, and the licence in force is %s`, inForce),
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("with the %s licence in force, an apply of EVPN and BGP peers gave %v, want an error that says %q", inForce, err, want)
		}
	}
}

// checkEVPNAllowed checks that the licence in force lets the EVPN and BGP resources through to
// the intent, which does not hold them yet.
func checkEVPNAllowed(t *testing.T, h *harness) {
	t.Helper()
	_, err := h.api.Apply(context.Background(), peersDoc())
	if err == nil || strings.Contains(err.Error(), "licence") || !strings.Contains(err.Error(), `BgpPeer "fabric-1": the kind must be`) {
		t.Errorf("with an Enterprise licence in force, an apply of EVPN and BGP peers gave %v, want the intent to refuse the kinds", err)
	}
}

// peersDoc declares a BGP and an EVPN peer, the resources of EVPN and BGP (ADR-0032).
func peersDoc() intent.Document {
	return intent.Document{Resources: []intent.Resource{
		{Kind: "BgpPeer", Name: "fabric-1", Spec: json.RawMessage(`{}`)},
		{Kind: "EvpnPeer", Name: "fabric-2", Spec: json.RawMessage(`{}`)},
	}}
}

// nodesDoc declares the VRF corp and the Nodes node-01 to node-<n> in it.
func nodesDoc(n int) intent.Document {
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
	}}
	for i := 1; i <= n; i++ {
		spec, err := json.Marshal(intent.Node{PublicKey: base64.StdEncoding.EncodeToString(nodeKey(i).Public()), VRFs: []string{"corp"}})
		if err != nil {
			panic(err)
		}
		doc.Resources = append(doc.Resources, intent.Resource{Kind: intent.KindNode, Name: nodeName(i), Spec: spec})
	}
	return doc
}

func nodeName(i int) string {
	return fmt.Sprintf("node-%02d", i)
}

// nodeKey returns the static key of node i of nodesDoc.
func nodeKey(i int) *keys.Soft {
	return fixedKey(byte(100 + i))
}

// setLicence installs a licence key that holds l, signed with testVendor, and returns the
// licence in force.
func (h *harness) setLicence(l licence.Licence) licence.Status {
	h.t.Helper()
	key, err := licence.Sign(testVendor, l)
	if err != nil {
		h.t.Fatal(err)
	}
	st, err := h.api.SetLicence(context.Background(), key)
	if err != nil {
		h.t.Fatalf("installing the licence key of %+v: %v", l, err)
	}
	return st
}

// licence returns the licence in force as the API reports it.
func (h *harness) licence() licence.Status {
	h.t.Helper()
	st, err := h.api.Licence(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

// waitLicence waits until the API reports the licence in force in state.
func (h *harness) waitLicence(state licence.State) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		st := h.licence()
		if st.State == state {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the licence in force did not reach the state %s within %v: %+v", state, waitTimeout, st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitMembers waits until the controller's store is a cluster of n voting members.
func (h *harness) waitMembers(n int) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		got, err := h.st.Members(context.Background())
		if err == nil && got == n {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the store did not reach %d members within %v: %d, %v", n, waitTimeout, got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
