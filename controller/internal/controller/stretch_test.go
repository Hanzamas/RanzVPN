// The Stretches of the L2 Networks in the controller conformance seam (SDN-63 #290, ADR-0032 amendment of 2026-10-22): a Stretch is
// made, listed, changed and deleted through the API, with the defaults of the ticket; each refusal is made before the apply and
// names the Node and the Network; a gateway that reports the Capability evpn takes the Stretch and one that does not is refused with
// the Capability named; and past the licence that has EVPN and BGP the Stretch is no longer part of the desired state of its gateway.
// The simulated gateways are the nodes of the seam: no frame moves yet.
package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// capsEVPN is capsServer with the Capability evpn: a Windows Server on which the VXLAN module of the node runs.
var capsEVPN = func() *controlpb.Capabilities {
	c := proto.Clone(capsServer).(*controlpb.Capabilities)
	c.Evpn = true
	return c
}()

// stretchNode declares the Node name with the static key key in VRF dc, and the further fields of its spec that extra holds, each
// after a comma.
func stretchNode(name string, key *keys.Soft, extra string) intent.Resource {
	spec := `{"publicKey": "` + base64.StdEncoding.EncodeToString(key.Public()) + `", "vrfs": ["dc"]` + extra + `}`
	return intent.Resource{Kind: intent.KindNode, Name: name, Spec: json.RawMessage(spec)}
}

// stretchOf declares the Stretch name of the Node gateway and the L2 Network network on the VNI vni, with the route target
// 65000:vni and the further fields of its spec that extra holds, each after a comma.
func stretchOf(name, gateway, network string, vni int, extra string) intent.Resource {
	spec := fmt.Sprintf(`{"gateway": %q, "network": %q, "vni": %d, "routeTargets": ["65000:%d"]%s}`, gateway, network, vni, vni, extra)
	return intent.Resource{Kind: intent.KindStretch, Name: name, Spec: json.RawMessage(spec)}
}

// stretchDoc declares VRF dc with the L2 Networks dc-l2 and dc-l2b and the Nodes gw-1, gw-2 and lan-1 in it, the last with the
// further fields of its spec that lanExtra holds, and the resources extra.
func stretchDoc(lanExtra string, extra ...intent.Resource) intent.Document {
	return intent.Document{Resources: append([]intent.Resource{
		{Kind: intent.KindVRF, Name: "dc", Spec: json.RawMessage(`{"id": 30, "ula": "fd30:1:2::/48"}`)},
		{Kind: intent.KindNetwork, Name: "dc-l2", Spec: json.RawMessage(`{"vrf": "dc", "mode": "L2"}`)},
		{Kind: intent.KindNetwork, Name: "dc-l2b", Spec: json.RawMessage(`{"vrf": "dc", "mode": "L2"}`)},
		stretchNode("gw-1", keyBranch1, ""),
		stretchNode("gw-2", keyBranch2, ""),
		stretchNode("lan-1", keyLab1, lanExtra),
	}, extra...)}
}

// stretchEnterprise is an Enterprise licence that runs for the whole test, which has EVPN and BGP.
func stretchEnterprise() licence.Licence {
	return licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(year)}
}

// stretchNetwork returns the Network object named name among the objects that the update in m sets, nil for none.
func stretchNetwork(m *controlpb.ControlMessage, name string) *controlpb.Network {
	for _, o := range m.GetUpdate().GetSet() {
		if nw := o.GetNetwork(); nw != nil && nw.GetName() == name {
			return nw
		}
	}
	return nil
}

// stretchQuiet checks that no update reaches the simulated node s within quietTimeout.
func stretchQuiet(t *testing.T, s *sim) {
	t.Helper()
	select {
	case u := <-s.Updates:
		t.Errorf("%s: got the update to generation %d, want none: it is no gateway of the Stretch", s.name, u.GetGeneration())
	case <-time.After(quietTimeout):
	}
}

// stretchList returns the Stretches as the API lists them, as JSON.
func (h *harness) stretchList() string {
	h.t.Helper()
	list, err := h.api.Stretches(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return asJSON(h.t, list)
}

// TestStretchLifecycle is the first criterion of SDN-63: a Stretch is made, listed, changed and deleted through the API. The
// controller fills in the defaults of the ticket, each change is one Generation of the gateway alone, whose update sets the Network
// object with the Stretch, or without it once the Stretch is deleted, and the other node of the VRF keeps its Generation.
func TestStretchLifecycle(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.setLicence(stretchEnterprise())
	h.applyDoc(stretchDoc(""))
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsEVPN
	gw.start(h)
	lan := h.sim("lan-1", keyLab1)
	gw.update(t)
	lan.update(t)
	h.waitNode("gw-1", 1, true)
	h.waitNode("lan-1", 1, true)
	if got := h.stretchList(); got != `[]` {
		t.Errorf("before the first Stretch the API lists %s, want none", got)
	}

	// Made: the defaults are 10,000 remote MAC addresses, a stale timer of 120 s, the BUM rate limit that is on, and irb off
	res, err := h.api.Apply(ctx, stretchDoc("", stretchOf("dc-stretch", "gw-1", "dc-l2", 5010, ``)))
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the Stretch changed %+v, want %+v", res.Nodes, want)
	}
	m := gw.update(t)
	want := &controlpb.Stretch{Vni: 5010, RouteTargets: []string{"65000:5010"}, BumRateLimit: intent.DefaultBUMRateLimit, MacImportLimit: 10000, StaleTimer: 120}
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || !proto.Equal(nw.GetStretch(), want) || len(m.GetUpdate().GetSet()) != 1 || len(m.GetUpdate().GetRemove()) != 0 {
		t.Errorf("the update of gw-1 is %v, want the Network dc-l2 alone, with the Stretch %v", m, want)
	}
	h.waitNode("gw-1", 2, true)
	stretchQuiet(t, lan)
	h.waitNode("lan-1", 1, true)
	wantList := `[{"name":"dc-stretch","gateway":"gw-1","network":"dc-l2","vni":5010,"routeTargets":["65000:5010"],"bumRateLimit":10000000,"macImportLimit":10000,"staleTimer":120,"delivered":true}]`
	if got := h.stretchList(); got != wantList {
		t.Errorf("the API lists\n%s\nwant\n%s", got, wantList)
	}
	rs, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rs {
		found = found || (r.Kind == intent.KindStretch && r.Name == "dc-stretch")
	}
	if !found {
		t.Errorf("the intent that the API lists has no Stretch dc-stretch: %+v", rs)
	}

	// Changed: another VNI, irb on, an ESI and two limits
	res, err = h.api.Apply(ctx, stretchDoc("", stretchOf("dc-stretch", "gw-1", "dc-l2", 5011, `, "irb": true, "macImportLimit": 2000, "staleTimer": 60, "esi": "00:11:22:33:44:55:66:77:88:99"`)))
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the change of the Stretch changed %+v, want %+v", res.Nodes, want)
	}
	m = gw.update(t)
	want = &controlpb.Stretch{Vni: 5011, RouteTargets: []string{"65000:5011"}, Esi: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		BumRateLimit: intent.DefaultBUMRateLimit, MacImportLimit: 2000, StaleTimer: 60, Irb: true}
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || !proto.Equal(nw.GetStretch(), want) {
		t.Errorf("the update of gw-1 is %v, want the Network dc-l2 with the Stretch %v", m, want)
	}
	h.waitNode("gw-1", 3, true)
	wantList = `[{"name":"dc-stretch","gateway":"gw-1","network":"dc-l2","vni":5011,"routeTargets":["65000:5011"],"esi":"00:11:22:33:44:55:66:77:88:99",` +
		`"bumRateLimit":10000000,"macImportLimit":2000,"staleTimer":60,"irb":true,"delivered":true}]`
	if got := h.stretchList(); got != wantList {
		t.Errorf("after the change the API lists\n%s\nwant\n%s", got, wantList)
	}

	// Deleted: the Network stays, the Stretch is gone from it
	res, err = h.api.Delete(ctx, intent.KindStretch, "dc-stretch")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 4}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the delete of the Stretch changed %+v, want %+v", res.Nodes, want)
	}
	m = gw.update(t)
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || nw.GetStretch() != nil || len(m.GetUpdate().GetRemove()) != 0 {
		t.Errorf("the update of gw-1 after the delete is %v, want the Network dc-l2 without a Stretch", m)
	}
	h.waitNode("gw-1", 4, true)
	if got := h.stretchList(); got != `[]` {
		t.Errorf("after the delete the API lists %s, want none", got)
	}
	if _, err := h.api.Delete(ctx, intent.KindStretch, "dc-stretch"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("a second delete of the Stretch gave %v, want 404", err)
	}
	stretchQuiet(t, lan)
	h.checkState(gw)
	h.checkState(lan)
}

// TestStretchRefusals is the second and the third criterion of SDN-63. The four refusals are made before the apply, so the intent and
// its revisions stay as they were, and each names the Node and the Network: a gateway that reports no evpn, with the Capability
// named, one VNI twice at a gateway, two gateways of a Network without an ESI, and a Node with the Role bridge in the Network. A
// gateway that reports evpn takes the Stretch that the first refusal kept from it.
func TestStretchRefusals(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.setLicence(stretchEnterprise())
	h.applyDoc(stretchDoc(""))
	gw := h.sim("gw-1", keyBranch1)
	gw.update(t)
	h.waitNode("gw-1", 1, true)
	before, log := h.resources(), h.revisionLog()

	refused := func(why string, doc intent.Document, status int, wants ...string) {
		t.Helper()
		_, err := h.api.Apply(ctx, doc)
		if got := httpStatus(err); got != status {
			t.Errorf("%s: the apply answered %d (%v), want %d", why, got, err, status)
		}
		for _, want := range wants {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error is %v, want one with %q", why, err, want)
			}
		}
		if after := h.resources(); after != before {
			t.Errorf("%s: a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", why, after, before)
		}
		if got := h.revisionLog(); got != log {
			t.Errorf("%s: a refused apply made a revision: %s, want %s", why, got, log)
		}
	}

	// A gateway that reports no evpn
	refused("a gateway without evpn", stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``)), http.StatusConflict,
		capability.ErrMissing.Error(), `Node "gw-1" (Server, x64): Stretch of Network "dc-l2" needs evpn, which the node does not report`)
	// One VNI that a gateway carries twice
	refused("one VNI twice at a gateway", stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``), stretchOf("s2", "gw-1", "dc-l2b", 5010, ``)), http.StatusBadRequest,
		`Node "gw-1" carries vni 5010 for Network "dc-l2" already`, `so it cannot carry it for Network "dc-l2b" too`)
	// A Network that two gateways stretch, and no ESI
	refused("two gateways and no ESI", stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``), stretchOf("s2", "gw-2", "dc-l2", 5010, ``)), http.StatusBadRequest,
		`Network "dc-l2" is stretched at the Nodes "gw-1", "gw-2" and Node "gw-1" has no esi`, `Network "dc-l2" is stretched at the Nodes "gw-1", "gw-2" and Node "gw-2" has no esi`)
	// A Node with the Role bridge in a Network that has a Stretch, which is not its gateway
	refused("a bridge in the Network", stretchDoc(`, "roles": ["bridge"]`, stretchOf("s1", "gw-1", "dc-l2", 5010, ``)), http.StatusBadRequest,
		`Network "dc-l2" has Node "lan-1", which has the role bridge and is no gateway of the Stretch (gateways: "gw-1")`)
	h.waitNode("gw-1", 1, true)

	// The gateway reports evpn in its next Hello and takes the Stretch
	gw.halt()
	gw.Capabilities = capsEVPN
	gw.start(h)
	h.waitNode("gw-1", 1, true)
	res, err := h.api.Apply(ctx, stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``)))
	if err != nil {
		t.Fatalf("the Stretch at a gateway that reports evpn: %v", err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the Stretch changed %+v, want %+v", res.Nodes, want)
	}
	if nw := stretchNetwork(gw.update(t), "dc-l2"); nw == nil || nw.GetStretch().GetVni() != 5010 {
		t.Errorf("the update of gw-1 has the Network %v, want the Stretch of VNI 5010", nw)
	}
	h.waitNode("gw-1", 2, true)
	h.checkState(gw)
	if c := h.node("gw-1").Capabilities; c == nil || !c.EVPN {
		t.Errorf("the API lists the Capabilities %+v of gw-1, want evpn", c)
	}

	// The same Stretch applies as it is, and a bridge may be the gateway itself
	if _, err := h.api.Apply(ctx, stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``))); err != nil {
		t.Errorf("applying the Stretch again: %v", err)
	}
	doc := stretchDoc("", stretchOf("s1", "gw-1", "dc-l2", 5010, ``))
	doc.Resources[3] = stretchNode("gw-1", keyBranch1, `, "roles": ["bridge"]`)
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Errorf("a bridge that is the gateway of the Stretch: %v", err)
	}
}

// TestStretchGatewayHello is the third criterion of SDN-63 at the Hello of a node. The Controller checks a node against the
// Capabilities that it reported, so a gateway that has reported none takes the Stretch into its desired state unchecked and is
// checked at its first Hello (ADR-0033): without evpn the Hello is refused, with the reason capability and the node, the Network and
// the Capability named, and a gateway that reports evpn is served the Stretch.
func TestStretchGatewayHello(t *testing.T) {
	h := newHarness(t)
	h.setLicence(stretchEnterprise())
	h.applyDoc(stretchDoc("", stretchOf("dc-stretch", "gw-1", "dc-l2", 5010, ``)))

	// A gateway whose host is a Windows Server and whose release does not report evpn
	gw := h.newSim("gw-1", keyBranch1)
	gw.start(h)
	refuse := gw.refusal(t).GetRefuse()
	want := `Node "gw-1" (Server, x64): Stretch of Network "dc-l2" needs evpn, which the node does not report`
	if refuse.GetReason() != controlpb.RefuseReason_REFUSE_REASON_CAPABILITY || !strings.Contains(refuse.GetMessage(), want) {
		t.Errorf("the Hello of gw-1 without evpn was refused with %v, want the reason capability and a message with %q", refuse, want)
	}
	if n := h.node("gw-1"); n.Connected {
		t.Errorf("gw-1, which was refused for the lack of evpn, is connected: %+v", n)
	}

	// The same gateway reports evpn in its next Hello and takes the Stretch
	gw.Capabilities = capsEVPN
	gw.start(h)
	if nw := stretchNetwork(gw.update(t), "dc-l2"); nw == nil || nw.GetStretch().GetVni() != 5010 {
		t.Errorf("the update of gw-1 has the Network %v, want the Stretch of VNI 5010", nw)
	}
	h.waitNode("gw-1", 1, true)
	h.checkState(gw)
}

// TestStretchPastTheLicence is the fourth criterion of SDN-63: a Stretch is part of EVPN and BGP, so the Personal tier refuses it,
// and when an Enterprise licence runs out, with no fallback licence for the version, the Stretch is no longer part of the desired
// state of its gateway: it gets a Generation whose Network object has none, the intent keeps the Stretch, and a licence that has EVPN
// and BGP again gives it back.
func TestStretchPastTheLicence(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.applyDoc(stretchDoc(""))
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsEVPN
	gw.start(h)
	gw.update(t)
	h.waitNode("gw-1", 1, true)

	// Without a licence key, and with a Business one, the licence in force has no EVPN and BGP
	doc := stretchDoc("", stretchOf("dc-stretch", "gw-1", "dc-l2", 5010, ``))
	want := `Stretch "dc-stretch": EVPN and BGP is an Enterprise feature, and the licence in force is Personal`
	if _, err := h.api.Apply(ctx, doc); httpStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), want) {
		t.Errorf("a Stretch without a licence key gave %v, want a 403 that says %q", err, want)
	}
	h.setLicence(licence.Licence{ID: "biz-1", Licensee: "Test", Tier: licence.Business, Nodes: 5, Expires: time.Now().Add(year)})
	want = `Stretch "dc-stretch": EVPN and BGP is an Enterprise feature, and the licence in force is Business`
	if _, err := h.api.Apply(ctx, doc); httpStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), want) {
		t.Errorf("a Stretch with a Business licence gave %v, want a 403 that says %q", err, want)
	}

	// With an Enterprise licence it is part of the state of its gateway
	sub := stretchEnterprise()
	h.setLicence(sub)
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	if nw := stretchNetwork(gw.update(t), "dc-l2"); nw == nil || nw.GetStretch().GetVni() != 5010 {
		t.Errorf("the update of gw-1 has the Network %v, want the Stretch of VNI 5010", nw)
	}
	h.waitNode("gw-1", 2, true)
	if got := h.stretchList(); !strings.Contains(got, `"delivered":true`) || strings.Contains(got, `"held"`) {
		t.Errorf("with the Enterprise licence the API lists %s, want the Stretch delivered", got)
	}

	// The subscription runs out while the controller runs, and has no fallback licence: the Personal tier is in force
	sub.Expires = time.Now().Add(3 * time.Second)
	if st := h.setLicence(sub); st.State != licence.StateActive {
		t.Fatalf("the subscription is %s, want it active until it expires", st.State)
	}
	h.waitLicence(licence.StateExpired)
	m := gw.update(t)
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || nw.GetStretch() != nil || len(m.GetUpdate().GetRemove()) != 0 {
		t.Errorf("the update of gw-1 past the licence is %v, want the Network dc-l2 without a Stretch", m)
	}
	h.waitNode("gw-1", 3, true)
	if _, state := gw.State(); state[desired.Key{Kind: controlpb.Kind_KIND_NETWORK, Name: "dc-l2"}].GetNetwork().GetStretch() != nil {
		t.Errorf("the state of gw-1 past the licence still has the Stretch")
	}
	wantList := `[{"name":"dc-stretch","gateway":"gw-1","network":"dc-l2","vni":5010,"routeTargets":["65000:5010"],"bumRateLimit":10000000,"macImportLimit":10000,"staleTimer":120,` +
		`"delivered":false,"held":"EVPN and BGP is an Enterprise feature, and the licence in force is Personal"}]`
	if got := h.stretchList(); got != wantList {
		t.Errorf("past the licence the API lists\n%s\nwant\n%s", got, wantList)
	}
	// The intent keeps the Stretch, and the overlay Network is unchanged
	if rs := h.resources(); !strings.Contains(rs, `"kind": "Stretch"`) {
		t.Errorf("the intent past the licence has no Stretch:\n%s", rs)
	}
	if _, err := h.api.Apply(ctx, doc); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a Stretch past the licence gave %v, want a 403", err)
	}

	// A licence that has EVPN and BGP again gives the Stretch back
	h.setLicence(stretchEnterprise())
	m = gw.update(t)
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || nw.GetStretch().GetVni() != 5010 {
		t.Errorf("the update of gw-1 under the new licence is %v, want the Network dc-l2 with the Stretch of VNI 5010", m)
	}
	h.waitNode("gw-1", 4, true)
	h.checkState(gw)
}

// TestStretchKeepsTheFallbackLicence is the other side of the fourth criterion of SDN-63, what the grace period keeps. An Enterprise
// subscription that ran out keeps EVPN and BGP for the versions that its perpetual fallback licence covers, so the Stretch is made
// and stays part of the desired state of its gateway. Past that, when the fallback licence is for an older version than the one
// the Controller runs, the Personal tier is in force and the gateway gets the Network without the Stretch, as it does when the
// subscription runs out with no fallback licence.
func TestStretchKeepsTheFallbackLicence(t *testing.T) {
	ctx := context.Background()
	h := newHarnessAt(t, "0.2.3")
	sub := licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(-24 * time.Hour), FallbackVersion: "0.2"}
	if st := h.setLicence(sub); st.State != licence.StateFallback || st.Tier != licence.Enterprise {
		t.Fatalf("the licence in force is %+v, want the fallback licence of the Enterprise subscription", st)
	}
	h.applyDoc(stretchDoc(""))
	gw := h.newSim("gw-1", keyBranch1)
	gw.Capabilities = capsEVPN
	gw.start(h)
	gw.update(t)
	h.waitNode("gw-1", 1, true)

	// Under the fallback licence the Stretch is made, and it is part of the state of its gateway
	if _, err := h.api.Apply(ctx, stretchDoc("", stretchOf("dc-stretch", "gw-1", "dc-l2", 5010, ``))); err != nil {
		t.Fatalf("a Stretch under the fallback licence: %v", err)
	}
	if nw := stretchNetwork(gw.update(t), "dc-l2"); nw == nil || nw.GetStretch().GetVni() != 5010 {
		t.Errorf("the update of gw-1 under the fallback licence has the Network %v, want the Stretch of VNI 5010", nw)
	}
	h.waitNode("gw-1", 2, true)
	if got := h.stretchList(); !strings.Contains(got, `"delivered":true`) || strings.Contains(got, `"held"`) {
		t.Errorf("under the fallback licence the API lists %s, want the Stretch delivered", got)
	}
	h.checkState(gw)

	// A fallback licence for an older version does not cover this Controller: the licence is past its grace period
	sub.FallbackVersion = "0.1"
	if st := h.setLicence(sub); st.State != licence.StateExpired || st.Tier != licence.Personal {
		t.Fatalf("with a fallback licence for 0.1 the licence in force is %+v, want the Personal tier", st)
	}
	m := gw.update(t)
	if nw := stretchNetwork(m, "dc-l2"); nw == nil || nw.GetStretch() != nil || len(m.GetUpdate().GetRemove()) != 0 {
		t.Errorf("the update of gw-1 past the fallback licence is %v, want the Network dc-l2 without a Stretch", m)
	}
	h.waitNode("gw-1", 3, true)
	if got := h.stretchList(); !strings.Contains(got, `"delivered":false`) || !strings.Contains(got, `"held":"EVPN and BGP is an Enterprise feature, and the licence in force is Personal"`) {
		t.Errorf("past the fallback licence the API lists %s, want the Stretch held by the licence", got)
	}
}
