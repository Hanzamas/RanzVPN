// The decoy of a Listener in the controller conformance seam (AUD1-DT-4 #452): the decoy of the Listener resource of a
// Node is in the Listener of its NodeConfig, which the node simulator receives, and a Listener that names none sends
// none. A decoy that is not a loopback address is refused when the intent is applied, and the intent stays as it was.
package controller_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// TestListenerDecoyReachesTheNode is the fourth criterion of #452: the NodeConfig that the node simulator receives
// holds the decoy of its Listener in the field of the schema, and the one of a Node whose Listener names none holds
// none. A change of the decoy is a new Generation of its Node alone.
func TestListenerDecoyReachesTheNode(t *testing.T) {
	h := newHarness(t)
	h.apply("listener-decoy.json")
	gw := h.sim("gw-1", keyBranch1)
	hub := h.sim("hub", keyBranch2)

	n := nodeObject(gw.update(t))
	if n == nil || n.GetListener() == nil || n.GetListenerDecoy() != "127.0.0.1:8080" || n.GetListener().GetName() != "edge-gw-1" {
		t.Errorf("the NodeConfig of gw-1 has the Listener %v and the decoy %q, want edge-gw-1 with the decoy 127.0.0.1:8080", n.GetListener(), n.GetListenerDecoy())
	}
	n = nodeObject(hub.update(t))
	if n == nil || n.GetListener() == nil || n.GetListenerDecoy() != "" {
		t.Errorf("the NodeConfig of hub has the Listener %v and the decoy %q, want one without a decoy", n.GetListener(), n.GetListenerDecoy())
	}
	h.waitNode("gw-1", 1, true)
	h.waitNode("hub", 1, true)

	// The decoy of gw-1 changes: its Generation moves, the one of hub does not
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindListener, Name: "edge-gw-1", Spec: json.RawMessage(`{"node": "gw-1", "decoy": "[::1]:9090", "certificate": {"file": "C:\\ProgramData\\Ranz\\gw-1.pfx"}}`)},
	}}
	res, err := h.api.Apply(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 1 || res.Nodes[0].Name != "gw-1" || res.Nodes[0].Generation != 2 {
		t.Errorf("the change of the decoy changed %+v, want gw-1 at generation 2 alone", res.Nodes)
	}
	n = nodeObject(gw.update(t))
	if n == nil || n.GetListenerDecoy() != "[::1]:9090" {
		t.Errorf("the NodeConfig of gw-1 has the decoy %q, want [::1]:9090", n.GetListenerDecoy())
	}
	h.waitNode("gw-1", 2, true)
	h.waitNode("hub", 1, true)
	h.checkState(gw)
	h.checkState(hub)
}

// TestListenerDecoyMustBeLoopback is the third criterion of #452 at the controller: a decoy that is not a loopback
// address is refused with a message that names the Listener, and the intent stays as it was.
func TestListenerDecoyMustBeLoopback(t *testing.T) {
	h := newHarness(t)
	h.apply("listener-decoy.json")
	before := h.resources()

	for decoy, want := range map[string]string{
		"192.0.2.10:8080":  `Listener "edge-gw-1": decoy: "192.0.2.10:8080" is not a loopback address`,
		"decoy.test:8080":  `Listener "edge-gw-1": decoy: "decoy.test:8080" is not an IP address and a port`,
		"[2001:db8::1]:80": `Listener "edge-gw-1": decoy: "[2001:db8::1]:80" is not a loopback address`,
	} {
		doc := intent.Document{Resources: []intent.Resource{
			{Kind: intent.KindListener, Name: "edge-gw-1", Spec: json.RawMessage(`{"node": "gw-1", "decoy": "` + decoy + `", "certificate": {"file": "C:\\ProgramData\\Ranz\\gw-1.pfx"}}`)},
		}}
		_, err := h.api.Apply(context.Background(), doc)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("an apply with the decoy %s: the error is %v, want one with %q", decoy, err, want)
		}
		if after := h.resources(); after != before {
			t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
		}
	}
}
