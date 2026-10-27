// Controller conformance for the health data of gateway HA (SDN-19 #195), with the harness and the
// node simulator of conformance_test.go.
package controller_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// peerDown reports whether the state of the simulated node s has the Peer peer marked down.
func peerDown(s *sim, peer string) bool {
	_, st := s.State()
	return st[desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: peer}].GetPeer().GetDown()
}

// TestGatewayDownReachesItsPeers checks the health data of gateway HA: gw-1 and gw-2 advertise one LAN
// subnet. Once gw-1 has had no control stream for NodeDownAfter, branch-1, which has both as peers, gets
// the Peer gw-1 marked down in its next Generation, and the mark goes when gw-1 opens a control stream
// again. gw-2 advertises the subnet itself, so it has no route of gw-1 to give elsewhere and gets no new
// Generation.
func TestGatewayDownReachesItsPeers(t *testing.T) {
	h := newTelemetryHarness(t, 300*time.Millisecond)
	if _, err := h.api.Apply(context.Background(), intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48", "ecmp": true}`)},
		{Kind: intent.KindNetwork, Name: "corp-lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`)},
		ipamNode("branch-1", keyBranch1, `"vrfs": ["corp"]`),
		ipamNode("gw-1", keyBranch2, `"vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}`),
		ipamNode("gw-2", keyLab1, `"vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}`),
	}}); err != nil {
		t.Fatal(err)
	}
	b1 := h.sim("branch-1", keyBranch1)
	gw1 := h.sim("gw-1", keyBranch2)
	gw2 := h.sim("gw-2", keyLab1)
	for _, s := range []*sim{b1, gw1, gw2} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	if peerDown(b1, "gw-1") || peerDown(b1, "gw-2") {
		t.Fatal("branch-1 has a gateway marked down while both have their control stream")
	}

	// gw-1 loses its control stream, and is down once it has had none for NodeDownAfter
	gw1.halt()
	b1.update(t)
	if gen, _ := b1.State(); gen != 2 || !peerDown(b1, "gw-1") || peerDown(b1, "gw-2") {
		t.Errorf("branch-1 is at generation %d with gw-1 down %v and gw-2 down %v, want generation 2 with gw-1 down alone",
			gen, peerDown(b1, "gw-1"), peerDown(b1, "gw-2"))
	}
	h.waitNode("branch-1", 2, true)
	if n := h.node("gw-2"); n.Generation != 1 {
		t.Errorf("gw-2 is at generation %d, want 1: it advertises the LAN subnet of gw-1 itself", n.Generation)
	}

	// gw-1 opens a control stream again: the mark goes, and branch-1 holds the compiled intent again
	gw1.start(h)
	b1.update(t)
	if gen, _ := b1.State(); gen != 3 || peerDown(b1, "gw-1") {
		t.Errorf("branch-1 is at generation %d with gw-1 down %v, want generation 3 with gw-1 up", gen, peerDown(b1, "gw-1"))
	}
	h.waitNode("branch-1", 3, true)
	h.waitNode("gw-1", 1, true)
	h.checkState(b1)
}
