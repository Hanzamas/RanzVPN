// Endpoints in the controller conformance seam (SDN-93 #410): the endpoints of a Node resource reach the Peer object
// of every Node that shares a VRF with it and its own NodeConfig, and a change of them is a new Generation of
// those Nodes only; the golden files endpoints2-gw-1 and endpoints2-hub hold the deltas. A malformed endpoint is
// refused when the intent is applied, with a message that says which, and the intent stays as it was.
package controller_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// peerObject returns the Peer object named name among the objects that the update in m sets, nil for none.
func peerObject(m *controlpb.ControlMessage, name string) *controlpb.Peer {
	for _, o := range m.GetUpdate().GetSet() {
		if p := o.GetPeer(); p != nil && p.GetName() == name {
			return p
		}
	}
	return nil
}

// nodeObject returns the NodeConfig among the objects that the update in m sets, nil for none.
func nodeObject(m *controlpb.ControlMessage) *controlpb.NodeConfig {
	for _, o := range m.GetUpdate().GetSet() {
		if n := o.GetNode(); n != nil {
			return n
		}
	}
	return nil
}

// equalEndpoints reports whether got holds the endpoints of want, in the same order.
func equalEndpoints(got, want []*controlpb.Endpoint) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

// TestEndpointsReachThePeers is the second criterion of SDN-93: the endpoints of hub are in the Peer object of gw-1,
// which shares the VRF corp with it, and in its own NodeConfig, in the order of its resource; lab-1, which shares no
// VRF with hub, has no peer. A change of them is a new Generation of gw-1 and hub, as a delta of one object each, and
// of no other Node: lab-1 stays at generation 1 and gets no update.
func TestEndpointsReachThePeers(t *testing.T) {
	h := newHarness(t)
	res := h.apply("endpoints.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 1}, {Name: "hub", Generation: 1}, {Name: "lab-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("endpoints.json changed %+v, want %+v", res.Nodes, want)
	}
	gw := h.sim("gw-1", keyBranch1)
	hub := h.sim("hub", keyBranch2)
	lab := h.sim("lab-1", keyLab1)

	first := []*controlpb.Endpoint{
		{Transport: controlpb.Transport_TRANSPORT_QUIC, Address: "hub.example.com:443"},
		{Transport: controlpb.Transport_TRANSPORT_TLS, Address: "hub.example.com:443"},
	}
	m := gw.update(t)
	if p := peerObject(m, "hub"); p == nil || !equalEndpoints(p.GetEndpoints(), first) {
		t.Errorf("the Peer hub of gw-1 is %v, want the endpoints %v", p, first)
	}
	if n := nodeObject(m); n == nil || len(n.GetEndpoints()) != 0 {
		t.Errorf("the NodeConfig of gw-1, which names no endpoint, is %v", n)
	}
	m = hub.update(t)
	if n := nodeObject(m); n == nil || !equalEndpoints(n.GetEndpoints(), first) {
		t.Errorf("the NodeConfig of hub is %v, want its own endpoints %v", n, first)
	}
	if p := peerObject(m, "gw-1"); p == nil || len(p.GetEndpoints()) != 0 {
		t.Errorf("the Peer gw-1 of hub is %v, want it without endpoints", p)
	}
	m = lab.update(t)
	if p := peerObject(m, "hub"); p != nil {
		t.Errorf("lab-1, which shares no VRF with hub, has the peer %v", p)
	}
	for _, name := range []string{"gw-1", "hub", "lab-1"} {
		h.waitNode(name, 1, true)
	}

	// The endpoints of hub change: its Generation and the one of gw-1 move, and the one of lab-1 does not
	res = h.apply("endpoints2.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 2}, {Name: "hub", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("endpoints2.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "endpoints2-gw-1", gw.update(t))
	golden(t, "endpoints2-hub", hub.update(t))
	h.waitNode("gw-1", 2, true)
	h.waitNode("hub", 2, true)
	h.waitNode("lab-1", 1, true)
	for _, s := range []*sim{gw, hub, lab} {
		h.checkState(s)
	}

	// The same document again changes nothing
	if res := h.apply("endpoints2.json"); len(res.Nodes) != 0 {
		t.Errorf("endpoints2.json applied again changed %+v", res.Nodes)
	}
}

// TestEndpointsAreChecked is the first criterion of SDN-93 at the controller: a malformed endpoint is refused with
// a message that names the Node, the endpoint and what is wrong with it, and the intent stays as it was.
func TestEndpointsAreChecked(t *testing.T) {
	h := newHarness(t)
	h.apply("endpoints.json")
	before := h.resources()

	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindNode, Name: "hub", Spec: json.RawMessage(`{"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"], "endpoints": [
			{"transport": "udp", "address": "hub.example.com:443"},
			{"transport": "tls", "address": "hub.example.com"},
			{"transport": "tls", "address": "bad_name.example:443"}]}`)},
	}}
	_, err := h.api.Apply(context.Background(), doc)
	if err == nil {
		t.Fatal("an apply with three malformed endpoints was applied")
	}
	for _, want := range []string{
		`Node "hub": endpoints[0]: the transport must be quic, tls or mimic, not "udp"`,
		`Node "hub": endpoints[1]: address "hub.example.com" has no port: write host:port`,
		`Node "hub": endpoints[2]: address "bad_name.example:443": the host is not a DNS name`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name %q", err, want)
		}
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
}
