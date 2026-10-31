// The mimic servers and their clients in the controller conformance seam (SDN-94 #423, ADR-0023): a Listener with a mimic
// section gives its Node the settings of a mimic server with a short id that the Controller made, and no key; once the Node
// reports the public key of its server, each Node that has the server as a peer with a mimic endpoint gets a link to it. The
// node simulator reports the key as a Node does, in a Pins message after its Hello; the golden files hold the deltas.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// counting is a source of random bytes that counts up from 1: the first short id that the controller makes is the bytes 1 to
// 8 and the second the bytes 9 to 16, so a short id that was made again is not one that was kept.
type counting byte

func (c *counting) Read(p []byte) (int, error) {
	for i := range p {
		*c++
		p[i] = byte(*c)
	}
	return len(p), nil
}

// The public keys that the Node hub reports, which are 32 bytes each, and the short ids that the controller makes for its server.
var (
	mimicKey1 = []byte("0123456789abcdef0123456789abcdef")
	mimicKey2 = []byte("fedcba9876543210fedcba9876543210")
	shortID1  = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	shortID2  = []byte{9, 10, 11, 12, 13, 14, 15, 16}
)

// newMimicHarness returns a harness whose controller draws the short ids of the mimic servers from counting, and the clock that it
// runs on, which starts now and which a test moves. The controller applies one change of the keys of a Node in
// controller.PinsInterval (AUD1-DT-20), by that clock, so a test whose Node changes its keys a second time moves the clock by the
// interval first. The controller looks at the reports that wait every 10 ms.
func newMimicHarness(t *testing.T) (*harness, *keyClock) {
	clk := &keyClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	h := &harness{t: t, rq: rqlitetest.Fresh(t), random: new(counting), tune: func(c *controller.Config) {
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

// mimicInput is what the controller keeps for the mimic server hub: its short id and the public key that its Node reported.
func mimicInput(id, key []byte) desired.Mimic {
	return desired.Mimic{ShortIDs: map[string][]byte{"hub": id}, Keys: map[string][]byte{"hub": key}}
}

// mimicPart returns the mimic part of the NodeConfig that the simulated node s holds now, nil for none.
func mimicPart(s *sim) *controlpb.Mimic {
	_, st := s.State()
	return st[desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: s.name}].GetNode().GetMimic()
}

// removed returns the keys of the objects that the update in m removes.
func removed(m *controlpb.ControlMessage) []desired.Key {
	var out []desired.Key
	for _, k := range m.GetUpdate().GetRemove() {
		out = append(out, desired.Key{Kind: k.GetKind(), Name: k.GetName()})
	}
	return out
}

// settle waits until each Node of gens has acknowledged its generation of gens and is connected: so a Node whose generation
// did not move did not get one.
func (h *harness) settle(gens map[string]uint64) {
	h.t.Helper()
	for name, gen := range gens {
		h.waitNode(name, gen, true)
	}
}

// checkMimicState checks that the state that the simulated node s built from its updates is the full state that the controller's
// intent compiles to for it, with the mimic part that m gives (desired.WithMimic).
func (h *harness) checkMimicState(s *sim, m desired.Mimic) {
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
	in = in.Capped(lic.Nodes)
	states, err := desired.Compile(in)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := desired.WithMimic(in, states, m); err != nil {
		h.t.Fatal(err)
	}
	gen, got := s.State()
	if want := states[s.name]; !desired.Equal(got, want) {
		h.t.Errorf("%s: the state at generation %d differs from the compiled intent with its mimic part:\n--- node\n%s\n--- intent\n%s",
			s.name, gen, show(desired.Full(got, gen)), show(desired.Full(want, gen)))
	}
}

// mimicNet is the network of mimic.json with its four Nodes connected: hub, the mimic server, gw-1 and gw-2, which share VRF corp
// with it, and lab-1, which shares none. clk is the clock of its controller (newMimicHarness).
type mimicNet struct {
	h                  *harness
	clk                *keyClock
	gw1, gw2, hub, lab *sim
}

// startMimicNet applies mimic.json, connects the four Nodes, has hub report mimicKey1, and takes the updates that they applied.
// Then gw-1 and gw-2 are at generation 2, which gave each its link, and hub and lab-1 at generation 1. The report of hub started
// its interval (controller.PinsInterval) at the time of the clock that the net holds.
func startMimicNet(t *testing.T) *mimicNet {
	t.Helper()
	h, clk := newMimicHarness(t)
	h.apply("mimic.json")
	n := &mimicNet{h: h, clk: clk, gw1: h.sim("gw-1", keyBranch1), gw2: h.sim("gw-2", keyRelay1), hub: h.sim("hub", keyBranch2), lab: h.sim("lab-1", keyLab1)}
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		s.update(t)
	}
	if err := n.hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey1}); err != nil {
		t.Fatal(err)
	}
	n.gw1.update(t)
	n.gw2.update(t)
	h.settle(map[string]uint64{"gw-1": 2, "gw-2": 2, "hub": 1, "lab-1": 1})
	return n
}

// TestMimicServerAndClientsGetTheirState is the third criterion of SDN-94: the Node hub, whose Listener has a mimic section, gets
// a state with the server settings and the short id and no key; before it reports its public key no client has a link; once it
// does, each Node that shares a VRF with it and has its mimic endpoint gets one link, with the address, the name, the public key
// and the short id, and no other Node gets a Generation. A mimic part of a state holds no private key: no message has a field for one.
func TestMimicServerAndClientsGetTheirState(t *testing.T) {
	ctx := context.Background()
	h, clk := newMimicHarness(t)
	res := h.apply("mimic.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 1}, {Name: "gw-2", Generation: 1}, {Name: "hub", Generation: 1}, {Name: "lab-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic.json changed %+v, want %+v", res.Nodes, want)
	}
	gw1 := h.sim("gw-1", keyBranch1)
	gw2 := h.sim("gw-2", keyRelay1)
	hub := h.sim("hub", keyBranch2)
	lab := h.sim("lab-1", keyLab1)

	// The server has its settings, with the short id that the controller made, and the defaults of what the section left out
	m := hub.update(t)
	wantServer := &controlpb.MimicServer{Listen: ":8443", ServerNames: []string{"www.example.com", "cdn.example.com"}, MaxTimeDiffMs: intent.DefaultMimicMaxTimeDiffMs,
		Decoy: &controlpb.MimicDecoy{Mode: controlpb.MimicDecoyMode_MIMIC_DECOY_MODE_OWN,
			Acme: &controlpb.MimicAcme{Directory: intent.DefaultACMEDirectory, Email: "ops@example.com", CacheDir: `C:\ProgramData\Ranz\mimic-acme`}},
		ShortId: shortID1}
	if got := nodeObject(m).GetMimic().GetServer(); !proto.Equal(got, wantServer) {
		t.Errorf("the server of hub is %v, want %v", got, wantServer)
	}
	if links := nodeObject(m).GetMimic().GetLinks(); len(links) != 0 {
		t.Errorf("hub has the links %v, but it has no mimic server as a peer", links)
	}

	// Before the report no client has a link, though each has the Peer hub with its endpoints
	for _, c := range []*sim{gw1, gw2} {
		m := c.update(t)
		if n := nodeObject(m); n == nil || n.GetMimic() != nil {
			t.Errorf("the NodeConfig of %s is %v, want no mimic part before hub reported its key", c.name, n)
		}
		if p := peerObject(m, "hub"); p == nil || len(p.GetEndpoints()) != 2 {
			t.Errorf("the Peer hub of %s is %v, want it with its two endpoints", c.name, p)
		}
	}
	if n := nodeObject(lab.update(t)); n == nil || n.GetMimic() != nil || n.GetListener() != nil {
		t.Errorf("the NodeConfig of lab-1 is %v, want it with no mimic part", n)
	}
	h.settle(map[string]uint64{"gw-1": 1, "gw-2": 1, "hub": 1, "lab-1": 1})

	// ranz explain of the Listener says that the Controller waits for the public key, and which Nodes have no link
	ex, err := h.api.ExplainListener(ctx, "edge-hub")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Node != "hub" || ex.Mimic == nil || ex.Mimic.Listen != ":8443" || ex.KeyReported || ex.PublicKey != "" || len(ex.Links) != 0 ||
		!strings.Contains(ex.Waiting, "the Controller waits for the public key of Node hub") || !slices.Equal(ex.Unlinked, []string{"gw-1", "gw-2"}) ||
		!slices.Equal(ex.MimicEndpoints, []string{"hub.example.com:8443"}) {
		t.Errorf("the explanation of edge-hub before the report is %+v, want a Controller that waits for the key of hub, and gw-1 and gw-2 without a link", ex)
	}

	// The Node hub reports its public key: each client gets its link in a delta of its NodeConfig, and no other Node a Generation
	if err := hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey1}); err != nil {
		t.Fatal(err)
	}
	golden(t, "mimic-link-gw-1", gw1.update(t))
	wantLink := &controlpb.MimicLink{Peer: "hub", Address: "hub.example.com:8443", ServerName: "www.example.com", PublicKey: mimicKey1, ShortId: shortID1}
	if links := nodeObject(gw2.update(t)).GetMimic().GetLinks(); len(links) != 1 || !proto.Equal(links[0], wantLink) {
		t.Errorf("the links of gw-2 are %v, want %v", links, wantLink)
	}
	h.settle(map[string]uint64{"gw-1": 2, "gw-2": 2, "hub": 1, "lab-1": 1})
	for _, s := range []*sim{gw1, gw2, hub, lab} {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey1))
	}

	// The explanation now holds the key, in hex, and the two links
	ex, err = h.api.ExplainListener(ctx, "edge-hub")
	wantLinks := []explain.ListenerLink{{Node: "gw-1", Address: "hub.example.com:8443", ServerName: "www.example.com"}, {Node: "gw-2", Address: "hub.example.com:8443", ServerName: "www.example.com"}}
	if err != nil || !ex.KeyReported || ex.PublicKey != hex.EncodeToString(mimicKey1) || ex.Waiting != "" || len(ex.Unlinked) != 0 || !slices.Equal(ex.Links, wantLinks) {
		t.Errorf("the explanation of edge-hub after the report is %+v (%v), want the key in hex and the links %v", ex, err, wantLinks)
	}
	var refused *api.Error
	if _, err := h.api.ExplainListener(ctx, "nowhere"); !errors.As(err, &refused) || refused.Status != 404 {
		t.Errorf("the explanation of a Listener that does not exist is %v, want 404 Not Found", err)
	}

	// A report replaces the one before: one that holds no key, as a Node that has none sends, takes the key away and with it the
	// links, and the Node stays connected; the key reported again gives them back. Each is a change of the keys of hub, which the
	// controller applies once in controller.PinsInterval, so the clock moves by that between them.
	clk.Advance(controller.PinsInterval)
	if err := hub.ReportKeys(nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*sim{gw1, gw2} {
		if n := nodeObject(c.update(t)); n == nil || n.GetMimic() != nil {
			t.Errorf("the NodeConfig of %s after hub reported no key is %v, want no mimic part", c.name, n)
		}
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 1, "lab-1": 1})
	clk.Advance(controller.PinsInterval)
	if err := hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*sim{gw1, gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !proto.Equal(links[0], wantLink) {
			t.Errorf("the links of %s after hub reported its key again are %v, want %v", c.name, links, wantLink)
		}
	}
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "hub": 1, "lab-1": 1})
	for _, s := range []*sim{gw1, gw2, hub, lab} {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey1))
	}
}

// TestMimicChangesReachTheServerAndItsClientsOnly is the fourth criterion of SDN-94: a change of the reported key changes the
// states of the clients, a change of the section the state of the server and, when it changes the first server name, the
// states of the clients, and a change of the endpoints of the server the states of the server and of its peers. lab-1, which
// shares no VRF with hub, stays at generation 1 throughout.
func TestMimicChangesReachTheServerAndItsClientsOnly(t *testing.T) {
	n := startMimicNet(t)
	h := n.h

	// A new key, an interval after the first report of hub (controller.PinsInterval): the links of gw-1 and gw-2 hold it, and hub
	// has no new Generation, since its state holds no key
	n.clk.Advance(controller.PinsInterval)
	if err := n.hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey2}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*sim{n.gw1, n.gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !bytes.Equal(links[0].GetPublicKey(), mimicKey2) {
			t.Errorf("the links of %s after the new key are %v, want one with the new key", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 1, "lab-1": 1})

	// A change of the section: hub gets the new settings with the short id it had, and its clients the new first server name
	res := h.apply("mimic-section.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 4}, {Name: "gw-2", Generation: 4}, {Name: "hub", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic-section.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "mimic-section-hub", n.hub.update(t))
	for _, c := range []*sim{n.gw1, n.gw2} {
		links := nodeObject(c.update(t)).GetMimic().GetLinks()
		if len(links) != 1 || links[0].GetServerName() != "cdn.example.com" || !bytes.Equal(links[0].GetPublicKey(), mimicKey2) || !bytes.Equal(links[0].GetShortId(), shortID1) {
			t.Errorf("the links of %s after the new section are %v, want one named cdn.example.com with the key and the short id that it had", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "hub": 2, "lab-1": 1})

	// A change of the endpoints of hub: its own NodeConfig, the Peer hub of its clients and the address of their links
	res = h.apply("mimic-endpoints.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 5}, {Name: "gw-2", Generation: 5}, {Name: "hub", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic-endpoints.json changed %+v, want %+v", res.Nodes, want)
	}
	wantEndpoints := []*controlpb.Endpoint{{Transport: controlpb.Transport_TRANSPORT_QUIC, Address: "hub.example.com:443"}, {Transport: controlpb.Transport_TRANSPORT_MIMIC, Address: "198.51.100.7:9443"}}
	if got := nodeObject(n.hub.update(t)).GetEndpoints(); !equalEndpoints(got, wantEndpoints) {
		t.Errorf("the endpoints of hub are %v, want %v", got, wantEndpoints)
	}
	for _, c := range []*sim{n.gw1, n.gw2} {
		m := c.update(t)
		if p := peerObject(m, "hub"); p == nil || !equalEndpoints(p.GetEndpoints(), wantEndpoints) {
			t.Errorf("the Peer hub of %s is %v, want the new endpoints", c.name, p)
		}
		if links := nodeObject(m).GetMimic().GetLinks(); len(links) != 1 || links[0].GetAddress() != "198.51.100.7:9443" {
			t.Errorf("the links of %s after the new endpoint are %v, want one that dials 198.51.100.7:9443", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 5, "gw-2": 5, "hub": 3, "lab-1": 1})
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey2))
	}
}

// TestMimicNodeThatLeavesHasNoLink is the fifth criterion of SDN-94: a Node that leaves the VRF has no link in its own later
// state, and no peer; the Nodes that it left have no peer for it; and a server that leaves a VRF, or stops being one, has no link in
// the states of the Nodes that no longer share a VRF with it. A server that becomes one again gets a new short id.
func TestMimicNodeThatLeavesHasNoLink(t *testing.T) {
	n := startMimicNet(t)
	h := n.h
	ctx := context.Background()

	// gw-1 leaves corp for lab, where lab-1 is: no link, and the Peers hub and gw-2 gone from its state
	res := h.apply("mimic-gw1-leaves.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 3}, {Name: "gw-2", Generation: 3}, {Name: "hub", Generation: 2}, {Name: "lab-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic-gw1-leaves.json changed %+v, want %+v", res.Nodes, want)
	}
	m := n.gw1.update(t)
	if c := nodeObject(m); c == nil || c.GetMimic() != nil {
		t.Errorf("the NodeConfig of gw-1 after it left corp is %v, want it with no mimic part", c)
	}
	for _, peer := range []string{"hub", "gw-2"} {
		if !slices.Contains(removed(m), desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: peer}) {
			t.Errorf("the update of gw-1 after it left corp removes %v, want the Peer %s among them", removed(m), peer)
		}
	}
	for _, s := range []*sim{n.gw2, n.hub} {
		if m := s.update(t); !slices.Contains(removed(m), desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: "gw-1"}) {
			t.Errorf("the update of %s after gw-1 left corp removes %v, want the Peer gw-1", s.name, removed(m))
		}
	}
	n.lab.update(t)
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 2, "lab-1": 2})
	if links := mimicPart(n.gw2).GetLinks(); len(links) != 1 || links[0].GetPeer() != "hub" {
		t.Errorf("the links of gw-2, which stayed in corp, are %v, want the one to hub", links)
	}
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey1))
	}

	// hub leaves corp for lab: gw-2, alone in corp, has no link and no Peer hub, and gw-1 and lab-1, which now share lab with it, have one
	res = h.apply("mimic-hub-leaves.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 4}, {Name: "gw-2", Generation: 4}, {Name: "hub", Generation: 3}, {Name: "lab-1", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic-hub-leaves.json changed %+v, want %+v", res.Nodes, want)
	}
	m = n.gw2.update(t)
	if c := nodeObject(m); c == nil || c.GetMimic() != nil || !slices.Contains(removed(m), desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: "hub"}) {
		t.Errorf("gw-2 after hub left corp has the NodeConfig %v and removes %v, want no mimic part and the Peer hub removed", c, removed(m))
	}
	for _, c := range []*sim{n.gw1, n.lab} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || links[0].GetPeer() != "hub" {
			t.Errorf("the links of %s, which share lab with hub, are %v, want the one to hub", c.name, links)
		}
	}
	n.hub.update(t)
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "hub": 3, "lab-1": 3})
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey1))
	}

	// The Listener goes: hub is no mimic server, and gw-1 and lab-1 have no link to it
	res, err := h.api.Delete(ctx, intent.KindListener, "edge-hub")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 5}, {Name: "hub", Generation: 4}, {Name: "lab-1", Generation: 4}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the delete of the Listener changed %+v, want %+v", res.Nodes, want)
	}
	for _, s := range []*sim{n.gw1, n.hub, n.lab} {
		if c := nodeObject(s.update(t)); c == nil || c.GetMimic() != nil {
			t.Errorf("the NodeConfig of %s after the Listener was deleted is %v, want no mimic part", s.name, c)
		}
	}
	h.settle(map[string]uint64{"gw-1": 5, "gw-2": 4, "hub": 4, "lab-1": 4})

	// The server that is one again gets a new short id, which its clients get in their links
	h.apply("mimic-section.json")
	if id := nodeObject(n.hub.update(t)).GetMimic().GetServer().GetShortId(); !bytes.Equal(id, shortID2) {
		t.Errorf("the short id of hub, a server again, is %v, want %v: a short id is kept for as long as the Node is a server", id, shortID2)
	}
	for _, c := range []*sim{n.gw1, n.lab} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !bytes.Equal(links[0].GetShortId(), shortID2) {
			t.Errorf("the links of %s after hub became a server again are %v, want one with the new short id", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 6, "gw-2": 4, "hub": 5, "lab-1": 5})
}

// waitMimicKey waits until the store holds the key want as the mimic key that the Node with the static key key reported, none when
// want is nil, and fails the test when it does not within waitTimeout.
func (h *harness) waitMimicKey(key string, want []byte) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		pins, err := h.st.LoadPins(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		if got := pins[key].GetMimicKey(); bytes.Equal(got, want) {
			return
		} else if time.Now().After(deadline) {
			h.t.Fatalf("the store holds the mimic key %x within %v, want %x", got, waitTimeout, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMimicDeletedNodeLeavesNoLinkAndNoKey is the fifth criterion of SDN-94 for a Node that leaves the Network by its Node resource:
// the Node of the server is deleted after its Listener, which a guard keeps from going before, and then the Peer hub and every link to
// it are gone from the states of the others. The controller forgets the public key that the Node reported, so a Node that is made
// again with the same static key starts with none: its clients get the Peer and no link until it reports a key, and its server has a
// new short id.
func TestMimicDeletedNodeLeavesNoLinkAndNoKey(t *testing.T) {
	n := startMimicNet(t)
	h := n.h
	ctx := context.Background()
	hubKey := string(keyBranch2.Public())
	h.waitMimicKey(hubKey, mimicKey1)

	// The Node that a Listener names is not deleted
	if _, err := h.api.Delete(ctx, intent.KindNode, "hub"); err == nil || !strings.Contains(err.Error(), `Node "hub" is used by Listener "edge-hub"`) {
		t.Errorf("the delete of hub while its Listener stands is %v, want a refusal that names the Listener", err)
	}

	// The Listener goes: hub is no server, and its clients have no link
	res, err := h.api.Delete(ctx, intent.KindListener, "edge-hub")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 3}, {Name: "gw-2", Generation: 3}, {Name: "hub", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the delete of the Listener changed %+v, want %+v", res.Nodes, want)
	}
	for _, s := range []*sim{n.gw1, n.gw2, n.hub} {
		if c := nodeObject(s.update(t)); c == nil || c.GetMimic() != nil {
			t.Errorf("the NodeConfig of %s after the Listener was deleted is %v, want no mimic part", s.name, c)
		}
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 2, "lab-1": 1})

	// The Node resource goes: hub is refused as a Node that no resource names, its peers lose the Peer, and the key that it reported is
	// gone from the store
	res, err = h.api.Delete(ctx, intent.KindNode, "hub")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 4}, {Name: "gw-2", Generation: 4}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the delete of hub changed %+v, want %+v", res.Nodes, want)
	}
	if r := n.hub.refusal(t).GetRefuse(); r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE {
		t.Errorf("hub was refused with %v after its Node resource was deleted, want UNKNOWN_NODE", r)
	}
	for _, c := range []*sim{n.gw1, n.gw2} {
		m := c.update(t)
		if !slices.Contains(removed(m), desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: "hub"}) || nodeObject(m).GetMimic() != nil {
			t.Errorf("the update of %s after hub was deleted removes %v and has the mimic part %v, want the Peer hub removed and no link", c.name, removed(m), nodeObject(m).GetMimic())
		}
	}
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "lab-1": 1})
	if pins, err := h.st.LoadPins(ctx); err != nil || pins[hubKey] != nil {
		t.Errorf("the store holds %v (%v) for hub after its Node resource was deleted, want nothing", pins[hubKey], err)
	}

	// The Node is made again with the same static key and the same Listener: it starts with no key, so its clients get the Peer and no
	// link, and its server has a short id of its own
	res = h.apply("mimic.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 5}, {Name: "gw-2", Generation: 5}, {Name: "hub", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic.json applied again changed %+v, want %+v", res.Nodes, want)
	}
	hub := h.sim("hub", keyBranch2)
	if id := nodeObject(hub.update(t)).GetMimic().GetServer().GetShortId(); !bytes.Equal(id, shortID2) {
		t.Errorf("the short id of hub, made again, is %v, want %v: the one of the Node that was deleted is not kept", id, shortID2)
	}
	for _, c := range []*sim{n.gw1, n.gw2} {
		m := c.update(t)
		if p := peerObject(m, "hub"); p == nil || nodeObject(m).GetMimic() != nil {
			t.Errorf("the update of %s after hub was made again has the Peer hub %v and the mimic part %v, want the Peer and no link", c.name, p, nodeObject(m).GetMimic())
		}
	}
	h.settle(map[string]uint64{"gw-1": 5, "gw-2": 5, "hub": 1, "lab-1": 1})
	ex, err := h.api.ExplainListener(ctx, "edge-hub")
	if err != nil || ex.KeyReported || len(ex.Links) != 0 || !strings.Contains(ex.Waiting, "the Controller waits for the public key of Node hub") || !slices.Equal(ex.Unlinked, []string{"gw-1", "gw-2"}) {
		t.Errorf("the explanation of edge-hub after hub was made again is %+v (%v), want a Controller that waits for its key, with no link", ex, err)
	}

	// It reports a key of its own: each client gets its link with that key and the short id of the new server
	if err := hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey2}); err != nil {
		t.Fatal(err)
	}
	wantLink := &controlpb.MimicLink{Peer: "hub", Address: "hub.example.com:8443", ServerName: "www.example.com", PublicKey: mimicKey2, ShortId: shortID2}
	for _, c := range []*sim{n.gw1, n.gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !proto.Equal(links[0], wantLink) {
			t.Errorf("the links of %s after hub reported its new key are %v, want %v", c.name, links, wantLink)
		}
	}
	h.settle(map[string]uint64{"gw-1": 6, "gw-2": 6, "hub": 1, "lab-1": 1})
	for _, s := range []*sim{n.gw1, n.gw2, hub, n.lab} {
		h.checkMimicState(s, mimicInput(shortID2, mimicKey2))
	}
}

// TestMimicKeyOfANodeThatIsNoServer: a Node that is no mimic server when it reports its key, as one does that has not yet applied
// the end of its role, has the report kept and no Generation made for it, since no state holds the key of a Node that is no server;
// and the clients get their link at once when the Node is a server again, with the key that it reported, and no second report.
func TestMimicKeyOfANodeThatIsNoServer(t *testing.T) {
	n := startMimicNet(t)
	h := n.h
	ctx := context.Background()
	hubKey := string(keyBranch2.Public())

	if _, err := h.api.Delete(ctx, intent.KindListener, "edge-hub"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*sim{n.gw1, n.gw2, n.hub} {
		s.update(t)
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 2, "lab-1": 1})

	// The report is kept, and nobody gets a Generation for it. It comes an interval after the first report of hub
	// (controller.PinsInterval), so the controller applies it at once.
	n.clk.Advance(controller.PinsInterval)
	if err := n.hub.ReportKeys(&controlpb.Pins{MimicKey: mimicKey2}); err != nil {
		t.Fatal(err)
	}
	h.waitMimicKey(hubKey, mimicKey2)
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 2, "lab-1": 1})
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		select {
		case u := <-s.Updates:
			t.Errorf("%s got the update %v for the key of a Node that is no mimic server", s.name, u)
		default:
		}
	}

	// The Node is a server again, with a short id of its own: its clients have the link in the same Generation, with the key that it
	// reported
	res := h.apply("mimic.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 4}, {Name: "gw-2", Generation: 4}, {Name: "hub", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic.json applied again changed %+v, want %+v", res.Nodes, want)
	}
	if id := nodeObject(n.hub.update(t)).GetMimic().GetServer().GetShortId(); !bytes.Equal(id, shortID2) {
		t.Errorf("the short id of hub, a server again, is %v, want %v", id, shortID2)
	}
	wantLink := &controlpb.MimicLink{Peer: "hub", Address: "hub.example.com:8443", ServerName: "www.example.com", PublicKey: mimicKey2, ShortId: shortID2}
	for _, c := range []*sim{n.gw1, n.gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !proto.Equal(links[0], wantLink) {
			t.Errorf("the links of %s after hub became a server again are %v, want %v", c.name, links, wantLink)
		}
	}
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "hub": 3, "lab-1": 1})
	for _, s := range []*sim{n.gw1, n.gw2, n.hub, n.lab} {
		h.checkMimicState(s, mimicInput(shortID2, mimicKey2))
	}
}

// TestMimicShortIDAndKeySurviveARestart is the sixth criterion of SDN-94: the short id of a server is the same after the controller
// restarts and loads its state again, and so is the key of its links, which the controller loads from its store: the Nodes get no
// Generation for the restart or for the key that hub reports again after its Hello, and the next change of the section gives hub
// the short id that it had, and its clients the key.
func TestMimicShortIDAndKeySurviveARestart(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	n := startMimicNet(t)
	h := n.h
	all := []*sim{n.gw1, n.gw2, n.hub, n.lab}
	if id := mimicPart(n.hub).GetServer().GetShortId(); !bytes.Equal(id, shortID1) {
		t.Fatalf("the short id of hub is %v, want %v", id, shortID1)
	}

	h.stop()
	for _, s := range all {
		if err := s.end(t); err == nil {
			t.Errorf("the stream of %s ended without an error when the controller stopped", s.name)
		}
	}
	h.rq.Stop()
	rqlitetest.Restart(t, h.rq)
	h.start()
	for _, s := range all {
		s.start(h)
	}
	h.settle(map[string]uint64{"gw-1": 2, "gw-2": 2, "hub": 1, "lab-1": 1})

	res := h.apply("mimic-section.json")
	if want := []controller.NodeGeneration{{Name: "gw-1", Generation: 3}, {Name: "gw-2", Generation: 3}, {Name: "hub", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("mimic-section.json after the restart changed %+v, want %+v", res.Nodes, want)
	}
	if id := nodeObject(n.hub.update(t)).GetMimic().GetServer().GetShortId(); !bytes.Equal(id, shortID1) {
		t.Errorf("the short id of hub after the restart is %v, want the one it had, %v", id, shortID1)
	}
	for _, c := range []*sim{n.gw1, n.gw2} {
		links := nodeObject(c.update(t)).GetMimic().GetLinks()
		if len(links) != 1 || !bytes.Equal(links[0].GetPublicKey(), mimicKey1) || !bytes.Equal(links[0].GetShortId(), shortID1) {
			t.Errorf("the links of %s after the restart are %v, want one with the key and the short id that it had", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 2, "lab-1": 1})
	for _, s := range all {
		h.checkMimicState(s, mimicInput(shortID1, mimicKey1))
	}
}

// TestMimicRefusesAKeyThatIsNoKey is the seventh criterion of SDN-94 at the controller: the report of a node holds the public
// key only, 32 bytes or none; a node that reports a key of another size has its stream ended with the reason PROTOCOL.
func TestMimicRefusesAKeyThatIsNoKey(t *testing.T) {
	h, _ := newMimicHarness(t)
	h.apply("mimic.json")
	hub := h.sim("hub", keyBranch2)
	hub.update(t)
	h.waitNode("hub", 1, true)
	if err := hub.ReportKeys(&controlpb.Pins{MimicKey: make([]byte, 31)}); err != nil {
		t.Fatal(err)
	}
	golden(t, "refuse-pins", hub.refusal(t))
}

// TestMimicRefusesANodeThatWouldHaveTooManyLinks: a Node takes 8 links at most, and an apply that gives one more is refused with
// the name of the Node, whether or not any key was reported, and the intent stays as it was.
func TestMimicRefusesANodeThatWouldHaveTooManyLinks(t *testing.T) {
	h, _ := newMimicHarness(t)
	h.apply("mimic.json")
	before := h.resources()

	// gw-2 becomes a mimic server with 8 mimic endpoints, and gw-1 has them and the one of hub among its peers: 9
	var endpoints []string
	for i := range 8 {
		endpoints = append(endpoints, fmt.Sprintf(`{"transport": "mimic", "address": "gw-2-%d.example.com:8443"}`, i))
	}
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindNode, Name: "gw-2", Spec: json.RawMessage(`{"publicKey": "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc=", "vrfs": ["corp"], "endpoints": [` + strings.Join(endpoints, ", ") + `]}`)},
		{Kind: intent.KindListener, Name: "edge-gw-2", Spec: json.RawMessage(`{"node": "gw-2", "certificate": {"file": "C:\\ProgramData\\Ranz\\gw-2.pfx"},
			"mimic": {"listen": ":9443", "serverNames": ["gw-2.example.com"], "decoy": {"selfSigned": true}}}`)},
	}}
	_, err := h.api.Apply(context.Background(), doc)
	if want := `Node "gw-1" has 9 mimic endpoints among its peers that are mimic servers, and a Node takes 8 links at most`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("an apply that gives gw-1 9 links: the error is %v, want one with %q", err, want)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
}
