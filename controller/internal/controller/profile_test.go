package controller_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// Session profiles (SDN-40, #233) at the controller: the test applies them through the HTTP API, as
// `ranz` does, and checks the profiles that the simulated nodes receive. The nanopb round trip of CI
// reads the frames of this test too, so the C node decodes each field of a SessionProfile as Go
// writes it.

// profilesHeld returns the session profile that the state of a simulated node gives the node itself,
// and the one of each of its peers by name: nil for one that runs under none.
func profilesHeld(s *sim) (self *controlpb.SessionProfile, peers map[string]*controlpb.SessionProfile) {
	_, state := s.State()
	peers = map[string]*controlpb.SessionProfile{}
	for _, o := range state.Objects() {
		switch {
		case o.GetNode() != nil:
			self = o.GetNode().GetProfile()
		case o.GetPeer() != nil:
			peers[o.GetPeer().GetName()] = o.GetPeer().GetProfile()
		}
	}
	return self, peers
}

// TestSessionProfilesReachTheDevices checks that the effective session profile of a User reaches each
// of its devices: in the NodeConfig of the device, whose flags the device enforces on itself, and in
// the Peer object of the device that every other Node holds, which enforces the profile on its
// session with the device. In profiles.json alice runs under laptops, which her Group staff gives,
// bob under contractors, which he names himself over the one of staff, and files, which no User owns,
// under none. A change of laptops reaches the laptop of alice and each Node that holds it as a peer
// as their next Generation; once bob names none, his laptop runs under the profile of staff.
func TestSessionProfilesReachTheDevices(t *testing.T) {
	h := newHarness(t)
	res := h.apply("profiles.json")
	if want := []controller.NodeGeneration{{Name: "alice-laptop", Generation: 1}, {Name: "bob-laptop", Generation: 1}, {Name: "files", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("profiles.json changed %+v, want %+v", res.Nodes, want)
	}
	sims := []*sim{h.sim("alice-laptop", keyBranch1), h.sim("bob-laptop", keyBranch2), h.sim("files", keyLab1)}

	// step waits until each node applied the Generation gen and checks that it runs under the profile
	// of its name in want, and that each other node holds it as a peer under the same
	step := func(gen uint64, want map[string]*controlpb.SessionProfile) {
		t.Helper()
		for _, s := range sims {
			s.update(t)
			h.waitNode(s.name, gen, true)
			h.checkState(s)
		}
		for _, s := range sims {
			self, peers := profilesHeld(s)
			if !proto.Equal(self, want[s.name]) {
				t.Errorf("generation %d: %s runs under %v, want %v", gen, s.name, self, want[s.name])
			}
			for _, o := range sims {
				if p, ok := peers[o.name]; o != s && (!ok || !proto.Equal(p, want[o.name])) {
					t.Errorf("generation %d: %s holds the peer %s under %v (a peer: %v), want %v", gen, s.name, o.name, p, ok, want[o.name])
				}
			}
		}
	}

	laptops := &controlpb.SessionProfile{Name: "laptops", User: "alice", UploadLimit: 20000000, DownloadLimit: 40000000, MaxSessions: 2, MaxIpv4: 4, MaxIpv6: 8,
		IdleTimeout: 900, NoServer: true, PrivacyFilter: true}
	contractors := &controlpb.SessionProfile{Name: "contractors", User: "bob", DownloadLimit: 10000000, MaxMacs: 1, AutoDisconnect: 28800, NoBridge: true, NoRouting: true}
	step(1, map[string]*controlpb.SessionProfile{"alice-laptop": laptops, "bob-laptop": contractors})

	// laptops changes: the laptop of alice runs under the new limits, and the two other nodes hold it
	// under them
	res = h.apply("profiles2.json")
	if want := []controller.NodeGeneration{{Name: "alice-laptop", Generation: 2}, {Name: "bob-laptop", Generation: 2}, {Name: "files", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("profiles2.json changed %+v, want %+v", res.Nodes, want)
	}
	laptops = &controlpb.SessionProfile{Name: "laptops", User: "alice", UploadLimit: 5000000, NoServer: true}
	step(2, map[string]*controlpb.SessionProfile{"alice-laptop": laptops, "bob-laptop": contractors})

	// bob names no profile of his own: his laptop runs under laptops, which his Group staff gives
	res = h.apply("profiles3.json")
	if want := []controller.NodeGeneration{{Name: "alice-laptop", Generation: 3}, {Name: "bob-laptop", Generation: 3}, {Name: "files", Generation: 3}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("profiles3.json changed %+v, want %+v", res.Nodes, want)
	}
	bob := &controlpb.SessionProfile{Name: "laptops", User: "bob", UploadLimit: 5000000, NoServer: true}
	step(3, map[string]*controlpb.SessionProfile{"alice-laptop": laptops, "bob-laptop": bob})
}
