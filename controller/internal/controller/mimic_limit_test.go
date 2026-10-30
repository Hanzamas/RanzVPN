// The limit of the reports of Pins (AUD1-DT-20 #522, CS-6 of docs/threat-model.md) in the controller conformance seam, with the
// harness of mimic_test.go and the clock that it moves: a Node that changes its keys more often than once in
// controller.PinsInterval costs the controller one write to the store, one compile and one Generation for each client in each
// interval, and nothing for the reports that it makes in between, of which the last is applied when the interval ends.
package controller_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// More public keys that hub reports, 32 bytes each (mimicKey1 and mimicKey2 are in mimic_test.go).
var (
	mimicKey3 = []byte("abcdefghijklmnopqrstuvwxyz012345")
	mimicKey4 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
)

// took waits until the controller has read every frame that the simulated node s sent before this call. s sends a Signal to peer,
// a Node that shares a VRF with it, and peer waits for the controller to forward it, which it does after the frames before it.
func took(t *testing.T, s, peer *sim) {
	t.Helper()
	if err := s.Signal(peer.name, []byte("the controller read what came before")); err != nil {
		t.Fatal(err)
	}
	peer.signal(t)
}

// reportKeys makes the simulated node s report the public key key of its mimic server, a second of the clock of the controller
// after the one before.
func reportKeys(t *testing.T, clk *keyClock, s *sim, key []byte) {
	t.Helper()
	clk.Advance(time.Second)
	if err := s.ReportKeys(&controlpb.Pins{MimicKey: key}); err != nil {
		t.Fatal(err)
	}
}

// TestMimicChangedKeysAreAppliedOncePerInterval is the first criterion of AUD1-DT-20: hub reports five changes of its keys within
// the interval of its first report, a second apart, and the controller applies none of them at once: the store keeps the key of the
// first report, and no client gets a Generation, so none cost a write to the store, a compile or a Generation. When the interval
// ends the controller applies the last report, and once: each client has its link with that key in one Generation. The interval
// that the application starts holds the next report of hub in its turn, and the interval of hub holds no report of another Node.
func TestMimicChangedKeysAreAppliedOncePerInterval(t *testing.T) {
	n := startMimicNet(t)
	h, clk := n.h, n.clk
	hubKey := string(keyBranch2.Public())
	h.waitMimicKey(hubKey, mimicKey1)

	// Five changes within the interval of the first report. The controller read them all before it forwards the Signal.
	for _, k := range [][]byte{mimicKey2, mimicKey3, mimicKey2, mimicKey3, mimicKey4} {
		reportKeys(t, clk, n.hub, k)
	}
	took(t, n.hub, n.gw1)
	h.waitMimicKey(hubKey, mimicKey1)

	// The interval of hub holds no report of another Node: gw-1, which is no mimic server, has its key stored at once
	reportKeys(t, clk, n.gw1, mimicKey2)
	h.waitMimicKey(string(keyBranch1.Public()), mimicKey2)

	// The interval ends: the controller applies the last report of hub. The first update that each client gets holds its link with
	// that key, and it is the third Generation, so no report before it made one.
	clk.Advance(controller.PinsInterval)
	for _, c := range []*sim{n.gw1, n.gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !bytes.Equal(links[0].GetPublicKey(), mimicKey4) {
			t.Errorf("the links of %s after the interval are %v, want one with the last key that hub reported", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 3, "gw-2": 3, "hub": 1, "lab-1": 1})
	h.waitMimicKey(hubKey, mimicKey4)

	// The application started an interval of its own: hub reports key 1 again at once, and the report waits for the end of that
	// interval too
	reportKeys(t, clk, n.hub, mimicKey1)
	took(t, n.hub, n.gw1)
	h.waitMimicKey(hubKey, mimicKey4)
	clk.Advance(controller.PinsInterval)
	for _, c := range []*sim{n.gw1, n.gw2} {
		if links := nodeObject(c.update(t)).GetMimic().GetLinks(); len(links) != 1 || !bytes.Equal(links[0].GetPublicKey(), mimicKey1) {
			t.Errorf("the links of %s after the second interval are %v, want one with key 1 again", c.name, links)
		}
	}
	h.settle(map[string]uint64{"gw-1": 4, "gw-2": 4, "hub": 1, "lab-1": 1})
	h.waitMimicKey(hubKey, mimicKey1)
}

// TestMimicKeysThatComeBackVoidTheReportThatWaits: hub reports another key within its interval and then the key that the controller
// holds. The Node is where it was, so the controller has nothing to apply when the interval ends: no client gets a Generation, and
// the store keeps the key.
func TestMimicKeysThatComeBackVoidTheReportThatWaits(t *testing.T) {
	n := startMimicNet(t)
	h, clk := n.h, n.clk
	hubKey := string(keyBranch2.Public())

	reportKeys(t, clk, n.hub, mimicKey2)
	reportKeys(t, clk, n.hub, mimicKey1)
	took(t, n.hub, n.gw1)
	clk.Advance(controller.PinsInterval)
	for _, c := range []*sim{n.gw1, n.gw2} {
		noUpdate(t, c)
	}
	h.settle(map[string]uint64{"gw-1": 2, "gw-2": 2, "hub": 1, "lab-1": 1})
	h.waitMimicKey(hubKey, mimicKey1)
}
