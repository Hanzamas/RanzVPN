// The first finding of the review of SDN-82-R1 (SDN-82-R2 #565) in the controller conformance seam, with the harness and the
// node simulator of conformance_test.go and devicekeys_test.go: the release before SDN-82-R1 stored the Ack of a gateway with
// the sealed key of each Device, also when the key did not open and the Device went to the gateway without it. This release
// trusts the Ack that the store holds, so it does not send such a gateway the key, and the upgrade note tells the operator to
// restart the gateway. The test pins what the note says, and a second test reads the note.
package controller_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// updatesOf returns how many Updates the simulated node s received.
func updatesOf(s *sim) int {
	n := 0
	for _, m := range received(s) {
		if m.GetUpdate() != nil {
			n++
		}
	}
	return n
}

// TestAGatewayThatTheEarlierReleaseLeftWithoutAKeyNeedsARestart is the first criterion of SDN-82-R2, for a stored Ack that
// holds a key that its gateway lacks. The earlier release ran while the PresharedKey of Device phone did not open, and the
// gateway started again meanwhile: it holds phone without its key. The store holds, as the Ack of the gateway, what that
// release put there, the state that it computed for the gateway with the sealed key of phone. After the upgrade the key opens,
// and the gateway opens its stream at the generation that it holds.
//
// The controller trusts the Ack, so it sends the gateway nothing: not when the stream opens, and not with a later generation,
// which carries the Devices that changed, as laptop, and not phone. That is what the note of SDN-82-R2 says, and the reason
// that it tells the operator to restart the gateway. The restart is the remedy that the note names: the gateway starts with
// nothing, and gets each Device with its key. The note of SDN-82-R1 says the other case, which TestAKeyThatOpensLateReachesItsGateway
// and TestAKeyThatOpensAgainAfterARestartReachesItsGateway pin: a gateway that this release left without a key gets it.
func TestAGatewayThatTheEarlierReleaseLeftWithoutAKeyNeedsARestart(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	h.stop()
	provider := &shutSealer{Sealer: h.sealer}
	h.sealer = provider
	h.start()
	gw, host := deviceLab(t, h, capsWireGuard)
	_, _, psk := makePhone(t, h.api)
	h.waitNode("gw", 2, true)
	waitPresharedKey(t, gw, "phone", psk)

	// The key does not open, and the gateway starts again: it gets phone without its key
	provider.shut.Store(true)
	gw.halt()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Fatalf("while the key does not open the gateway holds phone as %v, want it with its public key and without its PresharedKey", d)
	}
	waitAcked(t, h, "gw", "phone", false)
	before := updatesOf(gw2)

	// The upgrade: the controller stops, and the store holds as the Ack of the gateway the state that the earlier release
	// computed for it, with the sealed key of phone, which never reached the gateway
	h.stop()
	gw2.halt()
	host.halt()
	st, err := store.Open(ctx, h.rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	_, nodes, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, n := range nodes {
		if n.Name != "gw" {
			continue
		}
		if err := st.SaveAck(ctx, n.Name, n.Generation, n.Desired); err != nil {
			t.Fatal(err)
		}
		stored = true
	}
	st.Close()
	if !stored {
		t.Fatalf("the store holds no state of the gateway: %+v", nodes)
	}

	// This release starts with a key that opens, and the gateway, which kept its state, opens its stream at generation 2
	provider.shut.Store(false)
	h.start()
	gw2.start(h)
	h.waitNode("gw", 2, true)
	if d := ackedDevice(t, h, "gw", "phone"); d == nil || len(d.GetPresharedKey()) == 0 {
		t.Fatalf("the store holds the Ack of the gateway with phone as %v, want what the earlier release stored: with the sealed key", d)
	}
	if d := h.device("phone"); !d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("the controller lists phone as %+v, want a PresharedKey that opens: it takes the gateway for one that has it", d)
	}

	// A Device that is made now reaches the gateway, so the stream is live: it is the only update that the gateway gets, and
	// phone is not in it, since the Ack says that the gateway holds its key
	made, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw"})
	if err != nil || !made.PresharedKey {
		t.Fatalf("laptop is %+v, %v, want a Device with a PresharedKey", made, err)
	}
	laptop := configKey(t, made.Config, "PresharedKey")
	waitPresharedKey(t, gw2, "laptop", laptop)
	h.waitNode("gw", 3, true)
	if d := deviceOf(gw2, "phone"); d == nil || len(d.GetPresharedKey()) != 0 {
		t.Errorf("at generation 3 the gateway holds phone as %v, want it still without its PresharedKey: the controller trusts the Ack", d)
	}
	if n := updatesOf(gw2) - before; n != 1 {
		t.Errorf("the gateway received %d updates since the upgrade, want 1, the one of laptop: nothing for the key of phone", n)
	}

	// The remedy of the note: the gateway starts with nothing, and gets each Device with its key
	gw2.halt()
	gw3 := h.newSim("gw", keyBranch1)
	gw3.Capabilities = capsWireGuard
	gw3.start(h)
	waitPresharedKey(t, gw3, "phone", psk)
	waitPresharedKey(t, gw3, "laptop", laptop)
	h.waitNode("gw", 3, true)
}

// TestUpgradeNotesSayWhatTheControllerDoesForAGatewayOfTheEarlierRelease is the docs test of the first criterion of
// SDN-82-R2: the note of SDN-82-R2 tells the operator to restart the gateway that the earlier release left without a key of a
// Device, and says why and how, and the note of SDN-82-R1 no longer says that such a gateway gets the key. The pages are
// written for a person, so a phrase is looked for with the white space of the page folded into one space, and a page that
// loses one fails here until its reader has it again.
func TestUpgradeNotesSayWhatTheControllerDoesForAGatewayOfTheEarlierRelease(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "upgrade-notes.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(b)), " ")
	r2, r1 := strings.Index(text, "## SDN-82-R2 (#565)"), strings.Index(text, "## SDN-82-R1 (#529)")
	if r2 < 0 || r1 < r2 {
		t.Fatalf("docs/upgrade-notes.md has the note of SDN-82-R2 at %d and the note of SDN-82-R1 at %d, want the first above the second", r2, r1)
	}
	for _, want := range []string{
		"A gateway that the earlier release left without the key of a Device does not get it from this release. Restart it once.",
		"the release before SDN-82-R1 sent the Device to its gateway without the key, but stored the Ack of the gateway, the state that it acknowledged last, with the sealed key",
		"This release trusts the Ack that the store holds.",
		"sends it nothing: not when the key opens, and not after a restart of the Controller.",
		"Restart the Node service of that gateway (`Restart-Service ranzvpnserver`).",
		"The log of the earlier release names the Device of such a gateway (`the PresharedKey of a Device is not sent`)",
		"restart the gateway of each Device whose `presharedKey` is true",
		"`ranz device create` makes no file on a volume that keeps no access lists.",
		"`ranz device create` refuses a name with a colon on Windows.",
	} {
		if !strings.Contains(text[r2:r1], want) {
			t.Errorf("the note of SDN-82-R2 does not say %q", want)
		}
	}
	// The note of SDN-82-R1 says the case that holds, and not the one that the earlier release made
	if want := "A gateway that this release sent a Device without its key, since the key did not open when the Device was sent, gets the key too after a restart of the Controller with the key that sealed it. A gateway that the earlier release left so does not: see SDN-82-R2, above."; !strings.Contains(text[r1:], want) {
		t.Errorf("the note of SDN-82-R1 does not say %q", want)
	}
	if old := "A gateway that holds a Device without its key, since the key did not open when the Device was sent, gets the key too"; strings.Contains(text, old) {
		t.Errorf("docs/upgrade-notes.md still says %q, which the controller does not do for a gateway that the earlier release left without a key", old)
	}
}
