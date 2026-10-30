// The status that the portal gives a device (SDN-58 #251), with the clock of the lives of the keys that
// nodekeys_test.go moves: beside whether its Node is connected, the state of its key (SDN-56 #249). A Node that a
// Network holds for approval waits for an administrator, one whose key ended is held back until its User logs in
// again, and the portal says each, with when the key ends.
package controller_test

import (
	"context"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// TestThePortalSaysWhenADeviceWaitsForApprovalOrItsKeyEnded: a device of alice that a Network holds for approval is
// shown as waiting, and as offline with a key that ends in 90 days once an administrator approves it; after 91 days
// its key has ended, which the portal says, and when alice logs in again with the device the key lives again.
func TestThePortalSaysWhenADeviceWaitsForApprovalOrItsKeyEnded(t *testing.T) {
	j := newJoinHarness(t, "alice")
	ctx := context.Background()
	j.h.setPasswords("alice")
	// A Network that holds its new Nodes for approval, and a device of alice that comes after it
	j.h.applyJSON(keysVRF, keysNetwork(`, "approval": "manual"`))
	j.h.applyJSON(keysNode("alice-laptop", keyBranch1, "10.10.0.1", `, "owner": "alice"`))
	alice := j.self("alice")
	start := j.clk.Now()
	is := func(state string) func(controller.SelfDevice) bool {
		return func(d controller.SelfDevice) bool { return d.State == state }
	}

	// It waits for an administrator, and is not connected
	if d := waitSelfDeviceWhere(t, alice, "alice-laptop", "waiting for approval", is(controller.KeyPending)); d.Connected {
		t.Errorf("the device that waits for approval is %+v, want it not connected", d)
	}

	// An administrator approves it: its key lives 90 days from then, and the device is offline until it connects
	if _, err := j.h.api.ApproveNode(ctx, "alice-laptop"); err != nil {
		t.Fatal(err)
	}
	d := waitSelfDeviceWhere(t, alice, "alice-laptop", "offline once approved", is(controller.DeviceOffline))
	if want := start.Add(90 * keyDay); !d.KeyExpires.Equal(want) {
		t.Errorf("the key of the device ends at %v, want %v, 90 days after the approval", d.KeyExpires, want)
	}

	// After 91 days its key has ended: the portal says so, with when it ended
	j.clk.Advance(91 * keyDay)
	if d := waitSelfDeviceWhere(t, alice, "alice-laptop", "held back for its key", is(controller.KeyExpired)); !d.KeyExpires.Equal(start.Add(90 * keyDay)) {
		t.Errorf("the device whose key ended is %+v, want the end of its key, %v", d, start.Add(90*keyDay))
	}

	// Alice logs in again with the device: its key lives 90 days from then
	if err := j.h.reauthenticate("alice", "a good password", keyBranch1); err != nil {
		t.Fatal(err)
	}
	d = waitSelfDeviceWhere(t, alice, "alice-laptop", "offline again", is(controller.DeviceOffline))
	if want := start.Add(91*keyDay + 90*keyDay); !d.KeyExpires.Equal(want) {
		t.Errorf("the key of the device ends at %v after its login, want %v", d.KeyExpires, want)
	}
}
