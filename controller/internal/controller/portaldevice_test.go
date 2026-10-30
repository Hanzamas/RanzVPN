// The WireGuard Devices of a User in the portal (SDN-58 #251, on the Devices and their owners of SDN-82 #377),
// with the harness and the node simulator of conformance_test.go and the logins of logins_test.go: an
// administrator makes a Device for a User, and the portal lists it among the devices of that User with the tags
// that policy sees it with (its own and the Groups of the User), its address and the last handshake that its
// gateway reported; it counts against the maximum devices of the User as a Node does; no other User sees it or
// removes it; and the User removes it, which is a revision under its name that the gateway carries out with its
// next Generation, and which takes the PresharedKey of the Device with it.
package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// waitSelfDeviceWhere polls the devices that the portal shows c until the device name satisfies ok, and returns
// it. what says what the wait is for.
func waitSelfDeviceWhere(t *testing.T, c *api.Client, name, what string, ok func(controller.SelfDevice) bool) controller.SelfDevice {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		devices, err := c.SelfDevices(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devices {
			if d.Name == name && ok(d) {
				return d
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the device %s is not %s within %v: %+v", name, what, waitTimeout, devices)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// gatewayEnv returns the portal environment of portalIntent, with a sealing key for the PresharedKeys of the
// Devices, and the gateway gw of VRF default: a Node with a WireGuard end, on which wireguard.dll loads, that is
// connected at its first Generation.
func gatewayEnv(t *testing.T) (*loginEnv, *sim) {
	t.Helper()
	e := newLoginEnvWith(t, func(h *harness) {
		sealing, err := keys.GenerateSoft()
		if err != nil {
			t.Fatal(err)
		}
		h.sealer = keys.NewSealer(sealing)
	})
	portalIntent(t, e)
	gwKey := nodeKey(9)
	e.h.applyDoc(usersDoc(t, fmt.Sprintf(`{"kind": "Node", "name": "gw", "spec": {"publicKey": %q, "wireguard": {"endpoint": "gw.example.net"}}}`,
		base64.StdEncoding.EncodeToString(gwKey.Public()))))
	gw := e.h.newSim("gw", gwKey)
	gw.Capabilities = capsWireGuard
	gw.start(e.h)
	gw.update(t)
	e.h.waitNode("gw", 1, true)
	return e, gw
}

// TestAUserSeesAndRemovesTheWireGuardDevicesThatAreHers: the Device that an administrator made for alice is one
// of her devices. The portal lists it after her laptop with the tags of the Device and the Group of its owner,
// its VRF, its address and, once its gateway reports one, its last handshake, and none of the keys that the
// controller showed once. It counts against her maximum devices, so a third device is refused as `ranz apply`
// refuses it. Bob sees none of it and removes none of it, whichever kind he names. Alice removes it: a
// revision under her name, which its gateway carries out with its next Generation and which takes the
// PresharedKey of the Device with it, and the room that it held is hers again.
func TestAUserSeesAndRemovesTheWireGuardDevicesThatAreHers(t *testing.T) {
	e, gw := gatewayEnv(t)
	h, ctx := e.h, context.Background()

	// An administrator makes a Device for alice, with the keys that the controller makes for it and shows once
	made, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "alice-phone", Network: intent.DefaultNetwork, Gateway: "gw", Owner: "alice", Tags: []string{"phones"}})
	if err != nil {
		t.Fatal(err)
	}
	private, psk := configKey(t, made.Config, "PrivateKey"), configKey(t, made.Config, "PresharedKey")
	if private == nil || psk == nil {
		t.Fatalf("the configuration of the Device holds no private key or no PresharedKey:\n%s", made.Config)
	}
	waitDevice(t, gw, "alice-phone")
	alice, _ := e.portal(t, "alice", alicePassword)
	bob, _ := e.portal(t, "bob", bobPassword)

	// The portal lists it after her laptop: how it stands, and what policy sees of it
	devices, err := alice.SelfDevices(ctx)
	if err != nil || !slices.Equal(deviceNames(devices), []string{"alice-laptop", "alice-phone"}) {
		t.Fatalf("the devices of alice are %+v, %v, want her laptop and her Device", devices, err)
	}
	dev := h.device("alice-phone")
	wantAddresses := []controller.SelfAddress{{Network: intent.DefaultNetwork, Address: dev.Address}}
	if dev.IPv6Address != "" {
		wantAddresses = append(wantAddresses, controller.SelfAddress{Network: intent.DefaultNetwork, Address: dev.IPv6Address})
	}
	phone := devices[1]
	if dev.Address == "" || phone.Kind != intent.KindDevice || phone.State != "" || phone.Connected || !phone.LastHandshake.IsZero() || !phone.KeyExpires.IsZero() ||
		!slices.Equal(phone.Tags, []string{"phones", "staff"}) || !slices.Equal(phone.VRFs, []string{intent.DefaultVRF}) || !slices.Equal(phone.Addresses, wantAddresses) {
		t.Errorf("the Device of alice, before its gateway reports a handshake, is %+v, and the controller lists it as %+v: want its own tag and the Group of alice, VRF default and its addresses", phone, dev)
	}

	// Its gateway reports a handshake, and the portal shows it
	handshake := time.Date(2026, 10, 29, 20, 30, 0, 0, time.UTC)
	if err := gw.Telemetry(&controlpb.Telemetry{Devices: []*controlpb.DeviceCounters{
		{Device: "alice-phone", LastHandshakeMs: uint64(handshake.UnixMilli()), TxBytes: 10, RxBytes: 20}}}); err != nil {
		t.Fatal(err)
	}
	waitSelfDeviceWhere(t, alice, "alice-phone", "shown with the handshake that its gateway reported", func(d controller.SelfDevice) bool { return d.LastHandshake.Equal(handshake) })

	// The list holds none of the keys that the controller showed once, in any form
	devices, err = alice.SelfDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list, err := json.Marshal(devices)
	if err != nil {
		t.Fatal(err)
	}
	for what, secret := range map[string][]byte{"private key": private, "PresharedKey": psk} {
		if found := holds(list, secret); len(found) > 0 {
			t.Errorf("the list of the devices of alice holds the %s of her Device, in the forms %v", what, found)
		}
	}

	// The Device counts against her maximum of 2, as her laptop does: a third device is refused as an apply refuses it
	if info, err := alice.Self(ctx); err != nil || info.Devices != 2 || info.MaxDevices != 2 {
		t.Errorf("the portal shows alice with %+v, %v, want 2 devices of 2", info, err)
	}
	tablet := base64.StdEncoding.EncodeToString(nodeKey(5).Public())
	if _, err := alice.AddSelfDevice(ctx, "alice-tablet", tablet); httpStatus(err) != http.StatusBadRequest || !strings.Contains(errText(err), "the maximum is 2") {
		t.Errorf("a third device of alice, with her Device and her laptop: %v, want 400 and the refusal of ranz apply", err)
	}

	// Bob sees his laptop alone, and the Device of alice is no device of his to remove, whichever kind he names
	if devices, err := bob.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"bob-laptop"}) {
		t.Errorf("the devices of bob are %+v, %v, want his laptop alone", devices, err)
	}
	before := h.resources()
	for _, c := range []struct {
		who  *api.Client
		kind string
	}{{bob, intent.KindDevice}, {bob, intent.KindNode}, {alice, intent.KindNode}} {
		if _, err := c.who.RemoveSelfDevice(ctx, c.kind, "alice-phone"); httpStatus(err) != http.StatusNotFound {
			t.Errorf("removing alice-phone as the kind %s: %v, want 404", c.kind, err)
		}
	}
	if after := h.resources(); after != before {
		t.Errorf("a removal that is not the User's own changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || rows["alice-phone"] == "" {
		t.Fatalf("the PresharedKeys in the store before the removal are %v, %v, want that of alice-phone", rows, err)
	}

	// Alice removes it: the gateway stops terminating it with its next Generation, and its PresharedKey is gone
	removed, err := alice.RemoveSelfDevice(ctx, intent.KindDevice, "alice-phone")
	if err != nil || removed.Revision <= made.Revision {
		t.Fatalf("alice removes her Device: %+v, %v", removed, err)
	}
	deadline := time.Now().Add(waitTimeout)
	for deviceOf(gw, "alice-phone") != nil {
		if time.Now().After(deadline) {
			t.Fatalf("the gateway still terminates the Device that alice removed after %v", waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 0 {
		t.Errorf("the PresharedKeys in the store after the removal are %v, %v, want none", rows, err)
	}
	if devices, err := alice.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"alice-laptop"}) {
		t.Errorf("the devices of alice after the removal are %+v, %v, want her laptop alone", devices, err)
	}
	if left, err := h.api.Devices(ctx); err != nil || len(left) != 0 {
		t.Errorf("the controller lists the Devices %+v, %v after the removal, want none", left, err)
	}
	if info, err := alice.Self(ctx); err != nil || info.Devices != 1 {
		t.Errorf("the portal shows alice with %+v, %v after the removal, want 1 device", info, err)
	}
	if _, err := alice.AddSelfDevice(ctx, "alice-tablet", tablet); err != nil {
		t.Errorf("a device of alice, now that her Device is gone and she has room: %v", err)
	}

	// The removal is a revision under her name, and a call of hers, in the audit log
	h.waitAudit(h.api, "the removal of the Device by alice", func(rs []audit.Record) bool {
		var revised, called bool
		for _, r := range auditOfKind(rs, audit.IntentChange) {
			revised = revised || r.Revision == removed.Revision && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
		}
		for _, r := range auditOfKind(rs, audit.Operation) {
			called = called || r.Action == "DELETE /api/v1/self/devices/Device/alice-phone" && r.Actor == audit.ActorUser("alice") && r.Outcome == audit.Success
		}
		return revised && called
	})
}

// TestTheDeviceOfAUserBeyondTheLicenceIsShownAsSuch: a Device counts as a client node for the licence, and one
// above the node cap in force is in the state of no node, so the portal says that it is beyond the licence of the
// controller and not that its gateway has not seen it yet.
func TestTheDeviceOfAUserBeyondTheLicenceIsShownAsSuch(t *testing.T) {
	e, gw := gatewayEnv(t)
	h, ctx := e.h, context.Background()
	if _, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "alice-phone", Network: intent.DefaultNetwork, Gateway: "gw", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}
	waitDevice(t, gw, "alice-phone")
	alice, _ := e.portal(t, "alice", alicePassword)
	if devices, err := alice.SelfDevices(ctx); err != nil || !slices.Equal(deviceNames(devices), []string{"alice-laptop", "alice-phone"}) || devices[1].State != "" {
		t.Fatalf("the devices of alice under the licence of the first install are %+v, %v, want her laptop and her Device, which has no state", devices, err)
	}

	// A node cap that the Nodes of the intent fill: the Device is above it
	nodes, err := h.api.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.setLicence(licence.Licence{ID: "personal-small", Licensee: "Test", Tier: licence.Personal, Nodes: len(nodes), Expires: time.Now().Add(year)})
	d := waitSelfDeviceWhere(t, alice, "alice-phone", "beyond the licence", func(d controller.SelfDevice) bool { return d.State == controller.DeviceUnlicensed })
	if d.Kind != intent.KindDevice || !d.LastHandshake.IsZero() {
		t.Errorf("the Device of alice beyond the licence is %+v", d)
	}
}
