// The WireGuard Devices of a User in the portal (SDN-58 #251, on the Devices of SDN-82 #377), against a
// controller and the node simulator as the other tests of the UI run: the Device that an administrator made for
// a User is one of the devices on the page My devices, with its tags and its handshake, and the User removes it
// with its button, after a question that says what the removal of a Device means.
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
)

// TestThePortalListsAndRemovesAWireGuardDevice: alice signs in to the portal and finds the Device that an
// administrator made for her, as a WireGuard device with its address and the tags that policy sees (its own and
// the Group of her), and no handshake yet; once its gateway reports one the page shows it; and she removes the
// Device with its button, after the question that tells her that an administrator makes the next one. The
// controller then holds no Device.
func TestThePortalListsAndRemovesAWireGuardDevice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gwKey := newKey(t)
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: intent.DefaultVRF, Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lan", Spec: json.RawMessage(`{"vrf": "default", "ipv4Pool": "10.10.0.0/24"}`)},
		{Kind: intent.KindGroup, Name: "staff", Spec: json.RawMessage(`{}`)},
		{Kind: intent.KindUser, Name: "alice", Spec: json.RawMessage(`{"groups": ["staff"], "maxDevices": 4}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "wireguard": {"endpoint": "gw.example.net"}}`, portalKey(gwKey)))},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.SetUserPassword(ctx, "alice", portalAlicePassword); err != nil {
		t.Fatal(err)
	}

	// The gateway, on which wireguard.dll loads: it reports the key of its WireGuard interface
	gw := &nodesim.Node{Key: gwKey, Controller: h.ln.Addr().String(), ControllerKey: h.key.Public(),
		Capabilities: &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
			Wireguard: true, WireguardKey: bytes.Repeat([]byte{0x11}, 32)}}
	sctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- gw.Serve(sctx) }()
	t.Cleanup(func() {
		stop()
		<-served
	})
	h.waitNode(t, "gw", 1)

	// An administrator makes a Device for alice
	if _, err := h.admin.CreateDevice(ctx, controller.DeviceRequest{Name: "alice-phone", Network: "lan", Gateway: "gw", Owner: "alice", Tags: []string{"phones"}}); err != nil {
		t.Fatal(err)
	}

	tab := newBrowser(t)
	h.portalSignIn(t, tab, "alice", portalAlicePassword)
	portalControls(t, tab, "My devices", "selfDevices", "addSelfDevice", "removeSelfDevice", "signOut")
	rows := portalRows(t, tab, "#devices", 1)
	for _, want := range []string{"alice-phone", "WireGuard", "No handshake yet", "10.10.0.", "(lan)", "phones, staff"} {
		if !strings.Contains(rows[0], want) {
			t.Errorf("the row of the Device of alice has no %q: %q", want, rows[0])
		}
	}
	if account := run(t, tab, chromedp.Text(chromedp.CSS("#account"))); !strings.Contains(account, "1 of 4") {
		t.Errorf("the account is %q, want her one device of four: the Device counts", account)
	}

	// Its gateway reports a handshake, and the page shows it
	handshake := time.Date(2026, 10, 29, 20, 30, 0, 0, time.UTC)
	if err := gw.Telemetry(&controlpb.Telemetry{Devices: []*controlpb.DeviceCounters{
		{Device: "alice-phone", LastHandshakeMs: uint64(handshake.UnixMilli()), TxBytes: 10, RxBytes: 20}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		devices, err := h.admin.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) == 1 && devices[0].LastHandshake.Equal(handshake) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the controller does not list the handshake that the gateway reported within %v: %+v", waitTimeout, devices)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.visit(t, tab, "/portal", "portal")
	if rows := portalRows(t, tab, "#devices", 1); !strings.Contains(rows[0], "Last handshake") || strings.Contains(rows[0], "No handshake yet") {
		t.Errorf("the row of the Device after its handshake is %q, want the handshake", rows[0])
	}

	// She removes it after the question, which says that the configuration stops working and who makes the next one
	run(t, tab, chromedp.Steps(
		press(`//tr[td[1][normalize-space()="alice-phone"]]//button`),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
	))
	question := run(t, tab, chromedp.Text(chromedp.CSS("dialog[open] p")))
	for _, want := range []string{"WireGuard device alice-phone", "stops working for good", "an administrator makes a new Device"} {
		if !strings.Contains(question, want) {
			t.Errorf("the question before the removal of a Device is %q, want it to say %q", question, want)
		}
	}
	if strings.Contains(question, "you can add it again") {
		t.Errorf("the question before the removal of a Device promises that it can be added again: %q", question)
	}
	if got := h.act(t, tab, press(`//dialog[@open]//button[@value="ok"]`)); !strings.Contains(got, "The device alice-phone is removed") {
		t.Errorf("removing the Device says %q", got)
	}
	portalRows(t, tab, "#devices", 0)
	if left, err := h.admin.Devices(ctx); err != nil || len(left) != 0 {
		t.Errorf("the controller lists the Devices %+v, %v after the removal, want none", left, err)
	}
}
