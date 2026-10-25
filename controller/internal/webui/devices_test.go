// The WireGuard Devices in the web UI (SDN-80 #375), against a controller and the node simulator
// as the other tests of the UI run.
package webui_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestTheUIShowsTheDevices is the web UI part of the sixth criterion of SDN-80: the Devices page shows
// each Device with its Network, its gateway and its addresses, and the last handshake and the traffic
// that its gateway reported in its Telemetry, as GET /api/v1/devices lists them.
func TestTheUIShowsTheDevices(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gwKey := newKey(t)
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 7, "ula": "fd07:7:7::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lab-net", Spec: json.RawMessage(`{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`,
			base64.StdEncoding.EncodeToString(gwKey.Public())))},
		{Kind: intent.KindDevice, Name: "phone", Spec: json.RawMessage(`{"network": "lab-net", "gateway": "gw", "publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="}`)},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}

	// The gateway, on which wireguard.dll loads
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

	viewer := h.token(t, "viewer-1", rbac.Viewer)
	tab := newBrowser(t)
	h.signIn(t, tab, viewer)

	// Before its gateway reported anything, the Device has its addresses and no counters
	h.visit(t, tab, "/devices", "devices")
	row := run(t, tab, chromedp.Text(chromedp.Search(`//tr[td[1][normalize-space()="phone"]]`)))
	for _, want := range []string{"lab-net", "gw", "10.70.0.2", "fd07:7:7:1::2", "not reported"} {
		if !strings.Contains(row, want) {
			t.Errorf("before its gateway reported, the row of phone on the Devices page has no %q: %q", want, row)
		}
	}

	handshake := time.Date(2026, 10, 25, 7, 30, 0, 0, time.UTC)
	if err := gw.Telemetry(&controlpb.Telemetry{Devices: []*controlpb.DeviceCounters{
		{Device: "phone", LastHandshakeMs: uint64(handshake.UnixMilli()), TxBytes: 1200, RxBytes: 3400}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		devices, err := h.admin.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) == 1 && devices[0].RxBytes == 3400 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the API does not list what gw reported for phone within %v: %+v", waitTimeout, devices)
		}
		time.Sleep(20 * time.Millisecond)
	}

	h.visit(t, tab, "/devices", "devices")
	row = run(t, tab, chromedp.Text(chromedp.Search(`//tr[td[1][normalize-space()="phone"]]`)))
	// The last handshake as the browser's locale writes it, as the page does
	when := run(t, tab, chromedp.Evaluate[string](fmt.Sprintf(`new Date(%q).toLocaleString()`, handshake.Format(time.RFC3339))))
	for _, want := range []string{when, "1200", "3400"} {
		if !strings.Contains(row, want) {
			t.Errorf("the row of phone on the Devices page has no %q after its gateway reported: %q", want, row)
		}
	}
	if strings.Contains(row, "not reported") {
		t.Errorf("the row of phone says not reported after its gateway reported: %q", row)
	}
}
