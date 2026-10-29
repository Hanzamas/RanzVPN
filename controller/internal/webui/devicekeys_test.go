// The WireGuard Devices of SDN-82 (#377) in the web UI, against a controller and the node simulator as the
// other tests of the UI run: the Devices page makes a Device with the keys that the controller makes for
// it, shows its configuration and the QR code of it once, lists it and revokes it.
package webui_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// scanCanvas reads the QR code that the Devices page drew on its canvas, as the camera of a phone reads it
// off the screen.
func scanCanvas(t *testing.T, tab context.Context) string {
	t.Helper()
	url := run(t, tab, chromedp.Evaluate[string](`document.querySelector('#qr').toDataURL('image/png')`))
	data, ok := strings.CutPrefix(url, "data:image/png;base64,")
	if !ok {
		t.Fatalf("the canvas of the page gave %.40q, no PNG", url)
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	text, err := qrscan.Scan(img)
	if err != nil {
		t.Fatalf("the canvas of the page holds no QR code that can be read: %v", err)
	}
	return text
}

// TestTheUIMakesAndRevokesADevice is the sixth criterion of SDN-82 (#377), the web UI part of the UI action
// table test: an operator makes a Device with the form of the Devices page, which offers the Networks, the
// gateways and the Users of the Intent; the page shows its finished configuration, with the keys that the
// controller made for it, and the QR code on its canvas, which a scanner reads as exactly that
// configuration; they show once, since a reload shows neither and the API renders none of the keys later;
// the Device is listed with its owner and its PresharedKey; a Device with a public key of its own gets a
// PresharedKey too, shown once; and the operator revokes a Device with its button. A viewer has no form.
func TestTheUIMakesAndRevokesADevice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gwKey := newKey(t)
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 7, "ula": "fd07:7:7::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lab-net", Spec: json.RawMessage(`{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`,
			base64.StdEncoding.EncodeToString(gwKey.Public())))},
		{Kind: intent.KindUser, Name: "alice", Spec: json.RawMessage(`{}`)},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
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

	viewer := h.token(t, "viewer-1", rbac.Viewer)
	operator := h.token(t, "operator-1", rbac.Operator)
	tab := newBrowser(t)

	// A viewer's page has no form that makes a Device, and the call that the tab of a viewer makes anyway gets
	// the refusal of the API
	h.signIn(t, tab, viewer)
	h.visit(t, tab, "/devices", "devices")
	if run(t, tab, chromedp.Evaluate[bool](`document.querySelector('#make').checkVisibility()`)) {
		t.Error("the Devices page of a viewer shows the form that makes a Device")
	}
	refused := run(t, tab, chromedp.Evaluate[string](`import('/assets/api.js').then((m) => m.call('createDevice', {body: {name: 'x', network: 'lab-net', gateway: 'gw'}})).then(() => 'allowed', (e) => e.status + ' ' + e.message)`,
		chromedp.EvalAwaitPromise))
	_, err := h.client(viewer).CreateDevice(ctx, controller.DeviceRequest{Name: "x", Network: "lab-net", Gateway: "gw"})
	var refusal *api.Error
	if !errors.As(err, &refusal) {
		t.Fatalf("the viewer's call that makes a Device through the API gave %v", err)
	}
	if want := fmt.Sprintf("%d %s", refusal.Status, refusal.Message); refused != want || refusal.Status != http.StatusForbidden {
		t.Errorf("the viewer's call that makes a Device through the UI gave %q, and through the API %q", refused, want)
	}

	// An operator's form offers what the Intent holds
	h.signIn(t, tab, operator)
	h.visit(t, tab, "/devices", "devices")
	offered := func(selector string) []string {
		return run(t, tab, chromedp.Evaluate[[]string](`[...document.querySelectorAll('`+selector+` option')].map((o) => o.value)`))
	}
	for selector, want := range map[string][]string{"#network": {"lab-net"}, "#gateway": {"gw"}, "#owner": {"", "alice"}} {
		if got := offered(selector); !slices.Equal(got, want) {
			t.Errorf("the form offers %v in %s, want %v", got, selector, want)
		}
	}

	// The operator makes a Device that the controller gives its keys
	got := h.act(t, tab,
		chromedp.SetValue(chromedp.CSS("#name"), "phone"),
		chromedp.SetValue(chromedp.CSS("#network"), "lab-net"),
		chromedp.SetValue(chromedp.CSS("#gateway"), "gw"),
		chromedp.SetValue(chromedp.CSS("#owner"), "alice"),
		chromedp.SetValue(chromedp.CSS("#tags"), "phones, staff"),
		chromedp.Click(chromedp.CSS(`#make-form button[type="submit"]`)))
	if !strings.Contains(got, "Made Device phone as revision 2.") {
		t.Errorf("making the Device says %q", got)
	}
	shown := run(t, tab, chromedp.Evaluate[string](`document.querySelector('#config').textContent`))
	for _, want := range []string{"\nPrivateKey = ", "\nPresharedKey = ", "\nAddress = 10.70.0.2/32, fd07:7:7:1::2/128\n", "\nPublicKey = ERERERERERERERERERERERERERERERERERERERERERE=\n",
		"\nEndpoint = gw.example.net:51820\n"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the configuration on the page has no %q:\n%s", strings.TrimSpace(want), shown)
		}
	}
	if note := run(t, tab, chromedp.Evaluate[string](`document.querySelector('#keys-note').textContent`)); !strings.Contains(note, "The private key and the PresharedKey in this configuration show only now") {
		t.Errorf("the page says %q of the keys", note)
	}
	// The QR code on the canvas reads as exactly the configuration that the page shows
	if text := scanCanvas(t, tab); text != shown {
		t.Errorf("the QR code on the page reads as\n%s\nwant the configuration that the page shows\n%s", text, shown)
	}

	// The Device is listed, with its owner and its PresharedKey, and the controller has it as the page says
	row := `//tr[td[1][normalize-space()="phone"]]`
	run(t, tab, chromedp.WaitVisible(chromedp.Search(row)))
	text := run(t, tab, chromedp.Text(chromedp.Search(row)))
	for _, want := range []string{"lab-net", "gw", "alice", "10.70.0.2", "yes"} {
		if !strings.Contains(text, want) {
			t.Errorf("the row of phone on the Devices page has no %q: %q", want, text)
		}
	}
	devices, err := h.admin.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Name != "phone" || devices[0].Owner != "alice" || !devices[0].PresharedKey {
		t.Fatalf("the API lists %+v, want Device phone of alice with a PresharedKey", devices)
	}

	// It shows once: the controller renders neither key later, and a reload of the page shows neither
	later, err := h.admin.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PrivateKey", "PresharedKey"} {
		var key string
		for _, line := range strings.Split(shown, "\n") {
			if v, ok := strings.CutPrefix(line, name+" = "); ok {
				key = v
			}
		}
		if key == "" || strings.Contains(later, key) {
			t.Errorf("the key %s of the page is %q, and the configuration that the API renders later holds it: %v", name, key, strings.Contains(later, key))
		}
	}
	h.visit(t, tab, "/devices", "devices")
	if run(t, tab, chromedp.Evaluate[bool](`document.querySelector('#issued').checkVisibility()`)) ||
		run(t, tab, chromedp.Evaluate[string](`document.querySelector('#config').textContent`)) != "" {
		t.Error("the Devices page shows a configuration after a reload")
	}

	// A Device with a public key of its own, a router: the controller makes the PresharedKey, and the page
	// says that the private key goes into the configuration by hand
	const routerKey = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	got = h.act(t, tab,
		chromedp.SetValue(chromedp.CSS("#name"), "router"),
		chromedp.SetValue(chromedp.CSS("#network"), "lab-net"),
		chromedp.SetValue(chromedp.CSS("#gateway"), "gw"),
		chromedp.SetValue(chromedp.CSS("#public-key"), routerKey),
		chromedp.Click(chromedp.CSS(`#make-form button[type="submit"]`)))
	if !strings.Contains(got, "Made Device router as revision 3.") {
		t.Errorf("making the router says %q", got)
	}
	shown = run(t, tab, chromedp.Evaluate[string](`document.querySelector('#config').textContent`))
	if !strings.Contains(shown, "\n# PrivateKey = the private key of this Device, which only the Device holds\n") || !strings.Contains(shown, "\nPresharedKey = ") || strings.Contains(shown, "\nPrivateKey = ") {
		t.Errorf("the configuration of the router on the page is\n%s", shown)
	}
	if note := run(t, tab, chromedp.Evaluate[string](`document.querySelector('#keys-note').textContent`)); !strings.Contains(note, "The PresharedKey in this configuration shows only now") {
		t.Errorf("the page says %q of the keys of the router", note)
	}
	if text := scanCanvas(t, tab); text != shown {
		t.Errorf("the QR code of the router reads as\n%s\nwant the configuration that the page shows\n%s", text, shown)
	}
	// The button that clears the configuration clears it
	run(t, tab, chromedp.Click(chromedp.CSS("#done")))
	if run(t, tab, chromedp.Evaluate[bool](`document.querySelector('#issued').checkVisibility()`)) ||
		run(t, tab, chromedp.Evaluate[string](`document.querySelector('#config').textContent`)) != "" {
		t.Error("the Devices page shows the configuration after the button that clears it")
	}

	// The operator revokes the first Device with its button: it is a new revision, and the controller no longer lists it
	run(t, tab, chromedp.WaitVisible(chromedp.Search(`//tr[td[1][normalize-space()="router"]]`)))
	got = h.act(t, tab, chromedp.Click(chromedp.Search(row+`//button`)),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
		chromedp.Click(chromedp.CSS(`dialog[open] button[value="ok"]`)))
	if !strings.Contains(got, "Revoked Device phone as revision 4.") {
		t.Errorf("revoking the Device says %q", got)
	}
	run(t, tab, chromedp.WaitNotPresent(chromedp.Search(row)))
	devices, err = h.admin.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Name != "router" {
		t.Errorf("after the revoke the API lists %+v, want the router alone", devices)
	}
}
