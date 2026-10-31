// The Devices page and a PresharedKey that does not open (SDN-82-R1 #529), against a controller and the node simulator
// as the other tests of the UI run.
package webui_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// shutSealer is the sealing key of the host of a harness, whose key storage provider does not open what it sealed while
// shut is set, as one that does not answer: sealing takes the public half of the key alone, and works either way.
type shutSealer struct {
	store.Sealer
	shut atomic.Bool
}

func (s *shutSealer) Open(label string, sealed []byte) ([]byte, error) {
	if s.shut.Load() {
		return nil, errors.New("the provider does not answer")
	}
	return s.Sealer.Open(label, sealed)
}

// TestTheDevicesPageSaysThatAPresharedKeyDoesNotOpen is the Devices page of the third criterion of SDN-82-R1: a Device whose
// PresharedKey the controller cannot open says so in the column PresharedKey, in the place of yes, so that nobody takes its
// gateway for one that holds the key; a Device that has none says no.
func TestTheDevicesPageSaysThatAPresharedKeyDoesNotOpen(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gwKey := newKey(t)
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 7, "ula": "fd07:7:7::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lab-net", Spec: json.RawMessage(`{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`,
			base64.StdEncoding.EncodeToString(gwKey.Public())))},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}

	// serve keeps a gateway on which wireguard.dll loads on a control stream, from a start with nothing, until the
	// function that it returns stops it
	serve := func() func() {
		gw := &nodesim.Node{Key: gwKey, Controller: h.ln.Addr().String(), ControllerKey: h.key.Public(),
			Capabilities: &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
				Wireguard: true, WireguardKey: bytes.Repeat([]byte{0x11}, 32)}}
		sctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() { served <- gw.Serve(sctx) }()
		return func() {
			cancel()
			<-served
		}
	}
	stop := serve()
	h.waitNode(t, "gw", 1)
	if _, err := h.admin.CreateDevice(ctx, controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.CreateDevice(ctx, controller.DeviceRequest{Name: "plain", Network: "lab-net", Gateway: "gw", NoPresharedKey: true}); err != nil {
		t.Fatal(err)
	}
	h.waitNode(t, "gw", 3)

	// The provider does not answer, and the gateway starts again with nothing: the controller cannot open the key of phone
	// that it sends the gateway
	h.sealer.shut.Store(true)
	stop()
	t.Cleanup(serve())
	for deadline := time.Now().Add(waitTimeout); ; time.Sleep(pollInterval) {
		devices, err := h.admin.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) == 2 && devices[0].Name == "phone" && devices[0].PresharedKey && devices[0].PresharedKeyDoesNotOpen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the API lists %+v within %v, want phone with a PresharedKey that does not open", devices, waitTimeout)
		}
	}

	tab := newBrowser(t)
	h.signIn(t, tab, h.token(t, "viewer-1", rbac.Viewer))
	h.visit(t, tab, "/devices", "devices")
	for name, want := range map[string]string{"phone": "does not open", "plain": "no"} {
		row := `//tr[td[1][normalize-space()="` + name + `"]]`
		run(t, tab, chromedp.WaitVisible(chromedp.Search(row)))
		cell := run(t, tab, chromedp.Text(chromedp.Search(row+`/td[6]`)))
		if strings.TrimSpace(cell) != want {
			t.Errorf("the Devices page says %q of the PresharedKey of %s, want %q", cell, name, want)
		}
	}
}
