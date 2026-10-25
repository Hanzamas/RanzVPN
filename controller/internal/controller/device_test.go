// WireGuard Devices in the controller conformance seam (SDN-80 #375): a Device of a Network takes
// its addresses from the pools of the Network and keeps them, the controller compiles it into the
// state of its gateway with its key and into the state of every other node of the VRF without, its
// configuration is a golden output, a gateway without the Capability wireguard makes the controller
// refuse the intent before apply, a rule that names a Device by its tags reaches its gateway, the
// API lists the last handshake and the traffic that the gateway reports, and a Device counts as a
// client node for the licence.
package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// capsWireGuard is a Windows Server gateway on which wireguard.dll loads: capsServer with the
// Capability wireguard and the key of its WireGuard interface, 32 bytes of 0x11.
var capsWireGuard = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
	HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT,
	Wireguard: true, WireguardKey: []byte(strings.Repeat("\x11", 32))}

// gwMissesWireGuard is the problem of the gateway gw, which reports capsServer, with Device phone.
const gwMissesWireGuard = `Node "gw" (Server, x64): WireGuard Device "phone" needs wireguard, which the node does not report`

// deviceLab applies device-lab.json, the VRF lab with the gateway gw and the node host, and starts
// both nodes with gw reporting caps; it returns them once they acknowledged generation 1.
func deviceLab(t *testing.T, h *harness, caps *controlpb.Capabilities) (gw, host *sim) {
	t.Helper()
	h.apply("device-lab.json")
	gw = h.newSim("gw", keyBranch1)
	gw.Capabilities = caps
	gw.start(h)
	host = h.sim("host", keyBranch2)
	gw.update(t)
	host.update(t)
	h.waitNode("gw", 1, true)
	h.waitNode("host", 1, true)
	return gw, host
}

// TestDeviceNeedsWireGuardAtItsGateway is the third criterion of SDN-80: a gateway that does not
// report the Capability wireguard makes the controller refuse the intent that gives it a Device,
// before apply, with 409 Conflict and a message that names the Node and the Device. Nothing of it
// reaches a node.
func TestDeviceNeedsWireGuardAtItsGateway(t *testing.T) {
	h := newHarness(t)
	deviceLab(t, h, capsServer)
	before := h.resources()

	_, err := h.tryApply("device-phone.json")
	if httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), gwMissesWireGuard) {
		t.Errorf("a Device whose gateway does not report wireguard gave %v, want a 409 that names %q", err, gwMissesWireGuard)
	}
	if err != nil && strings.Contains(err.Error(), `Node "host"`) {
		t.Errorf("the refusal %q names host, which is no gateway of the Device", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	h.waitNode("gw", 1, true)
	h.waitNode("host", 1, true)
}

// TestDeviceJoinsThroughItsGateway is the fourth criterion of SDN-80: the Device gets an IPv4 and an
// IPv6 address of the pools of its Network and keeps them across a restart of its gateway and of the
// controller and when the intent changes around it; its gateway gets it with its key and the port of
// its WireGuard interface, the other node of the VRF without the key; and its configuration is the
// golden output testdata/device-phone.conf.
func TestDeviceJoinsThroughItsGateway(t *testing.T) {
	h := newHarness(t)
	gw, host := deviceLab(t, h, capsWireGuard)

	res := h.apply("device-phone.json")
	if want := []controller.NodeGeneration{{Name: "gw", Generation: 2}, {Name: "host", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("device-phone.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "device-gw", gw.update(t))
	golden(t, "device-host", host.update(t))
	h.waitNode("gw", 2, true)
	h.waitNode("host", 2, true)
	h.checkState(gw)
	h.checkState(host)
	checkPhone(t, h)
	checkPhoneConfig(t, h)

	// The gateway restarts: it is given the same state, and the Device keeps its addresses
	gw.halt()
	gw.start(h)
	h.waitNode("gw", 2, true)
	h.checkState(gw)
	checkPhone(t, h)

	// The same document again changes nothing, and a new Node that sorts before every other one
	// takes the next free address, not the one of the Device
	if res := h.apply("device-phone.json"); len(res.Nodes) != 0 {
		t.Errorf("device-phone.json applied again changed %+v", res.Nodes)
	}
	h.apply("device-alpha.json")
	h.waitNode("gw", 3, true)
	h.waitNode("host", 3, true)
	checkPhone(t, h)
	alpha := h.resource("Node", "alpha")
	if !strings.Contains(alpha, `"lab-net":"10.70.0.4"`) || !strings.Contains(alpha, `"lab-net":"fd07:7:7:1::4"`) {
		t.Errorf("Node alpha is %s, want the addresses 10.70.0.4 and fd07:7:7:1::4, after those of the Device", alpha)
	}

	// The controller restarts: the Device and its configuration are as they were
	h.stop()
	for _, s := range []*sim{gw, host} {
		s.end(t)
	}
	h.start()
	checkPhone(t, h)
	gw.start(h)
	h.waitNode("gw", 3, true)
	checkPhoneConfig(t, h)
}

// TestDeviceDenyRuleReachesItsGateway is the conformance part of the second criterion of SDN-80: a
// rule that denies the Device by its tag is in the compiled policy of its gateway, which judges the
// flows of the Device, and of the other node of the VRF, which judges them at their other end.
func TestDeviceDenyRuleReachesItsGateway(t *testing.T) {
	h := newHarness(t)
	gw, host := deviceLab(t, h, capsWireGuard)
	h.apply("device-phone.json")
	gw.update(t)
	host.update(t)
	h.waitNode("gw", 2, true)
	h.waitNode("host", 2, true)

	h.apply("device-deny.json")
	golden(t, "device-deny", gw.update(t))
	golden(t, "device-deny", host.update(t))
	h.waitNode("gw", 3, true)
	h.waitNode("host", 3, true)
	h.checkState(gw)
	h.checkState(host)
}

// TestGetDevicesShowsHandshakeAndTraffic is the API part of the sixth criterion of SDN-80: the
// last handshake and the traffic that the gateway of a Device reports in its Telemetry are what
// GET /api/v1/devices lists for it, and a node that is not its gateway cannot report them.
func TestGetDevicesShowsHandshakeAndTraffic(t *testing.T) {
	h := newHarness(t)
	gw, host := deviceLab(t, h, capsWireGuard)
	h.apply("device-phone.json")
	gw.update(t)
	host.update(t)
	h.waitNode("gw", 2, true)

	if d := h.device("phone"); !d.LastHandshake.IsZero() || d.TxBytes != 0 || d.RxBytes != 0 || !d.Reported.IsZero() {
		t.Errorf("before its gateway reported anything, Device phone is %+v", d)
	}
	handshake := time.Date(2026, 10, 25, 7, 30, 0, 0, time.UTC)
	if err := host.Telemetry(&controlpb.Telemetry{Devices: []*controlpb.DeviceCounters{{Device: "phone", LastHandshakeMs: 1, TxBytes: 99, RxBytes: 99}}}); err != nil {
		t.Fatal(err)
	}
	if err := gw.Telemetry(&controlpb.Telemetry{Devices: []*controlpb.DeviceCounters{
		{Device: "phone", LastHandshakeMs: uint64(handshake.UnixMilli()), TxBytes: 1200, RxBytes: 3400}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		d := h.device("phone")
		if d.RxBytes == 3400 {
			if !d.LastHandshake.Equal(handshake) || d.TxBytes != 1200 || d.Reported.IsZero() {
				t.Errorf("Device phone is %+v, want the last handshake %v, 1200 bytes sent and 3400 received", d, handshake)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the API does not list what gw reported for Device phone within %v: %+v", waitTimeout, d)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDeviceCountsAsClientNode is the ninth criterion of SDN-80: a Device counts as a client node
// for the licence. With a cap of 3 and two Nodes, one Device fits and the next is refused with a
// message that names it; under a cap that the Nodes fill, the Device is listed as unlicensed and is in
// the state of no node.
func TestDeviceCountsAsClientNode(t *testing.T) {
	h := newHarness(t)
	h.setLicence(licence.Licence{ID: "personal-3", Licensee: "Test", Tier: licence.Personal, Nodes: 3, Expires: time.Now().Add(year)})
	h.apply("device-lab.json")
	h.apply("device-phone.json")
	before := h.resources()

	_, err := h.tryApply("device-laptop.json")
	want := `refused by the licence: the Personal licence in force allows 3 nodes, and this apply would make 4 (new: Device "laptop"); a Business or Enterprise licence key raises the cap`
	if httpStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), want) {
		t.Errorf("a Device above the cap gave %v, want a 403 that says %q", err, want)
	}
	if after := h.resources(); after != before {
		t.Errorf("an apply above the cap changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if d := h.device("phone"); d.Unlicensed {
		t.Errorf("Device phone, the third of a cap of 3, is listed as unlicensed: %+v", d)
	}

	h.setLicence(licence.Licence{ID: "personal-2", Licensee: "Test", Tier: licence.Personal, Nodes: 2, Expires: time.Now().Add(year)})
	if d := h.device("phone"); !d.Unlicensed {
		t.Errorf("Device phone, above a cap of 2 that the Nodes fill, is listed as %+v, want unlicensed", d)
	}
	// host got generation 1 with the Nodes, 2 with the Device and 3 without it again
	host := h.sim("host", keyBranch2)
	host.update(t)
	h.waitNode("host", 3, true)
	h.checkState(host)
}

// checkPhone checks the addresses of Device phone that the API lists: the first free ones of the
// pools of lab-net after the Nodes gw and host.
func checkPhone(t *testing.T, h *harness) {
	t.Helper()
	d := h.device("phone")
	if d.Network != "lab-net" || d.Gateway != "gw" || d.Address != "10.70.0.3" || d.IPv6Address != "fd07:7:7:1::3" {
		t.Errorf("Device phone is %+v, want Network lab-net through gw with the addresses 10.70.0.3 and fd07:7:7:1::3", d)
	}
}

// checkPhoneConfig compares the configuration of Device phone with testdata/device-phone.conf.
func checkPhoneConfig(t *testing.T, h *harness) {
	t.Helper()
	got, err := h.api.DeviceConfig(context.Background(), "phone")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "device-phone.conf")
	if *rewrite {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A checkout on Windows may give the golden file CRLF line ends
	if want := strings.ReplaceAll(string(b), "\r\n", "\n"); got != want {
		t.Errorf("%s: the configuration differs from the golden file\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

// device returns the status of the Device name as the API lists it.
func (h *harness) device(name string) controller.DeviceStatus {
	h.t.Helper()
	devices, err := h.api.Devices(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, d := range devices {
		if d.Name == name {
			return d
		}
	}
	h.t.Fatalf("the API lists no Device %s: %+v", name, devices)
	return controller.DeviceStatus{}
}

// resource returns the spec of the resource kind/name as the API reports it, as compact JSON.
func (h *harness) resource(kind, name string) string {
	h.t.Helper()
	rs, err := h.api.Resources(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, r := range rs {
		if r.Kind == kind && r.Name == name {
			var b bytes.Buffer
			if err := json.Compact(&b, r.Spec); err != nil {
				h.t.Fatal(err)
			}
			return b.String()
		}
	}
	h.t.Fatalf("the intent has no %s %s", kind, name)
	return ""
}
