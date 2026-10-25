package desired

import (
	"slices"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The WireGuard Devices reach the nodes (SDN-80): every node of the VRF of a Device gets it with its
// addresses and tags, its gateway with its key too and the port of its WireGuard interface, and a
// node of another VRF does not get it. The gateway gets the rules that name the tags of its Devices,
// and a node that is the gateway of no Device has no port.
func TestCompileDevices(t *testing.T) {
	const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	const phoneKey = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="
	states := compile(t,
		res(intent.KindVRF, "lab", `{"id": 7, "ula": "fd07:7:7::/48"}`),
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net", "port": 51999}}`),
		res(intent.KindNode, "host", `{"publicKey": "`+key2+`", "vrfs": ["lab"], "tags": ["servers"]}`),
		res(intent.KindNode, "other", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(intent.KindDevice, "phone", `{"network": "lab-net", "gateway": "gw", "publicKey": "`+phoneKey+`", "tags": ["phones"]}`),
		res(intent.KindPolicy, "phones-to-phones", `{"vrf": "lab", "action": "allow", "from": {"tags": ["phones"]}, "to": {"tags": ["phones"]}}`),
	)
	key := Key{controlpb.Kind_KIND_DEVICE, "phone"}
	gw, host := states["gw"][key].GetDevice(), states["host"][key].GetDevice()
	if gw == nil || host == nil {
		t.Fatalf("gw has the Device %v and host %v, want both to have it", gw, host)
	}
	if _, ok := states["other"][key]; ok {
		t.Error("node other, of another VRF, has Device phone")
	}
	if len(gw.GetPublicKey()) != intent.KeySize || len(host.GetPublicKey()) != 0 {
		t.Errorf("the key of Device phone is %x at gw and %x at host, want it at its gateway gw only", gw.GetPublicKey(), host.GetPublicKey())
	}
	if text := addressText(host.GetAddresses()); host.GetVrfId() != 7 || host.GetGateway() != "gw" || !slices.Equal(host.GetTags(), []string{"phones"}) ||
		text != "lab-net 7 10.70.0.3/32, lab-net 7 fd07:7:7:1::3/128" {
		t.Errorf("Device phone at host is %v (addresses %s)", host, text)
	}
	if port := states["gw"][Key{controlpb.Kind_KIND_NODE, "gw"}].GetNode().GetWireguardPort(); port != 51999 {
		t.Errorf("the WireGuard port of gw is %d, want 51999", port)
	}
	if port := states["host"][Key{controlpb.Kind_KIND_NODE, "host"}].GetNode().GetWireguardPort(); port != 0 {
		t.Errorf("host, the gateway of no Device, has the WireGuard port %d", port)
	}
	rule := Key{controlpb.Kind_KIND_RULE, "phones-to-phones"}
	if _, ok := states["gw"][rule]; !ok {
		t.Error("gw, the gateway of Device phone, does not get the rule between the phones")
	}
	if _, ok := states["host"][rule]; ok {
		t.Error("host, which neither tag names, gets the rule between the phones")
	}
}
