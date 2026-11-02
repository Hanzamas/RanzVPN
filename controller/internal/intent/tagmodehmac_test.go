package intent

import (
	"strings"
	"testing"
)

// The tag mode hmac (SDN-88): a Network of a VRF whose link is geneve or noise takes it, in any case, and
// keeps it in its resource; the VRF has the mode of its Networks; and its tags are authenticated, so
// `ranz explain` does not mark the Network "tags not authenticated".
func TestApplyTagModeHMAC(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve"}`),
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.40.0.0/24", "tagMode": "HMAC"}`),
		res(KindNetwork, "corp-net", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "tagMode": "hmac"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["lab", "corp"], "vtep": {"address": "10.1.0.1"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for vrf, want := range map[string]string{"lab": TagModeHMAC, "corp": TagModeHMAC} {
		if got := in.VRFTagMode(vrf); got != want {
			t.Errorf("VRF %s has the tag mode %q, want %q", vrf, got, want)
		}
	}
	for _, network := range []string{"lab-net", "corp-net"} {
		if got := in.TagsNote(network); got != "" {
			t.Errorf("Network %s in the tag mode hmac is marked %q, want no mark: its tags are authenticated", network, got)
		}
	}
	found := false
	for _, r := range in.Resources() {
		if r.Kind == KindNetwork && r.Name == "lab-net" {
			found = strings.Contains(string(r.Spec), `"tagMode":"hmac"`)
		}
	}
	if !found {
		t.Errorf("the resource of Network lab-net does not hold the tagMode hmac in its one form")
	}
}

// VRFTagModes gives each VRF of the intent the tag mode that VRFTagMode gives it, in one pass over the
// Networks: the mode of its Networks, and off for a VRF without a Network.
func TestVRFTagModes(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve"}`),
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.40.0.0/24", "tagMode": "hmac"}`),
		res(KindNetwork, "corp-net", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["lab", "corp"], "vtep": {"address": "10.1.0.1"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.VRFs["spare"] = VRF{ID: 50}
	modes := in.VRFTagModes()
	for vrf := range in.VRFs {
		if got, want := modes[vrf], in.VRFTagMode(vrf); got != want {
			t.Errorf("VRFTagModes gives VRF %s the tag mode %q, and VRFTagMode %q", vrf, got, want)
		}
	}
	for vrf, want := range map[string]string{"lab": TagModeHMAC, "corp": TagModeOff, "spare": TagModeOff} {
		if got := modes[vrf]; got != want {
			t.Errorf("VRF %s has the tag mode %q, want %q", vrf, got, want)
		}
	}
}
