package intent

import (
	"strings"
	"testing"
)

// The tag mode of a Network (SDN-87): in lower case, off when it names none, which its resource leaves out;
// the tag mode of a VRF is that of its Networks; and a Network in trusted-underlay of a VRF with a plain link
// is marked "tags not authenticated", one of a VRF of kind noise and one in off are not.
func TestApplyTagModes(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`),
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve"}`),
		res(KindNetwork, "dc-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24", "tagMode": "Trusted-Underlay"}`),
		res(KindNetwork, "dc-mgmt", `{"vrf": "dc", "ipv4Pool": "10.31.0.0/24", "tagMode": "trusted-underlay"}`),
		res(KindNetwork, "corp-net", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "tagMode": "trusted-underlay"}`),
		res(KindNetwork, "lab-net", `{"vrf": "lab", "ipv4Pool": "10.40.0.0/24"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc", "lab"], "vtep": {"address": "10.1.0.1"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Networks["dc-net"].TagMode; got != TagModeTrustedUnderlay {
		t.Errorf("Network dc-net has the tagMode %q, want %q", got, TagModeTrustedUnderlay)
	}
	for vrf, want := range map[string]string{"dc": TagModeTrustedUnderlay, "corp": TagModeTrustedUnderlay, "lab": TagModeOff, "none": TagModeOff} {
		if got := in.VRFTagMode(vrf); got != want {
			t.Errorf("VRF %s has the tag mode %q, want %q", vrf, got, want)
		}
	}
	for network, want := range map[string]string{"dc-net": TagsNotAuthenticated, "dc-mgmt": TagsNotAuthenticated, "corp-net": "", "lab-net": "", "none": ""} {
		if got := in.TagsNote(network); got != want {
			t.Errorf("Network %s is marked %q, want %q", network, got, want)
		}
	}

	rs := in.Resources()
	for _, r := range rs {
		if r.Kind == KindNetwork && r.Name == "lab-net" && strings.Contains(string(r.Spec), "tagMode") {
			t.Errorf("the resource of Network lab-net, which names no tagMode, is %s", r.Spec)
		}
		if r.Kind == KindNetwork && r.Name == "dc-net" && !strings.Contains(string(r.Spec), `"tagMode":"trusted-underlay"`) {
			t.Errorf("the resource of Network dc-net is %s", r.Spec)
		}
	}
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || again.Networks["dc-net"].TagMode != TagModeTrustedUnderlay || again.Networks["lab-net"].TagMode != "" {
		t.Errorf("the resources applied again: %v, Network dc-net %+v, Network lab-net %+v", err, again.Networks["dc-net"], again.Networks["lab-net"])
	}
}

// A tag mode is refused with the Network and the reason: a mode that is neither off nor trusted-underlay
// (hmac comes with SDN-88), and two Networks of one VRF with two modes.
func TestApplyTagModesRejects(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want string
	}{
		{`"tagMode": "hmac"`, ``, `Network "a-net": the tagMode must be off or trusted-underlay, not "hmac"`},
		{`"tagMode": "on"`, ``, `Network "a-net": the tagMode must be off or trusted-underlay, not "on"`},
		{`"tagMode": "trusted-underlay"`, `"tagMode": "off"`, `Network "b-net": the tagMode is off, and Network "a-net" of the same VRF "dc" has trusted-underlay`},
		{``, `"tagMode": "trusted-underlay"`, `Network "b-net": the tagMode is trusted-underlay, and Network "a-net" of the same VRF "dc" has off`},
	} {
		_, err := Apply(New(), doc(
			res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`),
			res(KindNetwork, "a-net", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"`+linkField(c.a)+`}`),
			res(KindNetwork, "b-net", `{"vrf": "dc", "ipv4Pool": "10.31.0.0/24"`+linkField(c.b)+`}`),
		), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Network a-net {%s}, Network b-net {%s}: the error is %v, want one with %q", c.a, c.b, err, c.want)
		}
	}
}
