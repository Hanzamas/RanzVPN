package intent

import (
	"strings"
	"testing"
)

// A VRF of kind vxlan or geneve takes its id as its VNI when it names none, a kind in capitals is in lower
// case, and the address of a tunnel endpoint is in the form of netip; the links read back from the
// resources and apply again unchanged. A VRF that names no kind is of kind noise.
func TestApplyLinks(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", "link": "VXLAN"}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve", "vni": 7040}`),
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc", "lab", "corp"], "vtep": {"address": "::ffff:10.1.0.1", "vxlanPort": 4800}}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "vtep": {"address": "2001:DB8::2"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := in.VRFs["dc"]; v.Link != LinkVXLAN || v.VNI != 30 {
		t.Errorf("VRF dc has the link %q and the VNI %d, want vxlan and 30", v.Link, v.VNI)
	}
	if v := in.VRFs["lab"]; v.Link != LinkGeneve || v.VNI != 7040 {
		t.Errorf("VRF lab has the link %q and the VNI %d, want geneve and 7040", v.Link, v.VNI)
	}
	if v := in.VRFs["corp"]; Plain(v.Link) || v.VNI != 0 {
		t.Errorf("VRF corp has the link %q and the VNI %d, want noise and none", v.Link, v.VNI)
	}
	if got := in.Nodes["a"].VTEP; got != (VTEP{Address: "10.1.0.1", VXLANPort: 4800}) || VXLANPort(got) != 4800 || GenevePort(got) != 6081 {
		t.Errorf("the vtep of Node a is %+v", got)
	}
	if got := in.Nodes["b"].VTEP; got.Address != "2001:db8::2" || VXLANPort(got) != 4789 {
		t.Errorf("the vtep of Node b is %+v", got)
	}
	if got := in.PlainVRFs(in.Nodes["a"]); strings.Join(got, ",") != "dc,lab" {
		t.Errorf("the VRFs of Node a with a plain link are %v", got)
	}

	rs := in.Resources()
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || again.VRFs["dc"] != in.VRFs["dc"] || again.Nodes["a"].VTEP != in.Nodes["a"].VTEP {
		t.Errorf("the resources applied again: %v, VRF dc %+v, the vtep of a %+v", err, again.VRFs["dc"], again.Nodes["a"].VTEP)
	}
	for _, r := range rs {
		if r.Kind == KindVRF && r.Name == "corp" && (strings.Contains(string(r.Spec), "link") || strings.Contains(string(r.Spec), "vni")) {
			t.Errorf("the resource of VRF corp, which names no link, is %s", r.Spec)
		}
	}
}

// A link is refused with the VRF or the Node and the reason: an unknown kind, a VNI of a VRF of kind
// noise, a VNI out of range or twice, a Node of a plain VRF without a tunnel endpoint, an address that is
// no address of one Node or twice, ports out of range or the same.
func TestApplyLinksRejects(t *testing.T) {
	for _, c := range []struct {
		vrfs, a, b string
		want       string
	}{
		{`"link": "ipsec"`, ``, ``, `VRF "dc": the link must be noise, vxlan or geneve, not "ipsec"`},
		{`"link": "noise", "vni": 5`, ``, ``, `VRF "dc": vni 5 needs a link of kind vxlan or geneve, and the link is noise`},
		{`"link": "vxlan", "vni": 16777216`, `"vtep": {"address": "10.1.0.1"}`, `"vtep": {"address": "10.1.0.2"}`, `VRF "dc": vni 16777216 is not from 1 to 16777215`},
		{`"link": "vxlan", "vni": 40`, `"vtep": {"address": "10.1.0.1"}`, `"vtep": {"address": "10.1.0.2"}`, `VRF "lab": vni 40 is already the vni of VRF "dc"`},
		{`"link": "geneve"`, `"vtep": {"address": "10.1.0.1"}`, ``, `Node "b": VRF "dc" has a link of kind geneve, and the Node has no vtep`},
		{`"link": "vxlan"`, `"vtep": {"address": "10.1.0.1"}`, `"vtep": {"address": "10.1.0.1"}`, `Node "b": vtep address 10.1.0.1 is already the vtep address of Node "a"`},
		{`"link": "vxlan"`, `"vtep": {"address": "dc-gw.example.com"}`, `"vtep": {"address": "10.1.0.2"}`, `Node "a": vtep address "dc-gw.example.com" is not an IP address`},
		{`"link": "vxlan"`, `"vtep": {"address": "fe80::1%eth0"}`, `"vtep": {"address": "10.1.0.2"}`, `Node "a": vtep address "fe80::1%eth0" has a zone`},
		{`"link": "vxlan"`, `"vtep": {"address": "224.0.0.5"}`, `"vtep": {"address": "10.1.0.2"}`, `Node "a": vtep address "224.0.0.5" is not the address of one Node`},
		{`"link": "vxlan"`, `"vtep": {"address": "10.1.0.1", "vxlanPort": 70000}`, `"vtep": {"address": "10.1.0.2"}`, `Node "a": the vtep ports 70000 and 0 must be from 1 to 65535`},
		{`"link": "vxlan"`, `"vtep": {"address": "10.1.0.1", "genevePort": 4789}`, `"vtep": {"address": "10.1.0.2"}`, `Node "a": the vtep has the port 4789 for both VXLAN and Geneve`},
	} {
		lab := `"link": "geneve", "vni": 40`
		_, err := Apply(New(), doc(
			res(KindVRF, "dc", `{"id": 30, "ula": "fd12:3456:789c::/48", `+c.vrfs+`}`),
			res(KindVRF, "lab", `{"id": 41, "ula": "fd12:3456:789d::/48", `+lab+`}`),
			res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["dc"]`+linkField(c.a)+`}`),
			res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["dc"]`+linkField(c.b)+`}`),
		), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("VRF dc {%s}, Node a {%s}, Node b {%s}: the error is %v, want one with %q", c.vrfs, c.a, c.b, err, c.want)
		}
	}
}

// linkField returns the field s of a spec after a comma, "" for none.
func linkField(s string) string {
	if s == "" {
		return ""
	}
	return ", " + s
}
