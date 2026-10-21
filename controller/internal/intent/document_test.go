package intent

import (
	"bytes"
	"strings"
	"testing"
)

const docJSON = `{
  "resources": [
    {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}},
    {"kind": "Network", "name": "lan", "spec": {"vrf": "corp", "mode": "L2", "ipv4Pool": "10.0.0.0/24"}},
    {"kind": "Node", "name": "branch-1", "spec": {"publicKey": "` + key1 + `", "vrfs": ["corp"], "tags": ["branch"]}}
  ]
}`

const docYAML = `# The same intent as docJSON.
resources:
  - kind: VRF
    name: corp
    spec:
      id: 10
      ula: "fd12:3456:789a::/48"
      mtu: 1400
  - kind: Network
    name: lan
    spec:
      vrf: corp
      mode: L2
      ipv4Pool: 10.0.0.0/24
  - kind: Node
    name: branch-1
    spec:
      publicKey: ` + key1 + `
      vrfs: [corp]
      tags: [branch]
`

// The same intent in YAML and in JSON gives the same stored intent.
func TestParseDocumentYAMLAndJSON(t *testing.T) {
	fromJSON, err := ParseDocument([]byte(docJSON))
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := ParseDocument([]byte("\xef\xbb\xbf" + docYAML))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Apply(New(), fromJSON, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Apply(New(), fromYAML, nil)
	if err != nil {
		t.Fatal(err)
	}
	ra, rb := a.Resources(), b.Resources()
	if len(ra) != 3 || len(rb) != len(ra) {
		t.Fatalf("%d resources from JSON, %d from YAML, want 3 each", len(ra), len(rb))
	}
	for i := range ra {
		if ra[i].Kind != rb[i].Kind || ra[i].Name != rb[i].Name || !bytes.Equal(ra[i].Spec, rb[i].Spec) {
			t.Errorf("resource %d: JSON gives %s %s %s, YAML gives %s %s %s", i, ra[i].Kind, ra[i].Name, ra[i].Spec, rb[i].Kind, rb[i].Name, rb[i].Spec)
		}
	}
}

func TestParseDocumentRejects(t *testing.T) {
	for _, c := range []struct{ doc, want string }{
		{`{"resources": [], "extra": 1}`, `unknown field "extra"`},
		{"resources:\n  - kind: VRF\n    name: corp\n    colour: red\n", `unknown field "colour"`},
		{"resources: [\n", "YAML"},
	} {
		if _, err := ParseDocument([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: the error is %v, want one with %q", c.doc, err, c.want)
		}
	}
}
