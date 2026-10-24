package intent

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// An export in YAML reads back as the same document, which applies to the same intent.
func TestDocumentYAMLReadsBack(t *testing.T) {
	d, err := ParseDocument([]byte(docJSON))
	if err != nil {
		t.Fatal(err)
	}
	in, err := Apply(New(), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	y, err := Document{Resources: in.Resources()}.YAML()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(y), []byte("{")) {
		t.Fatalf("the YAML export reads as JSON:\n%s", y)
	}
	back, err := ParseDocument(y)
	if err != nil {
		t.Fatalf("the YAML export does not read back: %v\n%s", err, y)
	}
	again, err := Apply(New(), back, nil)
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, again); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent of the YAML export differs: put %+v, gone %+v\n%s", put, gone, y)
	}
}

// Replace makes a document the whole intent: the resources it leaves out are deleted, and a VRF
// keeps the id and the ULA that the document leaves out and takes the ones it declares.
func TestReplace(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindController, "c1", `{"address": "192.0.2.1:443", "publicKey": "`+key1+`"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Replace(in, doc(
		res(KindVRF, "corp", `{}`),
		res(KindVRF, "lab", `{"ula": "fd12:3456:789c:0::/48", "mtu": 1400}`),
		res(KindVRF, "new", `{"ula": "fd12:3456:789d::/48"}`),
	), bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := next.VRFs["corp"], (VRF{ID: 10, ULA: "fd12:3456:789a::/48", MTU: DefaultMTU}); !reflect.DeepEqual(got, want) {
		t.Errorf("corp, imported without its id and ULA, is %+v, want %+v", got, want)
	}
	if got, want := next.VRFs["lab"], (VRF{ID: 20, ULA: "fd12:3456:789c::/48", MTU: 1400}); !reflect.DeepEqual(got, want) {
		t.Errorf("lab, imported with another ULA, is %+v, want %+v", got, want)
	}
	if got, want := next.VRFs["new"], (VRF{ID: 1, ULA: "fd12:3456:789d::/48", MTU: DefaultMTU}); !reflect.DeepEqual(got, want) {
		t.Errorf("new, a VRF the intent did not hold, is %+v, want %+v", got, want)
	}
	if len(next.VRFs) != 3 || len(next.Networks) != 0 || len(next.Nodes) != 0 || len(next.Controllers) != 0 {
		t.Errorf("the import left %v", next.Resources())
	}
	if len(in.Networks) != 1 || len(in.Nodes) != 1 || in.VRFs["lab"].ULA != "fd12:3456:789b::/48" {
		t.Error("Replace changed the intent it was given")
	}

	// A document whose Network names a VRF that only the intent before holds is refused, and
	// the intent stays.
	same, err := Replace(in, doc(res(KindNetwork, "lan", `{"vrf": "corp"}`)), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Network "lan": VRF "corp" does not exist`) {
		t.Errorf("an import of a Network without its VRF: %v", err)
	}
	if put, gone := Changed(in, same); len(put) != 0 || len(gone) != 0 {
		t.Errorf("a refused import changed the intent: put %+v, gone %+v", put, gone)
	}
}
