package desired

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The decoy of a Listener reaches the Listener of the NodeConfig of its node, and a Listener that names
// none sends none (AUD1-DT-4 #452).
func TestCompileListenerDecoy(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindListener, "edge-a", `{"node": "a", "decoy": "127.0.0.1:8080", "certificate": {"file": "C:\\ranz\\a.pfx"}}`),
		res(intent.KindListener, "edge-b", `{"node": "b", "certificate": {"file": "C:\\ranz\\b.pfx"}}`),
	}
	states := compile(t, rs...)
	for node, want := range map[string]string{"a": "127.0.0.1:8080", "b": ""} {
		n := states[node][Key{controlpb.Kind_KIND_NODE, node}].GetNode()
		if n.GetListener() == nil || n.GetListenerDecoy() != want {
			t.Errorf("the NodeConfig of %s has the Listener %v and the decoy %q, want the decoy %q", node, n.GetListener(), n.GetListenerDecoy(), want)
		}
	}
}
