package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// A node whose host asks for X25519MLKEM768 reports the Capability pq_tls (CORE-P2-5, #382): the API form carries it as
// pqTls both ways, and one that does not report it has no pqTls in the API at all.
func TestAPIFormPQTLS(t *testing.T) {
	p := &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64, PqTls: true}
	got := FromProto(p)
	want := Capabilities{SKU: "Server", Architecture: "x64", PQTLS: true}
	if got == nil || *got != want {
		t.Fatalf("the API form of %v is %+v, want %+v", p, got, want)
	}
	back, err := got.Proto()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(back, p) {
		t.Errorf("the API form %+v comes back as %v, not %v", got, back, p)
	}
	for _, c := range []struct {
		caps *Capabilities
		want bool
	}{{got, true}, {FromProto(&controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER}), false}} {
		b, err := json.Marshal(c.caps)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"pqTls":true`) != c.want || strings.Contains(string(b), `"pqTls":false`) {
			t.Errorf("the API form %s, want pqTls %v", b, c.want)
		}
	}
}

// No feature needs pq_tls: a session falls back to X25519 without it, so a node that does not report it is refused nothing
// that one that reports it gets (ADR-0033 decision 4).
func TestNoFeatureNeedsPQTLS(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	)
	for _, node := range []string{"gw", "laptop"} {
		with := Check(node, &controlpb.Capabilities{PqTls: true}, states[node])
		without := Check(node, &controlpb.Capabilities{}, states[node])
		if len(with) != 0 || len(without) != 0 {
			t.Errorf("%s: the problems are %v with pq_tls and %v without it, want none", node, with, without)
		}
	}
}
