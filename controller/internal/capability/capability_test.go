package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const (
	key1 = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	key2 = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="
)

// A Windows Server gateway that has every Capability, and an arm64 Home laptop that has none of
// the optional ones.
var (
	server = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_SERVER, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
		HyperV: true, Lbfo: true, Selow: true, Xdp: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_RRAS_NAT}
	armHome = &controlpb.Capabilities{Sku: controlpb.Sku_SKU_HOME, Architecture: controlpb.Architecture_ARCHITECTURE_ARM64,
		EgressTier: controlpb.EgressTier_EGRESS_TIER_PROXY}
)

func compile(t *testing.T, rs ...intent.Resource) map[string]desired.State {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := desired.Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func res(kind, name, spec string) intent.Resource {
	return intent.Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
}

// Every core feature that the intent holds (VRFs, L3 Networks with their pools, tags and the
// peers of a full mesh) needs no Capability: a node that reports none at all gets it.
func TestCoreFeaturesNeedNoCapability(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": 1400}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNetwork, "corp-lan", `{"vrf": "corp", "mode": "L3", "ipv4Pool": "10.10.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(intent.KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.20.0.0/24"}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp", "lab"], "tags": ["branch", "laptop"]}`),
		res(intent.KindNode, "gw", `{"publicKey": "`+key1+`", "vrfs": ["corp", "lab"]}`),
	)
	for _, caps := range []*controlpb.Capabilities{nil, {}, armHome, server} {
		for name, s := range states {
			if problems := Check(name, caps, s); len(problems) > 0 {
				t.Errorf("node %s with the Capabilities %v: a core feature was refused: %v", name, caps, problems)
			}
		}
	}
	for _, s := range states {
		for _, o := range s.Objects() {
			for i, r := range requirements {
				if f := r.feature(o); f != "" {
					t.Errorf("requirement %d (%s) holds the core object %v as the feature %s", i, r.capability, o, f)
				}
			}
		}
	}
}

// An L2 Network needs XDP or SeLow on the node; the problem names the node and the Capability.
func TestL2NetworkNeedsAnL2Backend(t *testing.T) {
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNetwork, "corp-dmz", `{"vrf": "corp", "mode": "L2"}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	)
	s := states["laptop"]
	problems := Check("laptop", armHome, s)
	want := `Node "laptop" (Home, arm64): L2 Network "corp-dmz" needs XDP or SeLow, which the node does not report`
	if len(problems) != 1 || problems[0].Error() != want {
		t.Errorf("the problems are %v, want [%s]", problems, want)
	}
	if problems := Check("laptop", nil, s); len(problems) != 1 || !strings.HasPrefix(problems[0].Error(), `Node "laptop": L2 Network "corp-dmz" needs XDP or SeLow`) {
		t.Errorf("a node that reports nothing: the problems are %v", problems)
	}
	for _, caps := range []*controlpb.Capabilities{
		server,
		{Architecture: controlpb.Architecture_ARCHITECTURE_X64, Selow: true},
		{Architecture: controlpb.Architecture_ARCHITECTURE_X64, Xdp: true},
	} {
		if problems := Check("laptop", caps, s); len(problems) > 0 {
			t.Errorf("a node with %v was refused: %v", caps, problems)
		}
	}
}

// The API form and the protocol form of the Capabilities carry the same facts.
func TestAPIForm(t *testing.T) {
	got := FromProto(server)
	want := Capabilities{SKU: "Server", Architecture: "x64", HyperV: true, LBFO: true, SeLow: true, XDP: true, EgressTier: 1}
	if got == nil || *got != want {
		t.Fatalf("the API form of %v is %+v, want %+v", server, got, want)
	}
	back, err := got.Proto()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(back, server) {
		t.Errorf("the API form %+v comes back as %v, not %v", got, back, server)
	}
	if FromProto(nil) != nil {
		t.Error("no Capabilities have an API form")
	}
	if c := FromProto(&controlpb.Capabilities{}); c == nil || *c != (Capabilities{}) {
		t.Errorf("empty Capabilities have the API form %+v", c)
	}
	for _, c := range []Capabilities{{SKU: "Datacenter"}, {Architecture: "x86"}, {EgressTier: 4}} {
		if _, err := c.Proto(); err == nil {
			t.Errorf("%+v has a protocol form", c)
		}
	}
}
