package explain

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// quantumScenario is two Nodes that share VRF corp, whose link is of kind noise, and VRF dc, whose link is of kind vxlan.
func quantumScenario(t *testing.T) Scenario {
	return Scenario{Name: "quantum", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}, Intent: document(t, `{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "vxlan", "vni": 3000}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}},
		{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["corp", "dc"], "addresses": {"corp-lan": "10.10.0.1", "dc-lan": "10.30.0.1"}, "vtep": {"address": "192.0.2.1"}}},
		{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["corp", "dc"], "addresses": {"corp-lan": "10.10.0.2", "dc-lan": "10.30.0.2"}, "vtep": {"address": "192.0.2.2"}}},
		{"kind": "Policy", "name": "corp-all", "spec": {"vrf": "corp", "action": "allow"}},
		{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}}
	]}`)}
}

// ranz explain shows for each link of kind noise whether its session is quantum-resistant (CORE-P2-5, #382): the outer
// QUIC or TLS-443 session of two Nodes that both report the Capability pqTls negotiates X25519MLKEM768; when either does
// not, or reported no Capabilities, it falls back to X25519, not quantum-resistant, and explain names the Node that does
// not report it. The key exchange changes no verdict, and a link of kind vxlan, which encrypts nothing, has none.
func TestLinkShowsWhetherItsSessionIsQuantumResistant(t *testing.T) {
	in, states, err := quantumScenario(t).Compile()
	if err != nil {
		t.Fatal(err)
	}
	pq := &controlpb.Capabilities{PqTls: true}
	classical := &controlpb.Capabilities{Architecture: controlpb.Architecture_ARCHITECTURE_X64}
	for _, c := range []struct {
		what      string
		caps      map[string]*controlpb.Capabilities
		resistant bool
		without   []string
		text      string
	}{
		{"both report pqTls", map[string]*controlpb.Capabilities{"dc-1": pq, "dc-2": pq}, true, nil,
			"encrypted; its QUIC or TLS-443 session negotiates X25519MLKEM768, quantum-resistant, as dc-1 and dc-2 both report pqTls"},
		{"the peer does not", map[string]*controlpb.Capabilities{"dc-1": pq, "dc-2": classical}, false, []string{"dc-2"},
			"encrypted; its QUIC or TLS-443 session negotiates X25519, not quantum-resistant, as dc-2 does not report pqTls"},
		{"the sender reported none", map[string]*controlpb.Capabilities{"dc-2": pq}, false, []string{"dc-1"},
			"encrypted; its QUIC or TLS-443 session negotiates X25519, not quantum-resistant, as dc-1 does not report pqTls"},
		{"no Node reported any", nil, false, []string{"dc-1", "dc-2"},
			"encrypted; its QUIC or TLS-443 session negotiates X25519, not quantum-resistant, as dc-1 and dc-2 do not report pqTls"},
	} {
		t.Run(c.what, func(t *testing.T) {
			r, err := New(in, states).WithCapabilities(c.caps).Explain(Query{From: "dc-1", To: "dc-2", VRF: "corp", Protocol: "udp", SourcePort: 40000, Port: 53})
			if err != nil {
				t.Fatal(err)
			}
			link := steps(r, StepLink)
			if len(link) != 1 || link[0].Link == nil {
				t.Fatalf("the link steps are %+v", link)
			}
			l := link[0].Link
			want := KeyExchangeX25519
			if c.resistant {
				want = KeyExchangeHybrid
			}
			if l.Kind != "noise" || !l.Encrypted || l.KeyExchange != want || l.QuantumResistant != c.resistant || !slices.Equal(l.WithoutPQTLS, c.without) {
				t.Errorf("the link is %+v, want the key exchange %s, quantum-resistant %v, without pqTls %v", l, want, c.resistant, c.without)
			}
			if !strings.Contains(link[0].Text, "the Noise session of dc-1 to dc-2 carries the packet in VRF corp, "+c.text) {
				t.Errorf("the link step says %q, want %q", link[0].Text, c.text)
			}
			if !r.Verdict.Delivered || r.Verdict.Node != "dc-2" {
				t.Errorf("the verdict is %+v", r.Verdict)
			}
		})
	}

	// The link of kind vxlan encrypts nothing: no key exchange, whatever the Nodes report
	r, err := New(in, states).WithCapabilities(map[string]*controlpb.Capabilities{"dc-1": pq, "dc-2": pq}).Explain(Query{From: "dc-1", To: "dc-2", VRF: "dc", Protocol: "udp", SourcePort: 40000, Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	link := steps(r, StepLink)
	if len(link) != 1 || link[0].Link == nil {
		t.Fatalf("the link steps of VRF dc are %+v", link)
	}
	if l := link[0].Link; l.Kind != "vxlan" || l.KeyExchange != "" || l.QuantumResistant || len(l.WithoutPQTLS) != 0 || strings.Contains(link[0].Text, "quantum") {
		t.Errorf("the link of kind vxlan is %+v and says %q", l, link[0].Text)
	}
}

// The API form of the link carries the key exchange: keyExchange and quantumResistant, and the Nodes without pqTls.
func TestLinkKeyExchangeInTheAPIForm(t *testing.T) {
	b, err := json.Marshal(Link{Peer: "dc-2", Kind: "noise", Encrypted: true, KeyExchange: KeyExchangeHybrid, QuantumResistant: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"keyExchange":"X25519MLKEM768"`) || !strings.Contains(s, `"quantumResistant":true`) || strings.Contains(s, "withoutPqTls") {
		t.Errorf("the API form of a quantum-resistant link is %s", s)
	}
	b, err = json.Marshal(Link{Peer: "dc-2", Kind: "noise", Encrypted: true, KeyExchange: KeyExchangeX25519, WithoutPQTLS: []string{"dc-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"keyExchange":"X25519"`) || strings.Contains(s, "quantumResistant") || !strings.Contains(s, `"withoutPqTls":["dc-2"]`) {
		t.Errorf("the API form of a link that is not quantum-resistant is %s", s)
	}
	if got := keyExchangeText("dc-1", "dc-2", &Link{Kind: "vxlan"}); got != "" {
		t.Errorf("a link without a key exchange says %q", got)
	}
}
