package desired

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The policy of the VRFs reaches the nodes (SDN-8): every VRF carries its conntrack quota and its
// timeouts, every peer its tags, and a node gets as Rule objects the rules of its VRFs whose from
// or to end can be the node: web and db get the rule between them, guest, which has neither tag,
// does not; every node of corp gets no-ssh, whose from end is any; only db is in lab.
func TestCompilePolicy(t *testing.T) {
	const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	states := compile(t,
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48",
			"conntrack": {"maxFlows": 4096, "timeouts": {"tcpEstablished": 600, "tcpTransitory": 30, "udp": 20, "icmp": 5, "other": 40}}}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "web", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["web"]}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["corp", "lab"], "tags": ["linux", "db"]}`),
		res(intent.KindNode, "guest", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(intent.KindPolicy, "web-to-db", `{"vrf": "corp", "action": "allow", "priority": 100, "from": {"tags": ["web"]},
			"to": {"tags": ["db"], "addresses": ["10.1.0.0/16", "fd12::7"]}, "protocol": "tcp", "ports": [5432, "8000-8080"]}`),
		res(intent.KindPolicy, "no-ssh", `{"vrf": "corp", "action": "deny", "to": {"tags": ["linux"]}, "protocol": "tcp", "ports": [22]}`),
		res(intent.KindPolicy, "lab-all", `{"vrf": "lab", "action": "allow"}`),
	)
	for node, want := range map[string][]string{
		"web":   {"no-ssh", "web-to-db"},
		"db":    {"lab-all", "no-ssh", "web-to-db"},
		"guest": {"no-ssh"},
	} {
		var got []string
		for _, k := range states[node].keys() {
			if k.Kind == controlpb.Kind_KIND_RULE {
				got = append(got, k.Name)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("node %s gets the rules %v, want %v", node, got, want)
		}
	}

	rules := map[string]*controlpb.Rule{
		"web-to-db": {Name: "web-to-db", VrfId: 10, Priority: 100, Action: controlpb.RuleAction_RULE_ACTION_ALLOW,
			From: &controlpb.RuleEnd{Tags: []string{"web"}},
			To: &controlpb.RuleEnd{Tags: []string{"db"}, Prefixes: []*controlpb.Prefix{{Address: []byte{10, 1, 0, 0}, Length: 16},
				{Address: netip.MustParseAddr("fd12::7").AsSlice(), Length: 128}}},
			Protocol: 6, Ports: []*controlpb.PortRange{{First: 5432, Last: 5432}, {First: 8000, Last: 8080}}},
		"no-ssh": {Name: "no-ssh", VrfId: 10, Priority: intent.DefaultPriority, Action: controlpb.RuleAction_RULE_ACTION_DENY,
			To: &controlpb.RuleEnd{Tags: []string{"linux"}}, Protocol: 6, Ports: []*controlpb.PortRange{{First: 22, Last: 22}}},
		"lab-all": {Name: "lab-all", VrfId: 20, Priority: intent.DefaultPriority, Action: controlpb.RuleAction_RULE_ACTION_ALLOW},
	}
	for name, want := range rules {
		if got := states["db"][Key{controlpb.Kind_KIND_RULE, name}].GetRule(); !proto.Equal(got, want) {
			t.Errorf("rule %s is\n%v\nwant\n%v", name, got, want)
		}
	}

	corp := states["web"][Key{controlpb.Kind_KIND_VRF, "corp"}].GetVrf().GetPolicy()
	want := &controlpb.VrfPolicy{MaxFlows: 4096, TcpEstablished: 600, TcpTransitory: 30, Udp: 20, Icmp: 5, Other: 40}
	if !proto.Equal(corp, want) {
		t.Errorf("VRF corp has the policy %v, want %v", corp, want)
	}
	// A VRF that declares no conntrack has its policy too, with the defaults of the node
	if lab := states["db"][Key{controlpb.Kind_KIND_VRF, "lab"}].GetVrf().GetPolicy(); lab == nil || !proto.Equal(lab, &controlpb.VrfPolicy{}) {
		t.Errorf("VRF lab has the policy %v, want an empty one", lab)
	}

	if tags := states["web"][Key{controlpb.Kind_KIND_PEER, "db"}].GetPeer().GetTags(); !slices.Equal(tags, []string{"db", "linux"}) {
		t.Errorf("the peer db of web has the tags %v, want [db linux]", tags)
	}
	if tags := states["web"][Key{controlpb.Kind_KIND_PEER, "guest"}].GetPeer().GetTags(); len(tags) != 0 {
		t.Errorf("the peer guest of web has the tags %v, want none", tags)
	}
}

// A rule changes the state of the nodes that get it, and only those: a delta carries the rule.
func TestPolicyDelta(t *testing.T) {
	base := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "web", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["web"]}`),
		res(intent.KindNode, "db", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "tags": ["db"]}`),
	}
	before := compile(t, append(base, res(intent.KindPolicy, "web-in", `{"vrf": "corp", "action": "allow", "to": {"tags": ["web"]}, "protocol": "tcp", "ports": [443]}`))...)
	after := compile(t, append(base, res(intent.KindPolicy, "web-in", `{"vrf": "corp", "action": "allow", "to": {"tags": ["web"]}, "protocol": "tcp", "ports": [443, 80]}`))...)
	u := Delta(before["web"], 1, after["web"], 2)
	if len(u.GetSet()) != 1 || u.GetSet()[0].GetRule().GetName() != "web-in" || len(u.GetRemove()) != 0 {
		t.Errorf("the delta of web is %v, want the rule web-in alone", u)
	}
	// The from end of web-in is any, so db gets it too
	if !Equal(before["db"], after["db"]) {
		u := Delta(before["db"], 1, after["db"], 2)
		if len(u.GetSet()) != 1 || u.GetSet()[0].GetRule().GetName() != "web-in" {
			t.Errorf("the delta of db is %v, want the rule web-in alone", u)
		}
	} else {
		t.Errorf("the state of db did not change with the rule web-in, whose from end is any")
	}
	gone := compile(t, base...)
	if u := Delta(after["web"], 2, gone["web"], 3); len(u.GetSet()) != 0 || len(u.GetRemove()) != 1 || u.GetRemove()[0].GetKind() != controlpb.Kind_KIND_RULE {
		t.Errorf("the delta of web without the rule is %v, want the removal of web-in", u)
	}
}
