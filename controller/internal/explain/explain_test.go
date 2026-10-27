package explain

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// scenarioDir is tests/explain at the root of the repository: the scenarios of the explain conformance.
const scenarioDir = "../../../tests/explain"

// loadScenarios returns the scenarios of the directory dir, at least one.
func loadScenarios(t *testing.T, dir string) []Scenario {
	t.Helper()
	files, err := ScenarioFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("%s holds no scenario", dir)
	}
	var out []Scenario
	for _, f := range files {
		s, err := LoadScenario(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// scenario returns the scenario name of tests/explain, or of tests/explain/broken.
func scenario(t *testing.T, name string) Scenario {
	t.Helper()
	path := filepath.Join(scenarioDir, name+".json")
	if strings.HasPrefix(name, "broken/") {
		path = filepath.Join(scenarioDir, "broken", strings.TrimPrefix(name, "broken/")+".json")
	}
	s, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// model returns the model of the scenario s and what explain says of each of its packets.
func model(t *testing.T, s Scenario) (*Model, []Result) {
	t.Helper()
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	m := New(in, states)
	results, err := s.Explain(m)
	if err != nil {
		t.Fatal(err)
	}
	return m, results
}

// result returns the Result of the packet name of s.
func result(t *testing.T, s Scenario, results []Result, name string) Result {
	t.Helper()
	for i, p := range s.Packets {
		if p.Name == name {
			return results[i]
		}
	}
	t.Fatalf("scenario %s has no packet %s", s.Name, name)
	return Result{}
}

// steps returns the steps of r of the kind.
func steps(r Result, kind string) []Step {
	var out []Step
	for _, s := range r.Steps {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

// Every scenario of tests/explain, the broken one too, explains each of its packets as the scenario says: where it
// ends and the rule that judged it at each Node (ADR-0031 decision 8, the explain half of the suite). The fault of the
// broken scenario changes the verdict of the packets that it names and of no other.
func TestScenarios(t *testing.T) {
	all := append(loadScenarios(t, scenarioDir), loadScenarios(t, filepath.Join(scenarioDir, "broken"))...)
	broken := 0
	for _, s := range all {
		t.Run(s.Name, func(t *testing.T) {
			if err := s.Check(); err != nil {
				t.Error(err)
			}
		})
		if s.Fault != nil {
			broken++
		}
	}
	if broken == 0 {
		t.Error("no scenario of tests/explain/broken has a fault")
	}
}

// A scenario whose verdict explain does not give fails its check with a message that names the packet and what
// differs, and so does one whose fault names packets that it does not break, or one whose packets are one flow.
func TestCheckFails(t *testing.T) {
	s := scenario(t, "policy")
	s.Packets = slices.Clone(s.Packets)
	s.Packets[0].Expect.Rules = map[string]string{"web-1": "web-to-app", "app-1": "ops-ssh"}
	err := s.Check()
	if err == nil || !strings.Contains(err.Error(), "packet web-to-app") || !strings.Contains(err.Error(), "app-1=ops-ssh") {
		t.Errorf("a scenario that names the wrong rule: %v", err)
	}

	s = scenario(t, "policy")
	s.Packets = slices.Clone(s.Packets)
	s.Packets[1].Expect = Expect{Delivered: true, Node: "db-1"}
	if err := s.Check(); err == nil || !strings.Contains(err.Error(), "explain: dropped by web-1, the scenario: delivered to db-1") {
		t.Errorf("a scenario that delivers what explain drops: %v", err)
	}

	s = scenario(t, "policy")
	s.Packets = append(slices.Clone(s.Packets), s.Packets[0])
	s.Packets[len(s.Packets)-1].Name = "again"
	if err := s.Check(); err == nil || !strings.Contains(err.Error(), "it is of the flow of packet web-to-app") {
		t.Errorf("a scenario with one flow twice: %v", err)
	}

	s = scenario(t, "broken/policy-drift")
	s.Fault = &Fault{Node: "a-1", DropRule: "no-telnet", Breaks: []string{"web"}}
	if err := s.Check(); err == nil || !strings.Contains(err.Error(), "the fault changes the verdicts of the packets [telnet]") {
		t.Errorf("a fault that names the wrong packets: %v", err)
	}
	s.Fault = &Fault{Node: "a-1", DropRule: "no-such-rule", Breaks: []string{"telnet"}}
	if err := s.Check(); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Errorf("a fault that drops a rule that the Node does not hold: %v", err)
	}
}

// The steps of a leaked route name the VRF that leaks it and the route targets, and the policy of the VRF that the
// packet goes into judges it with the sender as the end outside the VRF.
func TestLeakSteps(t *testing.T) {
	s := scenario(t, "leak")
	_, results := model(t, s)
	r := result(t, s, results, "shared-to-red-dns")
	routes := steps(r, StepRoute)
	if len(routes) != 3 {
		t.Fatalf("the route steps are %+v, want the route of node-s, the source back at node-r and the destination at node-r", routes)
	}
	first := routes[0].Route
	if first.Next != "node-r" || first.Leaked != "red" || !slices.Equal(first.RouteTargets, []string{"64512:1"}) || first.Prefix != netip.MustParsePrefix("10.1.0.1/32") {
		t.Errorf("the route of node-s is %+v, want 10.1.0.1/32 to node-r, leaked from red by 64512:1", first)
	}
	if !strings.Contains(routes[0].Text, "leaks into VRF shared through the route targets 64512:1") {
		t.Errorf("the route step says %q", routes[0].Text)
	}
	if back := routes[1]; back.Node != "node-r" || back.VRF != "red" || back.Route.Next != "node-s" {
		t.Errorf("the route back at node-r is %+v", back)
	}
	pol := steps(r, StepPolicy)
	if len(pol) != 2 || !pol[0].Rule.Out || pol[1].Rule.Out || !strings.Contains(pol[1].Text, "the end outside the VRF, which node-s is to it") {
		t.Errorf("the policy steps are %+v", pol)
	}
	if link := steps(r, StepLink); len(link) != 1 || link[0].Link.Kind != "noise" || !link[0].Link.Encrypted || link[0].VRF != "red" {
		t.Errorf("the link step is %+v, want the Noise session in VRF red", link)
	}

	// blue leaks into shared and imports nothing: node-b cannot route the source back
	r = result(t, s, results, "shared-to-blue")
	if r.Verdict.Node != "node-b" || r.Verdict.Reason != DropRoute || !strings.Contains(r.Verdict.Text, "does not route the source 10.100.0.1 back to node-s") {
		t.Errorf("the verdict of shared-to-blue is %+v", r.Verdict)
	}
}

// The steps of 1:1 NAT name the NAT resource and the address that it rewrites, on the way out of a host and on the
// way in to one, and the verdict gives the addresses as the host sees them.
func TestNATSteps(t *testing.T) {
	s := scenario(t, "leak-nat")
	_, results := model(t, s)
	r := result(t, s, results, "blue-to-red-web")
	nats := steps(r, StepNAT)
	if len(nats) != 2 {
		t.Fatalf("the NAT steps are %+v, want blue-1-out at blue-1 and red-1-out at red-1", nats)
	}
	out, in := nats[0], nats[1]
	if out.Node != "blue-1" || out.NAT.Name != "blue-1-out" || out.NAT.From != netip.MustParseAddr("10.0.0.1") || out.NAT.To != netip.MustParseAddr("172.16.2.1") {
		t.Errorf("the NAT step out of blue-1 is %+v", out)
	}
	if in.Node != "red-1" || in.NAT.Name != "red-1-out" || in.NAT.From != netip.MustParseAddr("172.16.1.1") || in.NAT.To != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("the NAT step in to red-1 is %+v", in)
	}
	if !strings.Contains(out.Text, "the host's 10.0.0.1 is 172.16.2.1 in the VRF") || !strings.Contains(in.Text, "172.16.1.1 of the VRF is 10.0.0.1 for the host") {
		t.Errorf("the NAT steps say %q and %q", out.Text, in.Text)
	}

	// A Node named as the destination is the address that the VRF of the sender leads to it: the outside of its rule
	r = result(t, s, results, "red-to-blue-dns")
	if r.Packet.Destination != netip.MustParseAddr("172.16.2.1") || r.Packet.Source != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("red-1 to blue-1 is the packet %+v, want 10.0.0.1 > 172.16.2.1", r.Packet)
	}

	// An address of the LAN behind a Node, the inside of its rule, sends from that Node
	n := scenario(t, "nat")
	_, results = model(t, n)
	r = result(t, n, results, "lan-to-pc-syslog")
	if r.Packet.Node != "gw-1" || r.Packet.VRF != "corp" || len(steps(r, StepNAT)) != 1 || steps(r, StepNAT)[0].NAT.Name != "lan-1" {
		t.Errorf("the packet of 192.168.1.7 is %+v with the steps %+v", r.Packet, r.Steps)
	}
}

// ranz explain shows the endpoints of the two Nodes of a link (SDN-93, #410): where the sender dials the next Node, in
// the order of the race, and that a Node without endpoints is dialled by no peer.
func TestLinkShowsEndpoints(t *testing.T) {
	s := scenario(t, "policy")
	_, results := model(t, s)
	link := steps(result(t, s, results, "web-to-app"), StepLink)
	if len(link) != 1 {
		t.Fatalf("the link steps are %+v", link)
	}
	l := link[0].Link
	want := []Endpoint{{"quic", "203.0.113.10:443"}, {"tls", "203.0.113.10:443"}}
	if l.Peer != "app-1" || len(l.Endpoints) != 0 || !slices.Equal(l.SourceEndpoints, want) {
		t.Errorf("the link of web-1 to app-1 is %+v, want app-1 without endpoints and web-1 with %v", l, want)
	}
	if !strings.Contains(link[0].Text, "app-1 has no endpoints, so no peer dials it; web-1 is dialled at quic 203.0.113.10:443, tls 203.0.113.10:443") {
		t.Errorf("the link step says %q", link[0].Text)
	}
	link = steps(result(t, s, results, "ping"), StepLink)
	if len(link) != 1 || !slices.Equal(link[0].Link.Endpoints, want) || !strings.Contains(link[0].Text, "web-1 is dialled at quic 203.0.113.10:443, tls 203.0.113.10:443") {
		t.Errorf("the link of db-1 to web-1 is %+v", link)
	}
}

// ranz explain says that a link of kind vxlan or geneve is unencrypted (SDN-76, #356): the Noise session does not
// carry it, and its packets go plain to the tunnel endpoint of the peer.
func TestPlainLinkIsUnencrypted(t *testing.T) {
	for _, kind := range []string{"vxlan", "geneve"} {
		t.Run(kind, func(t *testing.T) {
			s := Scenario{Name: "links", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}, Intent: document(t, `{"resources": [
				{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "`+kind+`", "vni": 3000}},
				{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}},
				{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["dc"], "addresses": {"dc-lan": "10.30.0.1"}, "vtep": {"address": "192.0.2.1"}}},
				{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["dc"], "addresses": {"dc-lan": "10.30.0.2"}, "vtep": {"address": "192.0.2.2"}}},
				{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}}
			]}`)}
			m, _ := model(t, s)
			r, err := m.Explain(Query{From: "dc-1", To: "dc-2", Protocol: "udp", SourcePort: 40000, Port: 4789})
			if err != nil {
				t.Fatal(err)
			}
			link := steps(r, StepLink)
			if len(link) != 1 || link[0].Link.Kind != kind || link[0].Link.Encrypted || link[0].Link.VNI != 3000 {
				t.Fatalf("the link steps are %+v, want one of kind %s, unencrypted, on VNI 3000", link, kind)
			}
			if !strings.Contains(link[0].Text, "unencrypted, plain on a network that the operator trusts") {
				t.Errorf("the link step says %q", link[0].Text)
			}
			if !r.Verdict.Delivered || r.Verdict.Node != "dc-2" {
				t.Errorf("the verdict is %+v", r.Verdict)
			}
		})
	}
}

// A WireGuard Device is the end of a flow of its own: its addresses lead to its gateway, a packet of the Device leaves
// the gateway as a packet of its host, and the rules match the tags of the Device at both ends.
func TestDevice(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(ScenarioKey(200))
	s := Scenario{Name: "device", Nodes: map[string]uint8{"gw-1": 1, "pc-1": 33}, Intent: document(t, `{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "gw-1", "spec": {"vrfs": ["corp"], "tags": ["gateway"], "addresses": {"corp-lan": "10.10.0.1"}, "wireguard": {"endpoint": "gw-1.example.com", "port": 51820}}},
		{"kind": "Node", "name": "pc-1", "spec": {"vrfs": ["corp"], "tags": ["pc"], "addresses": {"corp-lan": "10.10.0.2"}}},
		{"kind": "Device", "name": "phone", "spec": {"network": "corp-lan", "gateway": "gw-1", "publicKey": "`+key+`", "tags": ["phone"], "address": "10.10.0.50"}},
		{"kind": "Policy", "name": "phone-to-pc", "spec": {"vrf": "corp", "action": "allow", "from": {"tags": ["phone"]}, "to": {"tags": ["pc"]}, "protocol": "tcp", "ports": [22]}}
	]}`)}
	m, _ := model(t, s)
	r, err := m.Explain(Query{From: "phone", To: "pc-1", Protocol: "tcp", SourcePort: 40000, Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if r.Packet.Node != "gw-1" || r.Packet.Source != netip.MustParseAddr("10.10.0.50") || !r.Verdict.Delivered || r.Verdict.Node != "pc-1" {
		t.Fatalf("the packet of the phone is %+v and ends %+v", r.Packet, r.Verdict)
	}
	if got := r.Rules(); got["gw-1"] != "phone-to-pc" || got["pc-1"] != "phone-to-pc" {
		t.Errorf("the rules are %v, want phone-to-pc at both ends", got)
	}
	// The gateway itself is no Device: its host has the tag gateway, which the rule does not name
	r, err = m.Explain(Query{From: "gw-1", To: "pc-1", Protocol: "tcp", SourcePort: 40001, Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict.Delivered || r.Verdict.Node != "gw-1" || r.Rules()["gw-1"] != DefaultDeny {
		t.Errorf("the packet of gw-1 ends %+v with the rules %v", r.Verdict, r.Rules())
	}
	// pc-1 reaches the phone at the address of the Device, through its gateway
	r, err = m.Explain(Query{From: "pc-1", To: "phone", Protocol: "tcp", SourcePort: 40002, Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if r.Packet.Destination != netip.MustParseAddr("10.10.0.50") || steps(r, StepRoute)[0].Route.Next != "gw-1" {
		t.Errorf("pc-1 to the phone is %+v with the steps %+v", r.Packet, r.Steps)
	}
}

// A query that names nothing that the model knows, or that cannot be one packet, is refused with a message that says
// why; an address that two Nodes hold needs the VRF.
func TestQueryErrors(t *testing.T) {
	s := scenario(t, "leak-nat")
	m, _ := model(t, s)
	for _, c := range []struct {
		q    Query
		want error
		text string
	}{
		{Query{From: "nowhere", To: "red-1"}, intent.ErrNotFound, `"nowhere" is no Node, Device or IP address`},
		{Query{From: "red-1", To: "nowhere"}, intent.ErrNotFound, `"nowhere" is no Node, Device or IP address`},
		{Query{From: "red-1", To: "red-1"}, intent.ErrInvalid, "sends the packet itself"},
		{Query{From: "red-1", To: "blue-1", VRF: "blue"}, intent.ErrInvalid, `Node "red-1" is not a member of VRF "blue"`},
		{Query{From: "red-1", To: "blue-1", VRF: "green"}, intent.ErrNotFound, `VRF "green"`},
		{Query{From: "red-1", To: "blue-1", Protocol: "gre"}, intent.ErrInvalid, "neither tcp, udp nor icmp"},
		{Query{From: "10.0.0.1", To: "172.16.1.1"}, intent.ErrInvalid, "the Nodes blue-1, red-1 hold the address 10.0.0.1: name the VRF"},
		{Query{From: "10.9.9.9", To: "172.16.1.1"}, intent.ErrNotFound, "no Node holds the address 10.9.9.9"},
		{Query{From: "red-1", To: "fd00:1::9"}, intent.ErrInvalid, "has no IPv6 address in VRF red"},
	} {
		_, err := m.Explain(c.q)
		if !errors.Is(err, c.want) || err == nil || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%+v: %v, want %v with %q", c.q, err, c.want, c.text)
		}
	}

	// With the VRF, the address is the one of blue-1
	r, err := m.Explain(Query{From: "10.0.0.1", To: "172.16.1.1", VRF: "blue", Protocol: "tcp", SourcePort: 40000, Port: 80})
	if err != nil || r.Packet.Node != "blue-1" || !r.Verdict.Delivered {
		t.Errorf("10.0.0.1 in VRF blue: %+v, %v", r, err)
	}

	// A Node of the intent that has no state, as above the node cap of a licence
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	delete(states, "blue-1")
	_, err = New(in, states).Explain(Query{From: "blue-1", To: "red-1"})
	if !errors.Is(err, intent.ErrInvalid) || !strings.Contains(err.Error(), "has no desired state") {
		t.Errorf("a Node without a state: %v", err)
	}
}

// The packets that a Node does not take: from an address that is not its own, to its own address, and to an address
// that no route holds.
func TestDropsAtTheSender(t *testing.T) {
	s := scenario(t, "policy")
	m, _ := model(t, s)
	for _, c := range []struct {
		q    Query
		text string
	}{
		{Query{From: "web-1", To: "10.99.0.1", Protocol: "udp", Port: 53}, "no route of VRF corp at web-1 holds 10.99.0.1"},
		{Query{From: "web-1", To: "10.10.0.10", Protocol: "udp", Port: 53}, "10.10.0.10 is an address of web-1 itself"},
	} {
		r, err := m.Explain(c.q)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict.Delivered || r.Verdict.Node != "web-1" || r.Verdict.Reason != DropRoute || !strings.Contains(r.Verdict.Text, c.text) {
			t.Errorf("%+v ends %+v, want a drop by web-1 for its route: %q", c.q, r.Verdict, c.text)
		}
	}
}

// The plan of a scenario for the harness carries the states as the Controller sends them, each packet as the host
// sends it, and the verdict of explain with the rule that judged it at each Node.
func TestPlan(t *testing.T) {
	s := scenario(t, "leak-nat")
	_, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	_, results := model(t, s)
	plan, err := s.Plan()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(plan)), "\n")
	if lines[1] != "plan "+strconv.Itoa(PlanVersion) || lines[2] != "scenario leak-nat" || lines[3] != "node blue-1 33" || lines[4] != "node red-1 1" {
		t.Fatalf("the plan starts with %q", lines[:5])
	}
	frames := map[string]bool{}
	var packets, expects, judges int
	for _, line := range lines {
		f := strings.Fields(line)
		switch f[0] {
		case "frame":
			b, err := hex.DecodeString(f[2])
			if err != nil {
				t.Fatal(err)
			}
			var m controlpb.ControlMessage
			if err := proto.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			got, err := desired.FromFull(m.GetUpdate())
			if err != nil || m.GetUpdate().GetGeneration() != 1 || !desired.Equal(got, states[f[1]]) {
				t.Errorf("the frame of %s is not generation 1 of its state: %v", f[1], err)
			}
			frames[f[1]] = true
		case "packet":
			n, _ := strconv.Atoi(f[1])
			pk := results[n-1].Packet
			b, err := hex.DecodeString(f[5])
			if err != nil {
				t.Fatal(err)
			}
			if f[2] != s.Packets[n-1].Name || f[3] != pk.Node || f[4] != strconv.Itoa(int(pk.VRFID)) || len(b) < 24 || b[0] != 0x45 || b[9] != pk.Protocol ||
				netip.AddrFrom4([4]byte(b[12:16])) != pk.Source || netip.AddrFrom4([4]byte(b[16:20])) != pk.Destination ||
				binary.BigEndian.Uint16(b[20:]) != pk.SourcePort || binary.BigEndian.Uint16(b[22:]) != pk.Port || checksum(0, b[:20]) != 0 {
				t.Errorf("the line %q is not the packet %+v", line, pk)
			}
			packets++
		case "expect":
			expects++
		case "judge":
			judges++
		}
	}
	if len(frames) != 2 || packets != len(s.Packets) || expects != len(s.Packets) {
		t.Errorf("the plan has the frames of %v, %d packets and %d verdicts", frames, packets, expects)
	}
	if want := "expect 1 delivered red-1 1 172.16.2.1 10.0.0.1"; !slices.Contains(lines, want) {
		t.Errorf("the plan has no line %q", want)
	}
	for _, want := range []string{"judge 1 blue-1 blue blue-allow-all", "judge 1 red-1 red red-web-from-blue", "judge 3 red-1 red default:deny"} {
		if !slices.Contains(lines, want) {
			t.Errorf("the plan has no line %q", want)
		}
	}
	if judges != 7 {
		t.Errorf("the plan has %d judge lines, want 7", judges)
	}
}

// The plan of the broken scenario gives a-1 a state without the rule of the fault, and keeps the verdicts of explain on
// the states of the intent: the harness must disagree with it on the telnet packet.
func TestPlanOfTheBrokenScenario(t *testing.T) {
	s := scenario(t, "broken/policy-drift")
	plan, err := s.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(plan), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "frame" {
			b, _ := hex.DecodeString(f[2])
			var m controlpb.ControlMessage
			if err := proto.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			st, err := desired.FromFull(m.GetUpdate())
			if err != nil {
				t.Fatal(err)
			}
			_, has := st[desired.Key{Kind: controlpb.Kind_KIND_RULE, Name: "no-telnet"}]
			if has != (f[1] == "b-1") {
				t.Errorf("the state of %s in the plan holds no-telnet: %v", f[1], has)
			}
		}
	}
	if !strings.Contains(string(plan), "\nexpect 2 dropped a-1\njudge 2 a-1 lab no-telnet\n") {
		t.Errorf("the plan does not keep the verdict of explain on the telnet packet:\n%s", plan)
	}
}

// The packets of a plan: an ICMP echo of each family with its checksum, and the header of IPv6.
func TestPlanPackets(t *testing.T) {
	v4 := ipPacket(Packet{Protocol: protoICMP, Source: netip.MustParseAddr("10.0.0.1"), Destination: netip.MustParseAddr("10.0.0.2")}, 7)
	if len(v4) != 36 || v4[20] != 8 || binary.BigEndian.Uint16(v4[24:]) != 7 || checksum(0, v4[20:]) != 0 || checksum(0, v4[:20]) != 0 {
		t.Errorf("the echo of IPv4 is %x", v4)
	}
	src, dst := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	v6 := ipPacket(Packet{Protocol: protoICMPv6, Source: src, Destination: dst}, 9)
	if len(v6) != 56 || v6[0] != 0x60 || v6[6] != protoICMPv6 || v6[40] != 128 || binary.BigEndian.Uint16(v6[44:]) != 9 || checksum(pseudo6(src, dst, 16, protoICMPv6), v6[40:]) != 0 {
		t.Errorf("the echo of IPv6 is %x", v6)
	}
	tcp := ipPacket(Packet{Protocol: protoTCP, Source: src, Destination: dst, SourcePort: 1, Port: 2}, 1)
	if len(tcp) != 60 || tcp[53] != 0x02 || binary.BigEndian.Uint16(tcp[4:]) != 20 {
		t.Errorf("the SYN of IPv6 is %x", tcp)
	}
	other := ipPacket(Packet{Protocol: 47, Source: netip.MustParseAddr("10.0.0.1"), Destination: netip.MustParseAddr("10.0.0.2")}, 1)
	if len(other) != 20 || other[9] != 47 {
		t.Errorf("the packet of protocol 47 is %x", other)
	}
	if got := (Packet{Protocol: 47, Source: netip.MustParseAddr("10.0.0.1"), Destination: netip.MustParseAddr("10.0.0.2")}).String(); got != "protocol 47 10.0.0.1 > 10.0.0.2" {
		t.Errorf("the packet says %q", got)
	}
}

// A scenario whose intent does not apply, or whose nodes do not match its Node resources, is refused.
func TestScenarioDocument(t *testing.T) {
	s := scenario(t, "nat")
	s.Nodes = map[string]uint8{"gw-1": 1}
	if _, err := s.Document(); err == nil || !strings.Contains(err.Error(), `Node "pc-1" has no key in nodes`) {
		t.Errorf("a Node without a key: %v", err)
	}
	s.Nodes = map[string]uint8{"gw-1": 1, "pc-1": 33, "pc-2": 65}
	if _, err := s.Document(); err == nil || !strings.Contains(err.Error(), `nodes names "pc-2"`) {
		t.Errorf("a key without a Node: %v", err)
	}
	s = scenario(t, "nat")
	s.Intent = document(t, `{"resources": [{"kind": "Node", "name": "gw-1", "spec": {"publicKey": "`+base64.StdEncoding.EncodeToString(ScenarioKey(33))+`"}}]}`)
	s.Nodes = map[string]uint8{"gw-1": 1}
	if _, err := s.Document(); err == nil || !strings.Contains(err.Error(), "not ") {
		t.Errorf("a publicKey of another scalar: %v", err)
	}
	s.Intent = document(t, `{"resources": [{"kind": "VRF", "name": "corp", "spec": {"mtu": 10}}]}`)
	s.Nodes = nil
	if _, _, err := s.Compile(); err == nil || !errors.Is(err, intent.ErrInvalid) {
		t.Errorf("an intent that does not apply: %v", err)
	}
	if _, err := LoadScenario(filepath.Join(scenarioDir, "no-such-scenario.json")); err == nil {
		t.Error("a scenario file that does not exist loaded")
	}
}

// document parses an intent document of a test.
func document(t *testing.T, s string) intent.Document {
	t.Helper()
	var d intent.Document
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	return d
}
