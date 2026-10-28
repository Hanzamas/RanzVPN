package explain

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The explain conformance (ADR-0031 decision 8). A scenario file of tests/explain holds a topology, an intent and
// test packets, with the verdict that each packet must get. Each runs twice: through Explain on the desired states
// that the intent compiles to (Check, and the API of the Controller in its conformance tests), and through the data
// plane of real Nodes in the vpntest harness (src/vpntest/explaintest.c), which runs a plan that ranz-explainplan
// writes from the scenario (Plan): the states as the control protocol carries them, which a stand-in controller of
// the harness sends to the Nodes over their control streams, and the packets, each with the verdict of Explain. The
// harness sends each packet from the host of its Node and finds where it ends and which rule of the policy judged it
// at each Node; every verdict must be the one of Explain. A scenario with a Fault breaks the data plane on purpose:
// the plan gives a Node a state without one of its rules, so the harness disagrees with Explain on the packets that
// the Fault names, and the suite must fail on them.

// PlanVersion is the version of the plans that Plan writes, the first line of each.
const PlanVersion = 1

// Scenario is one scenario of the explain conformance.
type Scenario struct {
	// Name is the name of the file of the scenario without .json.
	Name string `json:"-"`
	// Description says what the scenario shows.
	Description string `json:"description"`
	// Nodes holds the static key of each Node of the intent as the harness makes it: the first byte of its scalar,
	// whose bytes are first, first+1, ... first+31. A Node resource of the intent that leaves out its publicKey gets
	// the X25519 public key of that scalar, and one that gives it must give that key.
	Nodes map[string]uint8 `json:"nodes"`
	// Intent is the intent document of the scenario, applied to an empty intent.
	Intent intent.Document `json:"intent"`
	// Packets are the test packets, each the first of a flow, in the order that the harness sends them.
	Packets []ScenarioPacket `json:"packets"`
	// Fault breaks the data plane of the harness on purpose, nil for a scenario that the suite must pass.
	Fault *Fault `json:"fault,omitempty"`
}

// ScenarioPacket is a test packet of a scenario: its query, and the verdict that Explain and the data plane must
// both give.
type ScenarioPacket struct {
	Name string `json:"name"`
	Query
	Expect Expect `json:"expect"`
}

// Expect is the verdict of a test packet: where it ends, and the rule that judged it at each Node, by Node name (the
// Policy, or DefaultDeny), none for a Node whose policy did not judge it.
type Expect struct {
	Delivered   bool              `json:"delivered"`
	Node        string            `json:"node"`
	VRF         string            `json:"vrf,omitempty"`
	Source      string            `json:"source,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Rules       map[string]string `json:"rules,omitempty"`
}

// Fault is a deliberate break of the data plane of a scenario: the state of Node that the harness gets has no Rule
// object DropRule, so the data plane and Explain disagree on the packets that Breaks names.
type Fault struct {
	Node     string   `json:"node"`
	DropRule string   `json:"dropRule"`
	Breaks   []string `json:"breaks"`
}

// LoadScenario reads the scenario file path, a file of tests/explain.
func LoadScenario(path string) (Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, err
	}
	var s Scenario
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Scenario{}, fmt.Errorf("%s: %w", path, err)
	}
	s.Name = strings.TrimSuffix(filepath.Base(path), ".json")
	return s, nil
}

// ScenarioFiles returns the scenario files of the directory dir, in name order.
func ScenarioFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}

// ScenarioKey returns the public key of the static key of the scenario whose scalar starts with first.
func ScenarioKey(first uint8) []byte {
	scalar := make([]byte, intent.KeySize)
	for i := range scalar {
		scalar[i] = first + byte(i)
	}
	k, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		// Every 32 bytes are an X25519 scalar
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// Document returns the intent document of s with the public key of each Node filled in from Nodes. A Node of the
// intent without a key in Nodes, or one whose publicKey is not that key, is an error.
func (s Scenario) Document() (intent.Document, error) {
	doc := intent.Document{Resources: slices.Clone(s.Intent.Resources)}
	seen := map[string]bool{}
	for i, r := range doc.Resources {
		if r.Kind != intent.KindNode {
			continue
		}
		first, ok := s.Nodes[r.Name]
		if !ok {
			return intent.Document{}, fmt.Errorf("scenario %s: Node %q has no key in nodes", s.Name, r.Name)
		}
		seen[r.Name] = true
		spec := map[string]any{}
		if len(r.Spec) != 0 {
			if err := json.Unmarshal(r.Spec, &spec); err != nil {
				return intent.Document{}, fmt.Errorf("scenario %s: Node %q: %w", s.Name, r.Name, err)
			}
		}
		key := base64.StdEncoding.EncodeToString(ScenarioKey(first))
		if given, ok := spec["publicKey"]; ok && given != key {
			return intent.Document{}, fmt.Errorf("scenario %s: Node %q has the publicKey %v, not %s of the scalar from %d", s.Name, r.Name, given, key, first)
		}
		spec["publicKey"] = key
		b, err := json.Marshal(spec)
		if err != nil {
			return intent.Document{}, err
		}
		doc.Resources[i].Spec = b
	}
	for _, name := range slices.Sorted(maps.Keys(s.Nodes)) {
		if !seen[name] {
			return intent.Document{}, fmt.Errorf("scenario %s: nodes names %q, which the intent has no Node resource of", s.Name, name)
		}
	}
	return doc, nil
}

// Compile applies the intent of s to an empty intent, a ULA that a VRF leaves out drawn from a fixed seed, and
// compiles the desired state of every Node, as the Controller does.
func (s Scenario) Compile() (intent.Intent, map[string]desired.State, error) {
	doc, err := s.Document()
	if err != nil {
		return intent.Intent{}, nil, err
	}
	in, err := intent.Apply(intent.New(), doc, rand.NewChaCha8([32]byte{}))
	if err != nil {
		return intent.Intent{}, nil, fmt.Errorf("scenario %s: %w", s.Name, err)
	}
	states, err := desired.Compile(in)
	if err != nil {
		return intent.Intent{}, nil, fmt.Errorf("scenario %s: %w", s.Name, err)
	}
	return in, states, nil
}

// Explain explains each packet of s on the model m.
func (s Scenario) Explain(m *Model) ([]Result, error) {
	var out []Result
	for _, p := range s.Packets {
		r, err := m.Explain(p.Query)
		if err != nil {
			return nil, fmt.Errorf("scenario %s, packet %s: %w", s.Name, p.Name, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Differs returns how the Result r differs from the verdict e, nil when it gives it.
func (e Expect) Differs(r Result) []string {
	var out []string
	v := r.Verdict
	if v.Delivered != e.Delivered || v.Node != e.Node {
		out = append(out, fmt.Sprintf("explain: %s, the scenario: %s", outcome(v.Delivered, v.Node), outcome(e.Delivered, e.Node)))
	}
	if e.VRF != "" && v.VRF != e.VRF {
		out = append(out, fmt.Sprintf("explain delivers it in VRF %q, the scenario in %q", v.VRF, e.VRF))
	}
	for _, x := range []struct {
		what, want string
		got        netip.Addr
	}{{"source", e.Source, v.Source}, {"destination", e.Destination, v.Destination}} {
		if x.want != "" && x.got.String() != x.want {
			out = append(out, fmt.Sprintf("explain delivers it with the %s %s, the scenario with %s", x.what, x.got, x.want))
		}
	}
	if e.Reason != "" && v.Reason != e.Reason {
		out = append(out, fmt.Sprintf("explain drops it for the reason %q, the scenario for %q", v.Reason, e.Reason))
	}
	want := e.Rules
	if want == nil {
		want = map[string]string{}
	}
	if got := r.Rules(); !maps.Equal(got, want) {
		out = append(out, fmt.Sprintf("explain names the rules %s, the scenario %s", showRules(got), showRules(want)))
	}
	return out
}

// Check explains each packet of s on the states that its intent compiles to and checks that each gets its verdict,
// that no two packets are one flow, and that a Fault changes the verdicts of the packets that it names and of no
// other.
func (s Scenario) Check() error {
	in, states, err := s.Compile()
	if err != nil {
		return err
	}
	results, err := s.Explain(New(in, states))
	if err != nil {
		return err
	}
	var problems []error
	flows := map[string]string{}
	for i, p := range s.Packets {
		if p.Name == "" || strings.ContainsAny(p.Name, " \t") {
			problems = append(problems, fmt.Errorf("scenario %s: packet %d needs a name without a space", s.Name, i+1))
		}
		for _, d := range p.Expect.Differs(results[i]) {
			problems = append(problems, fmt.Errorf("scenario %s, packet %s: %s", s.Name, p.Name, d))
		}
		pk := results[i].Packet
		if pk.Protocol == protoTCP || pk.Protocol == protoUDP {
			key := fmt.Sprintf("%d %s %s", pk.Protocol, netip.AddrPortFrom(pk.Source, pk.SourcePort), netip.AddrPortFrom(pk.Destination, pk.Port))
			back := fmt.Sprintf("%d %s %s", pk.Protocol, netip.AddrPortFrom(pk.Destination, pk.Port), netip.AddrPortFrom(pk.Source, pk.SourcePort))
			for _, k := range []string{key, back} {
				if other, ok := flows[k]; ok {
					problems = append(problems, fmt.Errorf("scenario %s, packet %s: it is of the flow of packet %s, so a Node would not judge it again: give it other ports", s.Name, p.Name, other))
				}
			}
			flows[key] = p.Name
		}
	}
	if s.Fault != nil {
		broken, err := s.faulted(states)
		if err != nil {
			return err
		}
		faulted, err := s.Explain(New(in, broken))
		if err != nil {
			return err
		}
		var changed []string
		for i, p := range s.Packets {
			if verdictLine(results[i]) != verdictLine(faulted[i]) {
				changed = append(changed, p.Name)
			}
		}
		if want := slices.Sorted(slices.Values(s.Fault.Breaks)); !slices.Equal(slices.Sorted(slices.Values(changed)), want) || len(want) == 0 {
			problems = append(problems, fmt.Errorf("scenario %s: the fault changes the verdicts of the packets %v, and it names %v", s.Name, changed, s.Fault.Breaks))
		}
	}
	return errors.Join(problems...)
}

// faulted returns the states of the scenario with its Fault: the state of the Node of the Fault without the Rule.
func (s Scenario) faulted(states map[string]desired.State) (map[string]desired.State, error) {
	out := maps.Clone(states)
	st, ok := states[s.Fault.Node]
	key := desired.Key{Kind: controlpb.Kind_KIND_RULE, Name: s.Fault.DropRule}
	if !ok {
		return nil, fmt.Errorf("scenario %s: the fault names Node %q, which has no state", s.Name, s.Fault.Node)
	}
	if _, ok := st[key]; !ok {
		return nil, fmt.Errorf("scenario %s: the fault drops the rule %q, which the state of %s does not hold", s.Name, s.Fault.DropRule, s.Fault.Node)
	}
	st = maps.Clone(st)
	delete(st, key)
	out[s.Fault.Node] = st
	return out, nil
}

// Plan returns the plan of s for the vpntest harness (src/vpntest/explaintest.c), one line of words separated by
// spaces for each thing:
//
//	plan 1
//	scenario NAME
//	node NAME FIRST                    a Node and the first byte of the scalar of its static key
//	frame NODE HEX                     the ControlMessage that carries the Update of generation 1 of its state
//	packet I NAME NODE VRFID HEX       test packet I: its name, the Node whose host sends it, its VRF and its bytes
//	expect I delivered NODE VRFID SRC DST
//	expect I dropped NODE              the verdict of Explain: where the packet ends
//	judge I NODE VRF RULE              the rule of the policy of the VRF that judged it at the Node, one line for each
//	text I WORDS...                    the steps and the verdict of Explain, for the log
//
// The states are the ones of the intent, with the Fault of a broken scenario; the verdicts are always the ones of
// Explain on the states of the intent. Plan fails when Check does.
func (s Scenario) Plan() ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	in, states, err := s.Compile()
	if err != nil {
		return nil, err
	}
	results, err := s.Explain(New(in, states))
	if err != nil {
		return nil, err
	}
	if s.Fault != nil {
		if states, err = s.faulted(states); err != nil {
			return nil, err
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# The plan of the explain scenario %s for vpntest explain, written by ranz-explainplan\n", s.Name)
	fmt.Fprintf(&b, "plan %d\nscenario %s\n", PlanVersion, s.Name)
	for _, name := range slices.Sorted(maps.Keys(s.Nodes)) {
		fmt.Fprintf(&b, "node %s %d\n", name, s.Nodes[name])
	}
	for _, name := range slices.Sorted(maps.Keys(s.Nodes)) {
		st, ok := states[name]
		if !ok {
			return nil, fmt.Errorf("scenario %s: Node %q has no state", s.Name, name)
		}
		frame, err := proto.Marshal(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Update{Update: desired.Full(st, 1)}})
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "frame %s %s\n", name, hex.EncodeToString(frame))
	}
	for i, r := range results {
		n := i + 1
		pk := r.Packet
		fmt.Fprintf(&b, "packet %d %s %s %d %s\n", n, s.Packets[i].Name, pk.Node, pk.VRFID, hex.EncodeToString(ipPacket(pk, uint16(n))))
		if r.Verdict.Delivered {
			fmt.Fprintf(&b, "expect %d delivered %s %d %s %s\n", n, r.Verdict.Node, r.Verdict.VRFID, r.Verdict.Source, r.Verdict.Destination)
		} else {
			fmt.Fprintf(&b, "expect %d dropped %s\n", n, r.Verdict.Node)
		}
		for _, st := range r.Steps {
			if st.Kind == StepPolicy && st.Rule != nil && st.Rule.Name != "" {
				fmt.Fprintf(&b, "judge %d %s %s %s\n", n, st.Node, st.VRF, st.Rule.Name)
			}
		}
		for _, st := range r.Steps {
			fmt.Fprintf(&b, "text %d %s %s: %s\n", n, st.Node, st.Kind, oneLine(st.Text))
		}
		fmt.Fprintf(&b, "text %d verdict: %s\n", n, oneLine(r.Verdict.Text))
	}
	return b.Bytes(), nil
}

// verdictLine says the verdict of r and the rules that judged the packet in one line, which two Results share when
// they agree.
func verdictLine(r Result) string {
	v := r.Verdict
	line := outcome(v.Delivered, v.Node)
	if v.Delivered {
		line += fmt.Sprintf(" in VRF %s as %s > %s", v.VRF, v.Source, v.Destination)
	}
	return line + "; rules " + showRules(r.Rules())
}

func outcome(delivered bool, node string) string {
	if delivered {
		return "delivered to " + node
	}
	return "dropped by " + node
}

// showRules says the rules of each Node, in Node order.
func showRules(rules map[string]string) string {
	if len(rules) == 0 {
		return "none"
	}
	var out []string
	for _, n := range slices.Sorted(maps.Keys(rules)) {
		out = append(out, n+"="+rules[n])
	}
	return strings.Join(out, " ")
}

// oneLine puts a text on one line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ipPacket returns the bytes of the packet p as the host of its Node sends it: an IPv4 or IPv6 header and a UDP
// datagram, the SYN of TCP, an ICMP echo request with the identifier id, or nothing more for another protocol. Each
// echo of a scenario has an identifier of its own, so it opens a flow of its own.
func ipPacket(p Packet, id uint16) []byte {
	var l4 []byte
	switch p.Protocol {
	case protoUDP:
		l4 = make([]byte, 16)
		binary.BigEndian.PutUint16(l4, p.SourcePort)
		binary.BigEndian.PutUint16(l4[2:], p.Port)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	case protoTCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4, p.SourcePort)
		binary.BigEndian.PutUint16(l4[2:], p.Port)
		binary.BigEndian.PutUint32(l4[4:], 0x1000)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
		binary.BigEndian.PutUint16(l4[14:], 64240)
	case protoICMP, protoICMPv6:
		l4 = make([]byte, 16)
		l4[0] = 8
		if p.Protocol == protoICMPv6 {
			l4[0] = 128
		}
		binary.BigEndian.PutUint16(l4[4:], id)
		binary.BigEndian.PutUint16(l4[6:], 1)
		sum := uint32(0)
		if p.Protocol == protoICMPv6 {
			sum = pseudo6(p.Source, p.Destination, len(l4), protoICMPv6)
		}
		binary.BigEndian.PutUint16(l4[2:], checksum(sum, l4))
	}
	if p.Source.Is4() {
		h := make([]byte, 20)
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(len(h)+len(l4)))
		h[8] = 64
		h[9] = p.Protocol
		s, d := p.Source.As4(), p.Destination.As4()
		copy(h[12:], s[:])
		copy(h[16:], d[:])
		binary.BigEndian.PutUint16(h[10:], checksum(0, h))
		return append(h, l4...)
	}
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	h[6] = p.Protocol
	h[7] = 64
	s, d := p.Source.As16(), p.Destination.As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(h, l4...)
}

// pseudo6 returns the sum of the pseudo-header of IPv6 (RFC 8200 section 8.1).
func pseudo6(src, dst netip.Addr, length int, protocol uint8) uint32 {
	s, d := src.As16(), dst.As16()
	return sum16(sum16(0, s[:]), d[:]) + uint32(length>>16) + uint32(length&0xFFFF) + uint32(protocol)
}

// sum16 adds the bytes of b as big-endian 16-bit words to sum.
func sum16(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// checksum returns the Internet checksum of b with sum added (RFC 1071).
func checksum(sum uint32, b []byte) uint16 {
	sum = sum16(sum, b)
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}
