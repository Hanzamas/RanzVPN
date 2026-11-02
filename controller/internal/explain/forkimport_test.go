package explain

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/forkimport"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The import of a fork Config file (SDN-27, #203) is held to the access list of the fork. A frame is judged by the
// first active entry of the list in the order of the priorities, a pass entry before a discard entry of one priority,
// and passes when no entry matches (ApplyAccessListToForwardPacket and IsPacketMaskedByAccessList of src/Cedar/Hub.c,
// CmpAccessList of HubTable.c); the oracle below is that, written from that code for IPv4 frames between two users, and
// is checked against the verdicts that the fork itself gave the frames of the sample hub, which
// tests/golden/policyimport/policyimport_frames.txt records. The import is then held to the oracle: on a hub whose
// entries a Policy can carry, every frame gets the verdict of the fork; on the sample hub, whose entries have matches
// that a Policy lacks, no frame gets a better one.

// forkSession is a session of a Virtual Hub of the fork: the two ends of a frame.
type forkSession struct {
	// user and group are the user of the session and the group of that user.
	user, group string
	// mac and addr are its MAC address and its IPv4 address.
	mac  [6]byte
	addr [4]byte
}

// forkFrame is an IPv4 frame between two sessions of a hub: its protocol, its ports and, for TCP, whether it is the SYN
// that opens a connection.
type forkFrame struct {
	from, to     forkSession
	proto        uint8
	sport, dport uint16
	syn          bool
}

// forkRule is an entry of an access list as the fork loads it (SiLoadHubAccessCfg of Server.c).
type forkRule struct {
	index                                  int
	priority                               uint32
	active, discard, ipv6                  bool
	src, srcMask, dst, dstMask             [4]byte
	hasV6                                  bool
	protocol                               uint32
	srcPorts, dstPorts                     [2]uint32
	srcUser, dstUser                       string
	checkSrcMac, checkDstMac               bool
	srcMac, srcMacMask, dstMac, dstMacMask [6]byte
	checkTCP, established                  bool
}

// forkIP reads the IPv4 address item name of f, all 0 for none.
func forkIP(f *forkimport.Folder, name string) [4]byte {
	if a, err := netip.ParseAddr(strings.TrimSpace(f.Str(name))); err == nil && a.Is4() {
		return a.As4()
	}
	return [4]byte{}
}

// forkMAC reads a MAC address as StrToMac does: its hex digits, two for each of 6 bytes.
func forkMAC(s string) ([6]byte, bool) {
	var digits []byte
	for _, c := range []byte(s) {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, c-'0')
		case c >= 'a' && c <= 'f':
			digits = append(digits, c-'a'+10)
		case c >= 'A' && c <= 'F':
			digits = append(digits, c-'A'+10)
		}
	}
	var mac [6]byte
	if len(digits)/2 != 6 {
		return mac, false
	}
	for i := range mac {
		high, low := digits[2*i], digits[2*i+1]
		mac[i] = high<<4 | low
	}
	return mac, true
}

// readForkRule reads the folder f of an entry, the index-th of its list.
func readForkRule(f *forkimport.Folder, index int) forkRule {
	r := forkRule{index: index, priority: f.Uint("Priority"), active: f.Bool("Active"), discard: f.Bool("Discard"), ipv6: f.Bool("IsIPv6"),
		protocol: f.Uint("Protocol"), srcUser: f.Str("SrcUsername"), dstUser: f.Str("DestUsername"), checkTCP: f.Bool("CheckTcpState"),
		established: f.Bool("Established")}
	r.src, r.srcMask = forkIP(f, "SrcIpAddress"), forkIP(f, "SrcSubnetMask")
	r.dst, r.dstMask = forkIP(f, "DestIpAddress"), forkIP(f, "DestSubnetMask")
	for _, name := range []string{"SrcIpAddress6", "SrcSubnetMask6", "DestIpAddress6", "DestSubnetMask6"} {
		if a, err := netip.ParseAddr(f.Str(name)); err == nil && !a.IsUnspecified() {
			r.hasV6 = true
		}
	}
	r.srcPorts = [2]uint32{f.Uint("SrcPortStart"), f.Uint("SrcPortEnd")}
	r.dstPorts = [2]uint32{f.Uint("DestPortStart"), f.Uint("DestPortEnd")}
	if r.srcPorts[0] != 0 {
		r.srcPorts[1] = max(r.srcPorts[1], r.srcPorts[0])
	}
	if r.dstPorts[0] != 0 {
		r.dstPorts[1] = max(r.dstPorts[1], r.dstPorts[0])
	}
	var okAddress, okMask bool
	r.srcMac, okAddress = forkMAC(f.Str("SrcMacAddress"))
	r.srcMacMask, okMask = forkMAC(f.Str("SrcMacMask"))
	r.checkSrcMac = f.Bool("CheckSrcMac") && okAddress && okMask
	r.dstMac, okAddress = forkMAC(f.Str("DstMacAddress"))
	r.dstMacMask, okMask = forkMAC(f.Str("DstMacMask"))
	r.checkDstMac = f.Bool("CheckDstMac") && okAddress && okMask
	return r
}

// forkBit is 1 for true.
func forkBit(b bool) int {
	if b {
		return 1
	}
	return 0
}

// forkRules reads the access list of the Virtual Hub hub in the order that the fork judges by.
func forkRules(hub *forkimport.Folder) []forkRule {
	var out []forkRule
	for i, f := range hub.Child("AccessList").Sorted() {
		out = append(out, readForkRule(f, i))
	}
	slices.SortStableFunc(out, func(a, b forkRule) int {
		return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(forkBit(a.discard), forkBit(b.discard)), cmp.Compare(a.index, b.index))
	})
	return out
}

// forkNameMatches reports whether the user or group name of an entry matches a session: the name of its user or of its
// group, without regard to case. A list of users in a file matches no one, as the harness of the fork has none.
func forkNameMatches(name, user, group string) bool {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return true
	case strings.HasPrefix(strings.ToLower(name), "include:"):
		return false
	case strings.HasPrefix(strings.ToLower(name), "exclude:"):
		return true
	}
	return strings.EqualFold(name, user) || strings.EqualFold(name, group)
}

// forkAddressMatches reports whether the IPv4 address ip is of the address addr under the mask mask; every address is,
// when the entry has neither.
func forkAddressMatches(addr, mask, ip [4]byte) bool {
	var zero [4]byte
	if addr == zero && mask == zero {
		return true
	}
	for i := range ip {
		if ip[i]&mask[i] != addr[i]&mask[i] {
			return false
		}
	}
	return true
}

// forkMACMatches reports whether the MAC address mac is of the address addr under the mask mask.
func forkMACMatches(addr, mask, mac [6]byte) bool {
	for i := range mac {
		if addr[i]&mask[i] != mask[i]&mac[i] {
			return false
		}
	}
	return true
}

// forkPortIn reports whether the port is in the range, which holds every port when it is 0 and 0 (PortInRange of Hub.c).
func forkPortIn(port uint32, ports [2]uint32) bool {
	if ports[0] == 0 && ports[1] == 0 {
		return true
	}
	return port >= ports[0] && port <= ports[1]
}

// matches is IsPacketMaskedByAccessList for an IPv4 frame: whether the entry holds the frame.
func (r forkRule) matches(f forkFrame) bool {
	if !r.active {
		return false
	}
	if r.checkSrcMac && !forkMACMatches(r.srcMac, r.srcMacMask, f.from.mac) {
		return false
	}
	if r.checkDstMac && !forkMACMatches(r.dstMac, r.dstMacMask, f.to.mac) {
		return false
	}
	if !forkNameMatches(r.srcUser, f.from.user, f.from.group) || !forkNameMatches(r.dstUser, f.to.user, f.to.group) {
		return false
	}
	anyPorts := r.srcPorts[0] != 0 || r.srcPorts[1] != 0 || r.dstPorts[0] != 0 || r.dstPorts[1] != 0
	if r.ipv6 {
		// An entry of IPv6 holds no frame of IPv4 that it has an address, a protocol, ports or a TCP state for
		return !(r.hasV6 || r.protocol != 0 || anyPorts || r.checkTCP)
	}
	if !forkAddressMatches(r.src, r.srcMask, f.from.addr) || !forkAddressMatches(r.dst, r.dstMask, f.to.addr) {
		return false
	}
	if r.protocol != 0 && uint32(f.proto) != r.protocol {
		return false
	}
	if anyPorts {
		if f.proto != 6 && f.proto != 17 {
			return false
		}
		if !forkPortIn(uint32(f.sport), r.srcPorts) || !forkPortIn(uint32(f.dport), r.dstPorts) {
			return false
		}
	}
	if r.checkTCP {
		if f.proto != 6 {
			return false
		}
		// A segment that is no SYN without an ACK belongs to a connection that exists
		if r.established == f.syn {
			return false
		}
	}
	return true
}

// forkPasses reports whether the access list rules, in the order of the fork, lets the frame through.
func forkPasses(rules []forkRule, f forkFrame) bool {
	for _, r := range rules {
		if r.matches(f) {
			return !r.discard
		}
	}
	return true
}

// forkWorld is a Virtual Hub of a Config file with a session for each Node of a scenario, which is named after its
// user and whose address in the VRF is the address of the session.
type forkWorld struct {
	rules    []forkRule
	sessions map[string]forkSession
}

// forkMACs are the MAC addresses of the users of the sample hub in the test of the fork, which entry 5 of its list reads.
var forkMACs = map[string]string{"alice": "02-00-00-4C-00-01", "bob": "02-00-00-4C-00-02", "carol": "02-00-00-4C-00-03",
	"dave": "02-00-00-4C-00-04", "erin": "02-00-00-4C-00-05", "ops": "02-00-00-4C-00-07", "srv": "02-00-00-4C-00-0A"}

// newForkWorld returns the world of the Virtual Hub hub of a Config file for the Nodes of the intent in.
func newForkWorld(t *testing.T, hub *forkimport.Folder, in intent.Intent) forkWorld {
	t.Helper()
	w := forkWorld{rules: forkRules(hub), sessions: map[string]forkSession{}}
	users := hub.Child("SecurityAccountDatabase").Child("UserList")
	for name, n := range in.Nodes {
		a, err := netip.ParseAddr(n.Addresses[n.VRFs[0]])
		if err != nil {
			t.Fatalf("Node %s: %v", name, err)
		}
		s := forkSession{user: n.Owner, group: users.Child(n.Owner).Str("GroupName"), addr: a.As4()}
		if mac, ok := forkMAC(forkMACs[n.Owner]); ok {
			s.mac = mac
		}
		w.sessions[name] = s
	}
	return w
}

// passes reports whether the fork lets through the frame that the Node from sends the Node to, of the protocol
// proto (tcp, udp or icmp) and of the ports; a TCP frame is a SYN.
func (w forkWorld) passes(from, to, proto string, sport, dport uint16) bool {
	f := forkFrame{from: w.sessions[from], to: w.sessions[to], sport: sport, dport: dport}
	switch proto {
	case "tcp":
		f.proto, f.syn = 6, true
	case "udp":
		f.proto = 17
	default:
		f.proto, f.sport, f.dport = 1, 0, 0
	}
	return forkPasses(w.rules, f)
}

// forkProbes are the frames that the tests send between every two Nodes: TCP, UDP and ICMP, to the ports of the entries
// of the sample hub and of the hub of the exact test, and to others.
var forkProbes = []struct {
	proto string
	port  uint16
}{
	{"tcp", 22}, {"tcp", 25}, {"tcp", 80}, {"tcp", 443}, {"tcp", 3389}, {"tcp", 5000}, {"tcp", 8000}, {"tcp", 8080}, {"tcp", 8081},
	{"udp", 53}, {"udp", 5050}, {"udp", 5060}, {"udp", 7777}, {"udp", 8000}, {"udp", 8080}, {"udp", 8081}, {"udp", 9999},
	{"icmp", 0},
}

// compare sends every probe between every two Nodes of the model m, and returns the frames that the fork lets through
// and the model drops (narrower), and the frames that the model delivers and the fork drops (wider), each as a line of
// words; and how many frames it sent.
func (w forkWorld) compare(t *testing.T, m *Model, nodes []string) (narrower, wider []string, sent int) {
	t.Helper()
	for _, from := range nodes {
		for _, to := range nodes {
			if from == to {
				continue
			}
			for _, p := range forkProbes {
				sent++
				sport := uint16(40000 + sent)
				r, err := m.Explain(Query{From: from, To: to, Protocol: p.proto, SourcePort: sport, Port: p.port})
				if err != nil {
					t.Fatalf("%s to %s %s %d: %v", from, to, p.proto, p.port, err)
				}
				line := fmt.Sprintf("%s to %s %s %d (%s)", from, to, p.proto, p.port, strings.Join(slices.Sorted(maps.Values(r.Rules())), ", "))
				switch pass := w.passes(from, to, p.proto, sport, p.port); {
				case pass && !r.Verdict.Delivered:
					narrower = append(narrower, line)
				case !pass && r.Verdict.Delivered:
					wider = append(wider, line)
				}
			}
		}
	}
	return narrower, wider, sent
}

// readSampleHub returns the Virtual Hub LAB of the sample Config file of the import.
func readSampleHub(t *testing.T) *forkimport.Folder {
	t.Helper()
	b, err := os.ReadFile("../../../tests/golden/configimport/sample.config")
	if err != nil {
		t.Fatal(err)
	}
	root, err := forkimport.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	hub := root.Child("VirtualHUB").Child("LAB")
	if hub == nil {
		t.Fatal("the sample Config file has no Virtual Hub LAB")
	}
	return hub
}

// forkRecorded are the verdicts of the fork that tests/golden/policyimport/policyimport_frames.txt records for the frames
// of the sample hub that the scenario forkimport sends: its packet, the line of the file, and whether the fork let the
// frame through (the line says "both" with a Node that got it, or "fork" with one for a frame that the import denies, or
// "both nobody").
var forkRecorded = []struct {
	packet, line string
	passed       bool
}{
	{"alice-ssh-srv", "15 alice tcp 22 to srv: both srv/10 (pass-rule LAB.acl-1)", true},
	{"bob-ssh-srv", "16 bob tcp 22 to srv: both nobody (drop-rule LAB.acl-2)", false},
	{"erin-dns-srv", "17 erin udp 53 to srv: both nobody (drop-rule LAB.acl-3)", false},
	{"ops-rdp-carol", "19 ops tcp 3389 to carol: both carol (pass-rule LAB.acl-4.1)", true},
	{"dave-https-srv", "20 dave tcp 443 to srv: both srv/1 (pass-rule LAB.acl-4.2)", true},
	{"bob-udp8080-srv", "21 bob udp 8080 to srv: both srv (pass-rule LAB.acl-8.2)", true},
	{"bob-udp9999-srv-narrower", "22 bob udp 9999 to srv: fork srv; new core nobody (drop-rule LAB.acl-9): narrower", true},
	{"carol-http-srv-narrower", "23 carol tcp 80 to srv: fork srv; new core nobody (drop-rule LAB.acl-11): narrower", true},
	{"bob-http-srv-narrower", "24 bob tcp 80 to srv: fork srv; new core nobody (drop-rule LAB.acl-11): narrower", true},
	{"bob-syn5000-srv", "26 bob tcp syn 5000 to srv: both nobody (drop-rule LAB.acl-13)", false},
	{"bob-ping-carol", "27 bob ping to carol: both nobody (drop-rule LAB.acl-14)", false},
	{"carol-ping-bob", "28 carol ping to bob: both bob (pass-rule LAB.default-allow)", true},
}

// The oracle gives the frames of the sample hub the verdicts that the fork gave them, and the scenario forkimport, whose
// intent is the import of that hub, gives each of them the same verdict, but for the three frames that its names call
// narrower: the fork let those through, and the import denies them, because the entry that would have let them through
// or kept them out has a match that a Policy lacks. This is the second criterion of #203 for the frames that the fork
// was run on.
func TestForkImportJudgesTheRecordedFramesAsTheForkDid(t *testing.T) {
	s := scenario(t, "forkimport")
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	m := New(in, states)
	world := newForkWorld(t, readSampleHub(t), in)
	for _, c := range forkRecorded {
		var p *ScenarioPacket
		for i := range s.Packets {
			if s.Packets[i].Name == c.packet {
				p = &s.Packets[i]
			}
		}
		if p == nil {
			t.Errorf("the scenario has no packet %s", c.packet)
			continue
		}
		proto := p.Protocol
		if proto == "" {
			proto = "icmp"
		}
		if got := world.passes(p.From, p.To, proto, p.SourcePort, p.Port); got != c.passed {
			t.Errorf("%s: the oracle says that the fork lets it through: %v, and the record of the fork says %v (%s)", c.packet, got, c.passed, c.line)
		}
		r, err := m.Explain(p.Query)
		if err != nil {
			t.Errorf("%s: %v", c.packet, err)
			continue
		}
		narrower := strings.HasSuffix(c.packet, "-narrower")
		switch {
		case narrower && (!c.passed || r.Verdict.Delivered):
			t.Errorf("%s: the fork let it through: %v, and explain delivers it: %v, which a narrower frame does not do", c.packet, c.passed, r.Verdict.Delivered)
		case !narrower && r.Verdict.Delivered != c.passed:
			t.Errorf("%s: the fork let it through: %v, and explain delivers it: %v (%s)", c.packet, c.passed, r.Verdict.Delivered, c.line)
		}
	}
}

// Every frame between two Nodes of the sample hub, in every kind that the probes have, gets from the import a verdict that
// is no better than the fork gave it: the import carries an entry that has a match that a Policy lacks (a source port, the
// TCP state, a mask that is no prefix, a redirect, a list of users in a file) as a deny entry without it, and leaves out
// an allow entry that has one. Some frames get a worse verdict, which the notes of the import say.
func TestForkImportNeverLetsThroughWhatTheForkDropped(t *testing.T) {
	s := scenario(t, "forkimport")
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	m := New(in, states)
	world := newForkWorld(t, readSampleHub(t), in)
	var nodes []string
	for name := range in.Nodes {
		nodes = append(nodes, name)
	}
	slices.Sort(nodes)
	narrower, wider, sent := world.compare(t, m, nodes)
	for _, line := range wider {
		t.Errorf("the import delivers a frame that the fork dropped: %s", line)
	}
	if len(narrower) == 0 {
		t.Error("the import denies no frame that the fork let through, and the sample has entries that a Policy cannot carry")
	}
	t.Logf("%d frames: the import denies %d that the fork let through, and delivers none that the fork dropped", sent, len(narrower))
}

// forkExactConfig is a Config file with the Virtual Hub EXACT, whose access list has entries that a Policy carries as
// they are (users, a group and a user of one name, a priority with a pass entry and a discard entry, prefixes, ports
// without a protocol, an entry that is inactive), and whose users are in the groups red and blue.
const forkExactConfig = `declare root
{
declare ServerConfiguration
{
}
declare VirtualHUB
{
declare EXACT
{
declare AccessList
{
declare 1
{
bool Active true
bool Discard false
uint Priority 100
uint Protocol 6
uint DestPortStart 22
uint DestPortEnd 22
string SrcUsername red
}
declare 2
{
bool Active true
bool Discard true
uint Priority 100
uint Protocol 6
uint DestPortStart 22
uint DestPortEnd 22
}
declare 3
{
bool Active true
bool Discard true
uint Priority 200
string DestUsername blue
string SrcIpAddress 10.9.0.4
string SrcSubnetMask 255.255.255.255
}
declare 4
{
bool Active true
bool Discard false
uint Priority 300
uint Protocol 17
uint DestPortStart 5000
uint DestPortEnd 5100
string SrcUsername u3
}
declare 5
{
bool Active true
bool Discard true
uint Priority 400
uint Protocol 17
}
declare 6
{
bool Active true
bool Discard true
uint Priority 500
uint Protocol 1
string DestIpAddress 10.9.0.2
string DestSubnetMask 255.255.255.255
}
declare 7
{
bool Active true
bool Discard false
uint Priority 600
uint Protocol 6
uint DestPortStart 8000
uint DestPortEnd 8100
string SrcUsername red
}
declare 8
{
bool Active true
bool Discard true
uint Priority 700
uint DestPortStart 8081
uint DestPortEnd 8081
}
declare 9
{
bool Active false
bool Discard true
uint Priority 800
uint Protocol 6
}
}
declare SecurityAccountDatabase
{
declare GroupList
{
declare blue
{
}
declare red
{
}
}
declare UserList
{
declare blue
{
}
declare u1
{
string GroupName red
}
declare u2
{
string GroupName red
}
declare u3
{
string GroupName blue
}
declare u4
{
}
}
}
}
}
}
`

// On a hub whose entries a Policy carries as they are, every frame between two Nodes gets from the import the verdict
// that the fork gave it: the entries in the order of the fork, the group and the user of one name, a pass entry before a
// discard entry of one priority, the prefixes, the ports of both protocols, and what no entry matches. This is the second
// criterion of #203 held to every frame of a kind, not to the ones that the fork was run on.
func TestForkImportJudgesEveryFrameAsTheForkDid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exact.config")
	if err := os.WriteFile(path, []byte(forkExactConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var nodes []string
	var resources []intent.Resource
	keys := map[string]uint8{}
	for i, u := range []struct{ name, address string }{{"u1", "10.9.0.1"}, {"u2", "10.9.0.2"}, {"u3", "10.9.0.3"}, {"u4", "10.9.0.4"}, {"blue", "10.9.0.5"}} {
		nodes = append(nodes, u.name)
		keys[u.name] = uint8(1 + 32*i)
		spec := fmt.Sprintf(`{"vrfs": ["exact"], "owner": %q, "addresses": {"exact": %q}}`, u.name, u.address)
		resources = append(resources, intent.Resource{Kind: intent.KindNode, Name: u.name, Spec: []byte(spec)})
	}
	s := Scenario{Name: "exact", Nodes: keys, Intent: intent.Document{Resources: resources},
		Import: &ForkImport{Config: path, Pools: map[string]string{"EXACT": "10.9.0.0/24"}}}
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	root, err := forkimport.Parse([]byte(forkExactConfig))
	if err != nil {
		t.Fatal(err)
	}
	world := newForkWorld(t, root.Child("VirtualHUB").Child("EXACT"), in)
	narrower, wider, sent := world.compare(t, New(in, states), nodes)
	for _, line := range append(narrower, wider...) {
		t.Errorf("the verdict of the import differs from the one of the fork: %s", line)
	}
	if sent != 20*len(forkProbes) {
		t.Errorf("%d frames were sent, want %d", sent, 20*len(forkProbes))
	}
}
