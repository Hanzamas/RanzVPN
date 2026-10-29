package desired

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The mimic part of the state of a Node (SDN-94 #423, mimic.go): the settings of a mimic server with the short id and no
// key, and a link to each mimic endpoint of each peer that is a mimic server, once its Node reported its public key.

var (
	mimicID  = []byte("ABCDEFGH")
	mimicKey = []byte("0123456789abcdef0123456789abcdef")
)

// mimicSection is the Listener of the Node hub with a mimic section of two server names, and mimicHubEndpoints are the
// endpoints of hub: one of QUIC and two of the mimic transport, a name and an IPv6 address.
const (
	mimicSection = `{"node": "hub", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}, "mimic": {"listen": ":8443",
		"serverNames": ["www.example.com", "cdn.example.com"], "maxTimeDiffMs": 5000, "decoy": {"selfSigned": true}}}`
	mimicHubEndpoints = `[{"transport": "quic", "address": "hub.example.com:443"}, {"transport": "mimic", "address": "hub.example.com:8443"},
		{"transport": "mimic", "address": "[2001:db8::10]:8443"}]`
)

// mimicNetwork returns the resources of a network of the mimic server hub, whose Listener is listener and whose endpoints are
// endpoints, of gw-1, which shares VRF corp with it, of gw-2, which shares corp with it and lab with lab-1, and of lab-1,
// which shares no VRF with hub.
func mimicNetwork(listener, endpoints string) []intent.Resource {
	return []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "hub", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "endpoints": `+endpoints+`}`),
		res(intent.KindNode, "gw-1", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "gw-2", `{"publicKey": "`+key3+`", "vrfs": ["corp", "lab"]}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "`+key4+`", "vrfs": ["lab"]}`),
		res(intent.KindListener, "edge-hub", listener),
	}
}

// mimicStates applies the resources, compiles them and puts the mimic part into the states with m.
func mimicStates(t *testing.T, m Mimic, rs []intent.Resource) map[string]State {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithMimic(in, states, m); err != nil {
		t.Fatal(err)
	}
	return states
}

// reported is what the Controller holds when the Node hub reported its public key.
func reported() Mimic {
	return Mimic{ShortIDs: map[string][]byte{"hub": mimicID}, Keys: map[string][]byte{"hub": mimicKey}}
}

// mimicOf returns the mimic part of the NodeConfig of the Node name, nil for none.
func mimicOf(states map[string]State, name string) *controlpb.Mimic {
	return states[name][Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetMimic()
}

// hubLinks returns the links that a client of hub has once the key of hub is known: one for each of its mimic endpoints.
func hubLinks(key []byte) []*controlpb.MimicLink {
	return []*controlpb.MimicLink{
		{Peer: "hub", Address: "hub.example.com:8443", ServerName: "www.example.com", PublicKey: key, ShortId: mimicID},
		{Peer: "hub", Address: "[2001:db8::10]:8443", ServerName: "www.example.com", PublicKey: key, ShortId: mimicID},
	}
}

func sameLinks(got, want []*controlpb.MimicLink) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

// changed returns the names of the Nodes whose state differs between a and b, in name order.
func changed(a, b map[string]State) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(b)) {
		if !Equal(a[name], b[name]) {
			out = append(out, name)
		}
	}
	return out
}

// The Node that a Listener gives a mimic section gets the settings of the section with the short id and no key. Each Node
// that has it as a peer and a mimic endpoint of it gets one link for each of those endpoints, in the order of the
// endpoints, with the first server name, the public key that the Node reported and the short id: gw-1 and gw-2, which share
// corp with hub. lab-1 shares no VRF with it and gets none, and the endpoint of QUIC makes no link.
func TestWithMimicGivesTheServerAndItsClients(t *testing.T) {
	states := mimicStates(t, reported(), mimicNetwork(mimicSection, mimicHubEndpoints))

	hub := mimicOf(states, "hub")
	want := &controlpb.MimicServer{Listen: ":8443", ServerNames: []string{"www.example.com", "cdn.example.com"}, MaxTimeDiffMs: 5000,
		Decoy: &controlpb.MimicDecoy{Mode: controlpb.MimicDecoyMode_MIMIC_DECOY_MODE_OWN, SelfSigned: true}, ShortId: mimicID}
	if !proto.Equal(hub.GetServer(), want) {
		t.Errorf("the server of hub is %v, want %v", hub.GetServer(), want)
	}
	if len(hub.GetLinks()) != 0 {
		t.Errorf("hub, which has no mimic server as a peer, has the links %v", hub.GetLinks())
	}
	for _, name := range []string{"gw-1", "gw-2"} {
		m := mimicOf(states, name)
		if m.GetServer() != nil || !sameLinks(m.GetLinks(), hubLinks(mimicKey)) {
			t.Errorf("the mimic part of %s is %v, want the links %v and no server", name, m, hubLinks(mimicKey))
		}
	}
	if m := mimicOf(states, "lab-1"); m != nil {
		t.Errorf("lab-1, which shares no VRF with the server, has the mimic part %v", m)
	}
	// The rest of the NodeConfig of hub is the one that Compile made
	plain, err := Compile(mustApply(t, mimicNetwork(mimicSection, mimicHubEndpoints)))
	if err != nil {
		t.Fatal(err)
	}
	got := states["hub"][Key{controlpb.Kind_KIND_NODE, "hub"}].GetNode()
	made := plain["hub"][Key{controlpb.Kind_KIND_NODE, "hub"}].GetNode()
	if made.GetMimic() != nil {
		t.Errorf("Compile made the mimic part %v: it cannot know the short id and the key", made.GetMimic())
	}
	made = proto.Clone(made).(*controlpb.NodeConfig)
	made.Mimic = got.GetMimic()
	if !proto.Equal(got, made) {
		t.Errorf("the NodeConfig of hub is %v, want what Compile made with the mimic part alone added", got)
	}
}

// mustApply applies the resources to an empty intent.
func mustApply(t *testing.T, rs []intent.Resource) intent.Intent {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// Until the Node of the server reported its public key, no client has a link: the server has its settings, and the Nodes
// that will have a link have no mimic part. A key of another size is no key.
func TestWithMimicWaitsForTheKey(t *testing.T) {
	for name, keys := range map[string]map[string][]byte{
		"no report":       nil,
		"an empty key":    {"hub": {}},
		"a short key":     {"hub": mimicKey[:31]},
		"a long key":      {"hub": append(slices.Clone(mimicKey), 'x')},
		"a key of a Node": {"gw-1": mimicKey},
	} {
		states := mimicStates(t, Mimic{ShortIDs: map[string][]byte{"hub": mimicID}, Keys: keys}, mimicNetwork(mimicSection, mimicHubEndpoints))
		if mimicOf(states, "hub").GetServer() == nil {
			t.Errorf("%s: hub has no server settings", name)
		}
		for _, node := range []string{"gw-1", "gw-2", "lab-1"} {
			if m := mimicOf(states, node); m != nil {
				t.Errorf("%s: %s has the mimic part %v before the key of hub was reported", name, node, m)
			}
		}
	}
}

// A change of the reported key changes the state of the clients, which hold it in their links, and of no other Node. A
// change of the section changes the state of the server, and the state of the clients when it changes what their links hold,
// the first server name, and of no other Node. A change of the endpoints of the server changes its state and the states of
// its peers, and of no other Node.
func TestWithMimicChangesTheServerAndItsClientsOnly(t *testing.T) {
	before := mimicStates(t, reported(), mimicNetwork(mimicSection, mimicHubEndpoints))
	for _, c := range []struct {
		name     string
		m        Mimic
		listener string
		hub      string
		want     []string
	}{
		{"a new key", Mimic{ShortIDs: reported().ShortIDs, Keys: map[string][]byte{"hub": []byte("fedcba9876543210fedcba9876543210")}}, mimicSection, mimicHubEndpoints, []string{"gw-1", "gw-2"}},
		{"the same key", reported(), mimicSection, mimicHubEndpoints, nil},
		{"the clock tolerance", reported(), strings.Replace(mimicSection, "5000", "6000", 1), mimicHubEndpoints, []string{"hub"}},
		{"the decoy", reported(), strings.Replace(mimicSection, `"selfSigned": true`, `"mode": "borrow", "dest": "www.example.com:443"`, 1), mimicHubEndpoints, []string{"hub"}},
		{"the address of the sidecar", reported(), strings.Replace(mimicSection, ":8443", ":9443", 1), mimicHubEndpoints, []string{"hub"}},
		{"the order of the server names", reported(), strings.Replace(mimicSection, `["www.example.com", "cdn.example.com"]`, `["cdn.example.com", "www.example.com"]`, 1), mimicHubEndpoints, []string{"gw-1", "gw-2", "hub"}},
		{"the second server name", reported(), strings.Replace(mimicSection, "cdn.example.com", "img.example.com", 1), mimicHubEndpoints, []string{"hub"}},
		{"a new short id", Mimic{ShortIDs: map[string][]byte{"hub": []byte("IJKLMNOP")}, Keys: reported().Keys}, mimicSection, mimicHubEndpoints, []string{"gw-1", "gw-2", "hub"}},
		{"a mimic endpoint of the server", reported(), mimicSection, strings.Replace(mimicHubEndpoints, "hub.example.com:8443", "hub.example.com:9443", 1), []string{"gw-1", "gw-2", "hub"}},
		{"the endpoint of QUIC of the server", reported(), mimicSection, strings.Replace(mimicHubEndpoints, "hub.example.com:443", "198.51.100.7:443", 1), []string{"gw-1", "gw-2", "hub"}},
	} {
		after := mimicStates(t, c.m, mimicNetwork(c.listener, c.hub))
		if got := changed(before, after); !slices.Equal(got, c.want) {
			t.Errorf("%s changed the states of %v, want %v", c.name, got, c.want)
		}
	}

	// The new key is one object of each client, its NodeConfig, in a delta
	after := mimicStates(t, Mimic{ShortIDs: reported().ShortIDs, Keys: map[string][]byte{"hub": []byte("fedcba9876543210fedcba9876543210")}}, mimicNetwork(mimicSection, mimicHubEndpoints))
	u := Delta(before["gw-1"], 1, after["gw-1"], 2)
	if len(u.GetSet()) != 1 || len(u.GetRemove()) != 0 || u.GetSet()[0].GetNode().GetName() != "gw-1" {
		t.Fatalf("the update of gw-1 for the new key is %v, want its NodeConfig alone", u)
	}
	if links := u.GetSet()[0].GetNode().GetMimic().GetLinks(); len(links) != 2 || string(links[0].GetPublicKey()) != "fedcba9876543210fedcba9876543210" {
		t.Errorf("the links of gw-1 after the new key are %v", links)
	}
}

// A mimic endpoint of a Node that is no mimic server makes no link, and a mimic server that no Node has a mimic endpoint
// of has no client.
func TestWithMimicLinksOnlyToServers(t *testing.T) {
	// gw-1 has a mimic endpoint but no section: it is dialled over mimic by no client that could have a link
	rs := mimicNetwork(mimicSection, mimicHubEndpoints)
	rs[3] = res(intent.KindNode, "gw-1", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "endpoints": [{"transport": "mimic", "address": "gw-1.example.com:8443"}]}`)
	states := mimicStates(t, reported(), rs)
	if links := mimicOf(states, "hub").GetLinks(); len(links) != 0 {
		t.Errorf("hub has the links %v, though the only peer with a mimic endpoint is no mimic server", links)
	}
	if links := mimicOf(states, "gw-2").GetLinks(); !sameLinks(links, hubLinks(mimicKey)) {
		t.Errorf("gw-2 has the links %v, want those of hub alone", links)
	}

	// hub names no endpoint of the mimic transport: its clients have no link
	states = mimicStates(t, reported(), mimicNetwork(mimicSection, `[{"transport": "quic", "address": "hub.example.com:443"}, {"transport": "tls", "address": "hub.example.com:443"}]`))
	if mimicOf(states, "hub").GetServer() == nil {
		t.Error("hub has no server settings")
	}
	for _, name := range []string{"gw-1", "gw-2"} {
		if m := mimicOf(states, name); m != nil {
			t.Errorf("%s has the mimic part %v, but hub has no mimic endpoint", name, m)
		}
	}
}

// A Node that a leak joins to the server, which shares no VRF with it, has the server as a peer with its endpoints, and gets
// its links as a peer does; a Node that no leak joins to it gets none.
func TestWithMimicLinksTheLeakedPeers(t *testing.T) {
	rs := []intent.Resource{
		res(intent.KindVRF, "shared", `{"id": 10, "ula": "fd00:10::/48", "exportTargets": ["64512:10"], "importTargets": ["64512:1"]}`),
		res(intent.KindVRF, "red", `{"id": 1, "ula": "fd00:1::/48", "exportTargets": ["64512:1"], "importTargets": ["64512:10"]}`),
		res(intent.KindVRF, "green", `{"id": 3, "ula": "fd00:3::/48"}`),
		res(intent.KindNetwork, "shared-lan", `{"vrf": "shared", "ipv4Pool": "10.10.0.0/24"}`),
		res(intent.KindNetwork, "red-lan", `{"vrf": "red", "ipv4Pool": "10.1.0.0/24"}`),
		res(intent.KindNetwork, "green-lan", `{"vrf": "green", "ipv4Pool": "10.3.0.0/24"}`),
		res(intent.KindNode, "dns", `{"publicKey": "`+key1+`", "vrfs": ["shared"], "endpoints": [{"transport": "mimic", "address": "dns.example.com:8443"}]}`),
		res(intent.KindNode, "r", `{"publicKey": "`+key2+`", "vrfs": ["red"]}`),
		res(intent.KindNode, "g", `{"publicKey": "`+key3+`", "vrfs": ["green"]}`),
		res(intent.KindListener, "edge-dns", `{"node": "dns", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}, "mimic": {"listen": ":8443",
			"serverNames": ["dns.example.com"], "decoy": {"selfSigned": true}}}`),
	}
	states := mimicStates(t, Mimic{ShortIDs: map[string][]byte{"dns": mimicID}, Keys: map[string][]byte{"dns": mimicKey}}, rs)
	want := []*controlpb.MimicLink{{Peer: "dns", Address: "dns.example.com:8443", ServerName: "dns.example.com", PublicKey: mimicKey, ShortId: mimicID}}
	if p := states["r"][Key{controlpb.Kind_KIND_PEER, "dns"}].GetPeer(); len(p.GetVrfIds()) != 0 || p == nil {
		t.Fatalf("the Peer dns of r is %v, want a peer that shares no VRF with r", p)
	}
	if got := mimicOf(states, "r").GetLinks(); !sameLinks(got, want) {
		t.Errorf("r, which a leak joins to dns, has the links %v, want %v", got, want)
	}
	if m := mimicOf(states, "g"); m != nil {
		t.Errorf("g, which no leak joins to dns, has the mimic part %v", m)
	}
}

// A Node takes MaxMimicLinks links at most, and an intent that gives one more is refused, with the name of the Node, whether
// or not the keys of the servers were reported: the number of the links does not depend on the reports.
func TestWithMimicRefusesMoreLinksThanANodeTakes(t *testing.T) {
	endpoints := func(n int) string {
		var es []string
		for i := range n {
			es = append(es, `{"transport": "mimic", "address": "s`+string(rune('0'+i))+`.example.com:8443"}`)
		}
		return "[" + strings.Join(es, ", ") + "]"
	}
	network := func(first, second int) []intent.Resource {
		listener := func(node string) string {
			return `{"node": "` + node + `", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}, "mimic": {"listen": ":8443", "serverNames": ["www.example.com"], "decoy": {"selfSigned": true}}}`
		}
		return []intent.Resource{
			res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
			res(intent.KindNode, "s1", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "endpoints": `+endpoints(first)+`}`),
			res(intent.KindNode, "s2", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "endpoints": `+endpoints(second)+`}`),
			res(intent.KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
			res(intent.KindListener, "l1", listener("s1")),
			res(intent.KindListener, "l2", listener("s2")),
		}
	}
	ids := map[string][]byte{"s1": mimicID, "s2": []byte("IJKLMNOP")}

	// 4 and 4 are 8 links, which a Node takes, and 5 and 4 are 9, which it does not
	if states := mimicStates(t, Mimic{ShortIDs: ids}, network(4, 4)); mimicOf(states, "c") != nil {
		t.Errorf("c has the mimic part %v before a key was reported", mimicOf(states, "c"))
	}
	keys := Mimic{ShortIDs: ids, Keys: map[string][]byte{"s1": mimicKey, "s2": mimicKey}}
	if got := mimicOf(mimicStates(t, keys, network(4, 4)), "c").GetLinks(); len(got) != MaxMimicLinks {
		t.Errorf("c has %d links, want %d", len(got), MaxMimicLinks)
	}
	for _, m := range []Mimic{{ShortIDs: ids}, keys} {
		in := mustApply(t, network(5, 4))
		states, err := Compile(in)
		if err != nil {
			t.Fatal(err)
		}
		err = WithMimic(in, states, m)
		if !errors.Is(err, intent.ErrInvalid) || !strings.Contains(err.Error(), `Node "c" has 9 mimic endpoints among its peers that are mimic servers, and a Node takes 8 links at most`) {
			t.Errorf("the error for 9 links is %v, want one that names Node c and the limit", err)
		}
	}
}

// A server needs a short id, and a Node that has none among the states needs nothing: a server that no state holds, which the
// licence left out, has no peer and no short id.
func TestWithMimicNeedsAShortID(t *testing.T) {
	in := mustApply(t, mimicNetwork(mimicSection, mimicHubEndpoints))
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range [][]byte{nil, mimicID[:7], append(slices.Clone(mimicID), 'x')} {
		err := WithMimic(in, states, Mimic{ShortIDs: map[string][]byte{"hub": id}})
		if err == nil || !strings.Contains(err.Error(), `Node "hub": its mimic server has no short id of 8 bytes`) {
			t.Errorf("a short id of %d bytes: the error is %v", len(id), err)
		}
	}

	delete(states, "hub")
	if err := WithMimic(in, states, Mimic{}); err != nil {
		t.Errorf("the states have no Node that is a mimic server, and WithMimic says %v", err)
	}
	if m := mimicOf(states, "gw-1"); m != nil {
		t.Errorf("gw-1 has the mimic part %v, but its server has no state", m)
	}
}

// An intent that has no mimic section leaves the states as Compile made them: the same objects, and the same NodeConfig.
func TestWithMimicLeavesOtherStatesAlone(t *testing.T) {
	rs := mimicNetwork(mimicSection, mimicHubEndpoints)
	in := mustApply(t, rs[:len(rs)-1])
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]*controlpb.Object{}
	for name, st := range states {
		before[name] = st[Key{controlpb.Kind_KIND_NODE, name}]
	}
	if err := WithMimic(in, states, reported()); err != nil {
		t.Fatal(err)
	}
	for name, st := range states {
		if st[Key{controlpb.Kind_KIND_NODE, name}] != before[name] {
			t.Errorf("the NodeConfig of %s was replaced, though no Listener has a mimic section", name)
		}
	}
}

// WithMimic copies what it puts into a state: a change of the short id or the key that it was given later, or of the
// section, changes none of the states, and two compilations of the same input are equal.
func TestWithMimicSharesNothing(t *testing.T) {
	m := Mimic{ShortIDs: map[string][]byte{"hub": slices.Clone(mimicID)}, Keys: map[string][]byte{"hub": slices.Clone(mimicKey)}}
	in := mustApply(t, mimicNetwork(mimicSection, mimicHubEndpoints))
	states, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithMimic(in, states, m); err != nil {
		t.Fatal(err)
	}
	again, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithMimic(in, again, reported()); err != nil {
		t.Fatal(err)
	}
	m.ShortIDs["hub"][0], m.Keys["hub"][0] = 'X', 'X'
	section, _ := in.MimicOf("hub")
	section.ServerNames[0] = "changed.example"
	for _, name := range []string{"hub", "gw-1", "gw-2", "lab-1"} {
		if !Equal(states[name], again[name]) {
			t.Errorf("the state of %s changed after the inputs of WithMimic were changed", name)
		}
	}
	if got := mimicOf(states, "hub").GetServer(); got.GetShortId()[0] != 'A' || got.GetServerNames()[0] != "www.example.com" {
		t.Errorf("the server of hub is %v, want what it was given", got)
	}
}
