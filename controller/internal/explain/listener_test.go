package explain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The explanation of a Listener (SDN-94 #423, listener.go): the mimic section, whether the Node reported the public key of its
// mimic server, and the Nodes that have a link to the server, which the desired states hold.

var (
	listenerShortID = []byte("ABCDEFGH")
	listenerKey     = []byte("0123456789abcdef0123456789abcdef")
)

// listenerResources are a mimic server hub, whose Listener edge-hub has a mimic section and whose endpoints are hubEndpoints,
// two clients that share VRF corp with it, gw-1 and gw-2, and lab-1, which shares none. The Listener of gw-1 has no section.
func listenerResources(hubEndpoints string) []intent.Resource {
	res := func(kind, name, spec string) intent.Resource {
		return intent.Resource{Kind: kind, Name: name, Spec: json.RawMessage(spec)}
	}
	return []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(intent.KindNode, "hub", `{"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "endpoints": `+hubEndpoints+`}`),
		res(intent.KindNode, "gw-1", `{"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["corp"]}`),
		res(intent.KindNode, "gw-2", `{"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["corp"]}`),
		res(intent.KindNode, "lab-1", `{"publicKey": "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc=", "vrfs": ["lab"]}`),
		res(intent.KindListener, "edge-hub", `{"node": "hub", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}, "mimic": {"listen": ":8443",
			"serverNames": ["www.example.com", "cdn.example.com"], "maxTimeDiffMs": 5000, "decoy": {"acme": {"cacheDir": "C:\\ProgramData\\Ranz\\mimic-acme"}}}}`),
		res(intent.KindListener, "edge-gw-1", `{"node": "gw-1", "certificate": {"ksp": "00112233445566778899AABBCCDDEEFF00112233"}}`),
	}
}

const listenerMimicEndpoints = `[{"transport": "quic", "address": "hub.example.com:443"}, {"transport": "mimic", "address": "hub.example.com:8443"}]`

// listenerStates returns the intent of listenerResources and its desired states, with the mimic part that the Controller makes
// when the Node of hub reported key, none when it is nil.
func listenerStates(t *testing.T, hubEndpoints string, key []byte) (intent.Intent, map[string]desired.State) {
	t.Helper()
	in, err := intent.Apply(intent.New(), intent.Document{Resources: listenerResources(hubEndpoints)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	states, err := desired.Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	m := desired.Mimic{ShortIDs: map[string][]byte{"hub": listenerShortID}}
	if key != nil {
		m.Keys = map[string][]byte{"hub": key}
	}
	if err := desired.WithMimic(in, states, m); err != nil {
		t.Fatal(err)
	}
	return in, states
}

// Before the Node of the server reported its public key, the Controller waits for it: the answer says so, names the Nodes that
// will have a link and have none, and lists none as linked.
func TestListenerWaitsForTheKey(t *testing.T) {
	in, states := listenerStates(t, listenerMimicEndpoints, nil)
	res, err := Listener(in, states, "edge-hub", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Listener != "edge-hub" || res.Node != "hub" || res.Mimic == nil || res.Mimic.Listen != ":8443" || len(res.Mimic.ServerNames) != 2 {
		t.Errorf("the answer is %+v, want the Listener edge-hub of hub with its mimic section", res)
	}
	if res.KeyReported || res.PublicKey != "" {
		t.Errorf("the answer says that the key was reported: %+v", res)
	}
	if !strings.Contains(res.Waiting, "the Controller waits for the public key of Node hub") {
		t.Errorf("the answer waits for %q, want the public key of Node hub", res.Waiting)
	}
	if len(res.Links) != 0 || res.Links == nil {
		t.Errorf("the links are %#v, want an empty list that is no null", res.Links)
	}
	if !slices.Equal(res.Unlinked, []string{"gw-1", "gw-2"}) || !slices.Equal(res.MimicEndpoints, []string{"hub.example.com:8443"}) {
		t.Errorf("the Nodes without a link are %v and the mimic endpoints %v, want gw-1 and gw-2, and hub.example.com:8443", res.Unlinked, res.MimicEndpoints)
	}
}

// Once the key is reported, each Node that has the server as a peer with a mimic endpoint has its link, in the order of the Nodes,
// and the answer holds the key in hex and waits for nothing.
func TestListenerShowsTheLinks(t *testing.T) {
	in, states := listenerStates(t, listenerMimicEndpoints, listenerKey)
	res, err := Listener(in, states, "edge-hub", listenerKey)
	if err != nil {
		t.Fatal(err)
	}
	if !res.KeyReported || res.PublicKey != hex.EncodeToString(listenerKey) || res.Waiting != "" || len(res.Unlinked) != 0 {
		t.Errorf("the answer is %+v, want the key reported, in hex, and nothing to wait for", res)
	}
	want := []ListenerLink{{Node: "gw-1", Address: "hub.example.com:8443", ServerName: "www.example.com"}, {Node: "gw-2", Address: "hub.example.com:8443", ServerName: "www.example.com"}}
	if !reflect.DeepEqual(res.Links, want) {
		t.Errorf("the links are %+v, want %+v", res.Links, want)
	}

	// The answer is the JSON of the API: it reads back as it was, with the section as the operator wrote it
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back ListenerResult
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, res) {
		t.Errorf("the answer %s reads back as %+v (%v), want %+v", b, back, err, res)
	}
	for _, want := range []string{`"keyReported":true`, `"serverNames":["www.example.com","cdn.example.com"]`, `"cacheDir":"C:\\ProgramData\\Ranz\\mimic-acme"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the JSON %s does not hold %s", b, want)
		}
	}
}

// A key that is no key of 32 bytes is no report. A Listener that has no mimic section has nothing to explain, and a name that
// is no Listener is not found. A server whose Node has no desired state, which the licence left out, says so.
func TestListenerOtherAnswers(t *testing.T) {
	in, states := listenerStates(t, listenerMimicEndpoints, listenerKey)
	res, err := Listener(in, states, "edge-hub", listenerKey[:31])
	if err != nil || res.KeyReported || res.PublicKey != "" || !strings.Contains(res.Waiting, "waits for the public key") {
		t.Errorf("a key of 31 bytes: %+v (%v), want a key that is not reported", res, err)
	}

	res, err = Listener(in, states, "edge-gw-1", nil)
	if err != nil || res.Mimic != nil || res.Node != "gw-1" || res.Waiting != "" || len(res.Links) != 0 || len(res.Unlinked) != 0 {
		t.Errorf("a Listener without a mimic section: %+v (%v), want its Node and nothing else", res, err)
	}

	if _, err := Listener(in, states, "nowhere", nil); !errors.Is(err, intent.ErrNotFound) || !strings.Contains(err.Error(), `Listener "nowhere"`) {
		t.Errorf("a name that is no Listener: %v, want an error that wraps ErrNotFound and names it", err)
	}

	delete(states, "hub")
	res, err = Listener(in, states, "edge-hub", listenerKey)
	if err != nil || !res.KeyReported || !strings.Contains(res.Waiting, "Node hub has no desired state") || len(res.Links) != 0 {
		t.Errorf("a server whose Node has no state: %+v (%v), want a note that it has none", res, err)
	}
}

// A server whose Node names no endpoint of the mimic transport has no client: no Node has a link, and none is waiting for one,
// and the answer lists no endpoint.
func TestListenerWithoutAMimicEndpoint(t *testing.T) {
	in, states := listenerStates(t, `[{"transport": "quic", "address": "hub.example.com:443"}]`, listenerKey)
	res, err := Listener(in, states, "edge-hub", listenerKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MimicEndpoints) != 0 || len(res.Links) != 0 || len(res.Unlinked) != 0 || !res.KeyReported {
		t.Errorf("the answer is %+v, want a reported key, no mimic endpoint, no link and no Node that waits for one", res)
	}
}
