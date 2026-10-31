package intent

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// stretchBase is an intent for the Stretches of the tests: VRF dc with the L2 Networks dc-l2 and dc-l2b, the L3 Network dc-l3 and
// the Nodes gw-1, gw-2 and lan-1, and VRF lab with the L2 Network lab-l2 and the Node lab-1.
func stretchBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "dc", `{"id": 30, "ula": "fd30:1:2::/48"}`),
		res(KindVRF, "lab", `{"id": 40, "ula": "fd40:1:2::/48"}`),
		res(KindNetwork, "dc-l2", `{"vrf": "dc", "mode": "L2"}`),
		res(KindNetwork, "dc-l2b", `{"vrf": "dc", "mode": "L2"}`),
		res(KindNetwork, "dc-l3", `{"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}`),
		res(KindNetwork, "lab-l2", `{"vrf": "lab", "mode": "L2"}`),
		res(KindNode, "gw-1", `{"publicKey": "`+key1+`", "vrfs": ["dc"]}`),
		res(KindNode, "gw-2", `{"publicKey": "`+key2+`", "vrfs": ["dc"]}`),
		res(KindNode, "lan-1", `{"publicKey": "`+key3+`", "vrfs": ["dc"]}`),
		res(KindNode, "lab-1", `{"publicKey": "`+key4+`", "vrfs": ["lab"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// stretchFields is the spec of a Stretch of gw-1 and dc-l2 without its closing brace, to which a test adds fields.
const stretchFields = `{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]`

// A Stretch gets the defaults of the ticket for what it leaves out, in the one form of its route targets and its ESI, and keeps
// what it declares. The Stretches read back from the resources, last, and an import of a document without one takes it away.
func TestApplyStretch(t *testing.T) {
	in, err := Apply(stretchBase(t), doc(res(KindStretch, "dc-stretch",
		`{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010", "64512:10", "192.0.2.1:7"], "esi": "AA:bb:cc:dd:ee:ff:00:11:22:33"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Stretch{Gateway: "gw-1", Network: "dc-l2", VNI: 5010, RouteTargets: []string{"192.0.2.1:7", "64512:10", "65000:5010"}, ESI: "aa:bb:cc:dd:ee:ff:00:11:22:33",
		BUMRateLimit: DefaultBUMRateLimit, MACImportLimit: 10000, StaleTimer: 120}
	if got := in.Stretches["dc-stretch"]; !reflect.DeepEqual(got, want) {
		t.Errorf("the completed Stretch is %+v, want %+v", got, want)
	}

	// What a Stretch declares stays, and a second apply keeps the Stretch it changes in place
	again, err := Apply(in, doc(res(KindStretch, "dc-stretch",
		`{"gateway": "gw-1", "network": "dc-l2", "vni": 5011, "routeTargets": ["65000:5011"], "bumRateLimit": 1000000, "macImportLimit": 500, "staleTimer": 30, "irb": true}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	want = Stretch{Gateway: "gw-1", Network: "dc-l2", VNI: 5011, RouteTargets: []string{"65000:5011"}, BUMRateLimit: 1000000, MACImportLimit: 500, StaleTimer: 30, IRB: true}
	if got := again.Stretches["dc-stretch"]; len(again.Stretches) != 1 || !reflect.DeepEqual(got, want) {
		t.Errorf("the changed Stretch is %+v among %d, want %+v alone", got, len(again.Stretches), want)
	}
	if got := in.Stretches["dc-stretch"]; got.VNI != 5010 {
		t.Errorf("the apply that changed the Stretch changed the intent it started from: %+v", got)
	}

	// The Stretches come after the Devices in the resources, and read back as they were
	rs := in.Resources()
	if last := rs[len(rs)-1]; last.Kind != KindStretch || last.Name != "dc-stretch" {
		t.Errorf("the last resource is %s %q, want Stretch \"dc-stretch\"", last.Kind, last.Name)
	}
	if kindOrder(KindStretch) <= kindOrder(KindDevice) {
		t.Error("a Stretch is not ordered after the Devices")
	}
	back, err := FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Stretches["dc-stretch"]; !reflect.DeepEqual(got, in.Stretches["dc-stretch"]) {
		t.Errorf("the Stretch read back is %+v, want %+v", got, in.Stretches["dc-stretch"])
	}

	// An import of a document without the Stretch takes it away
	var rest []Resource
	for _, r := range rs {
		if r.Kind != KindStretch {
			rest = append(rest, r)
		}
	}
	next, err := Replace(in, Document{Resources: rest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Stretches) != 0 {
		t.Errorf("after the import the Stretches are %+v, want none", next.Stretches)
	}

	// The diff between two intents names the Stretch that changed
	put, gone := Changed(in, again)
	if len(put) != 1 || put[0].Kind != KindStretch || len(gone) != 0 {
		t.Errorf("the change from the first Stretch to the second is put %+v, gone %+v, want the Stretch alone", put, gone)
	}
}

// A Stretch that is not whole, or that binds what it cannot, is refused with the name of what is wrong, and a refused apply
// changes nothing.
func TestApplyStretchRejects(t *testing.T) {
	base := stretchBase(t)
	nine := `["65000:1", "65000:2", "65000:3", "65000:4", "65000:5", "65000:6", "65000:7", "65000:8", "65000:9"]`
	for _, c := range []struct {
		spec string
		want string
	}{
		{`{"gateway": "nope", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`, `Stretch "s": Node "nope" does not exist`},
		{`{"network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`, `Stretch "s": Node "" does not exist`},
		{`{"gateway": "gw-1", "network": "nope", "vni": 5010, "routeTargets": ["65000:5010"]}`, `Stretch "s": Network "nope" does not exist`},
		{`{"gateway": "gw-1", "network": "dc-l3", "vni": 5010, "routeTargets": ["65000:5010"]}`, `Stretch "s": Network "dc-l3" is of mode L3, and only an L2 Network is stretched`},
		{`{"gateway": "lab-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`, `Stretch "s": Node "lab-1" is no member of VRF "dc", the VRF of Network "dc-l2"`},
		{`{"gateway": "gw-1", "network": "dc-l2", "routeTargets": ["65000:5010"]}`, `Stretch "s": vni 0 is not between 1 and 16777215`},
		{`{"gateway": "gw-1", "network": "dc-l2", "vni": 16777216, "routeTargets": ["65000:5010"]}`, `Stretch "s": vni 16777216 is not between 1 and 16777215`},
		{`{"gateway": "gw-1", "network": "dc-l2", "vni": 5010}`, `Stretch "s": routeTargets needs at least one route target`},
		{`{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ` + nine + `}`, `Stretch "s": routeTargets holds 9 route targets, at most 8`},
		{`{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["dc"]}`, `Stretch "s": routeTargets: route target "dc" is not ASN:NUMBER or IPV4:NUMBER`},
		{`{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:1", "65000:1"]}`, `Stretch "s": routeTargets lists the route target 65000:1 twice`},
		{stretchFields + `, "esi": "00:11"}`, `Stretch "s": esi "00:11" is not 10 octets of two hexadecimal digits separated by colons`},
		{stretchFields + `, "esi": "00:11:22:33:44:55:66:77:88:9g"}`, `is not 10 octets of two hexadecimal digits`},
		{stretchFields + `, "esi": "00:00:00:00:00:00:00:00:00:00"}`, `Stretch "s": esi "00:00:00:00:00:00:00:00:00:00" is all zeros`},
		{stretchFields + `, "macImportLimit": 1048577}`, `Stretch "s": macImportLimit 1048577 is above 1048576`},
		{stretchFields + `, "staleTimer": 3601}`, `Stretch "s": staleTimer 3601 is above 3600 seconds`},
		{stretchFields + `, "colour": "red"}`, `Stretch "s": spec: json: unknown field "colour"`},
	} {
		next, err := Apply(base, doc(res(KindStretch, "s", c.spec)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
		if len(next.Stretches) != 0 {
			t.Errorf("%s: a failed apply changed the intent", c.spec)
		}
	}
	// The names of a Stretch follow the rule of every name
	if _, err := Apply(base, doc(res(KindStretch, "-s", stretchFields+`}`)), nil); err == nil || !strings.Contains(err.Error(), `Stretch "-s": the name must be`) {
		t.Errorf("a Stretch named -s: %v", err)
	}
}

// The refusals that name the Node and the Network: a VNI that a gateway carries for two Networks, a Network that two gateways
// stretch without the ESI, a Stretch of a Network that has a bridge, a Network stretched twice at one gateway.
func TestStretchRefusalsNameTheNodeAndTheNetwork(t *testing.T) {
	base := stretchBase(t)
	a := `{"gateway": "gw-1", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]`

	// One VNI at one gateway for two Networks; the same VNI at two gateways, and two VNIs at one, are fine
	_, err := Apply(base, doc(res(KindStretch, "a", a+`}`),
		res(KindStretch, "b", `{"gateway": "gw-1", "network": "dc-l2b", "vni": 5010, "routeTargets": ["65000:5010"]}`)), nil)
	want := `Stretch "b": Node "gw-1" carries vni 5010 for Network "dc-l2" already (Stretch "a"), so it cannot carry it for Network "dc-l2b" too`
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("a VNI at a gateway for two Networks: %v, want an error with %q", err, want)
	}
	for _, b := range []string{`{"gateway": "gw-2", "network": "dc-l2b", "vni": 5010, "routeTargets": ["65000:5010"]}`,
		`{"gateway": "gw-1", "network": "dc-l2b", "vni": 5011, "routeTargets": ["65000:5011"]}`} {
		if _, err := Apply(base, doc(res(KindStretch, "a", a+`}`), res(KindStretch, "b", b)), nil); err != nil {
			t.Errorf("the Stretches %s and %s: %v, want them applied", a, b, err)
		}
	}

	// A Network that two gateways stretch needs the ESI in both
	b := `{"gateway": "gw-2", "network": "dc-l2", "vni": 5010, "routeTargets": ["65000:5010"]`
	_, err = Apply(base, doc(res(KindStretch, "a", a+`}`), res(KindStretch, "b", b+`}`)), nil)
	for _, want := range []string{
		`Stretch "a": Network "dc-l2" is stretched at the Nodes "gw-1", "gw-2" and Node "gw-1" has no esi`,
		`Stretch "b": Network "dc-l2" is stretched at the Nodes "gw-1", "gw-2" and Node "gw-2" has no esi`,
	} {
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
			t.Errorf("two gateways and no ESI: %v, want an error with %q", err, want)
		}
	}
	_, err = Apply(base, doc(res(KindStretch, "a", a+`, "esi": "00:11:22:33:44:55:66:77:88:99"}`), res(KindStretch, "b", b+`}`)), nil)
	if want := `Stretch "b": Network "dc-l2" is stretched at the Nodes "gw-1", "gw-2" and Node "gw-2" has no esi`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("two gateways and the ESI at one: %v, want an error with %q", err, want)
	}
	if err != nil && strings.Contains(err.Error(), `Node "gw-1" has no esi`) {
		t.Errorf("the error names gw-1, whose Stretch has the ESI: %v", err)
	}
	pair, err := Apply(base, doc(res(KindStretch, "a", a+`, "esi": "00:11:22:33:44:55:66:77:88:99"}`), res(KindStretch, "b", b+`, "esi": "00:11:22:33:44:55:66:77:88:99"}`)), nil)
	if err != nil || len(pair.Stretches) != 2 {
		t.Errorf("two gateways that share the ESI: %v, want both applied", err)
	}

	// A Network is stretched at one gateway once
	_, err = Apply(base, doc(res(KindStretch, "a", a+`}`), res(KindStretch, "b", `{"gateway": "gw-1", "network": "dc-l2", "vni": 5011, "routeTargets": ["65000:5011"]}`)), nil)
	want = `Stretch "b": Network "dc-l2" is already stretched at Node "gw-1" by Stretch "a"`
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("a Network stretched twice at a gateway: %v, want an error with %q", err, want)
	}

	// A Network with a Stretch has no bridge but its gateways: whichever comes second is refused
	bridge, err := Apply(base, doc(res(KindNode, "lan-1", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "roles": ["bridge", "server"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := bridge.Nodes["lan-1"].Roles; !slices.Equal(got, []string{"bridge", "server"}) {
		t.Errorf("the roles of lan-1 are %v, want bridge and server", got)
	}
	want = `Stretch "a": Network "dc-l2" has Node "lan-1", which has the role bridge and is no gateway of the Stretch (gateways: "gw-1")`
	if _, err = Apply(bridge, doc(res(KindStretch, "a", a+`}`)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("a Stretch of a Network with a bridge: %v, want an error with %q", err, want)
	}
	stretched, err := Apply(base, doc(res(KindStretch, "a", a+`}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(stretched, doc(res(KindNode, "lan-1", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "roles": ["bridge"]}`)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Errorf("a bridge in a Network with a Stretch: %v, want an error with %q", err, want)
	}
	// The gateway may be the bridge, a bridge outside the VRF of the Network is no bridge of it, and so is a Network with no Stretch
	for _, c := range []struct {
		why  string
		node Resource
	}{
		{"the gateway itself", res(KindNode, "gw-1", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "roles": ["bridge"]}`)},
		{"a node of another VRF", res(KindNode, "lab-1", `{"publicKey": "`+key4+`", "vrfs": ["lab"], "roles": ["bridge"]}`)},
	} {
		if _, err := Apply(stretched, doc(c.node), nil); err != nil {
			t.Errorf("a bridge that is %s: %v, want it applied", c.why, err)
		}
	}
	if _, err := Apply(bridge, doc(res(KindStretch, "b", `{"gateway": "lab-1", "network": "lab-l2", "vni": 5010, "routeTargets": ["65000:5010"]}`)), nil); err != nil {
		t.Errorf("a Stretch of lab-l2, whose VRF has no bridge: %v, want it applied", err)
	}
	// Two gateways of a Network may both be bridges: each is a gateway of the Stretch of the Network
	both, err := Apply(base, doc(res(KindNode, "gw-1", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "roles": ["bridge"]}`),
		res(KindNode, "gw-2", `{"publicKey": "`+key2+`", "vrfs": ["dc"], "roles": ["bridge"]}`),
		res(KindStretch, "a", a+`, "esi": "00:11:22:33:44:55:66:77:88:99"}`), res(KindStretch, "b", b+`, "esi": "00:11:22:33:44:55:66:77:88:99"}`)), nil)
	if err != nil || len(both.Stretches) != 2 {
		t.Errorf("two gateways that are bridges and share the ESI: %v, want both applied", err)
	}
}

// The Roles of a Node are the four of ADR-0011, each once, and the Controller keeps them in order.
func TestNodeRoles(t *testing.T) {
	base := stretchBase(t)
	in, err := Apply(base, doc(res(KindNode, "lan-1", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "roles": ["relay", "client", "bridge", "server"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := in.Nodes["lan-1"].Roles, []string{"bridge", "client", "relay", "server"}; !slices.Equal(got, want) {
		t.Errorf("the roles are %v, want %v", got, want)
	}
	if len(base.Nodes["lan-1"].Roles) != 0 {
		t.Errorf("the apply gave a Node of the intent it started from the roles %v", base.Nodes["lan-1"].Roles)
	}
	for _, c := range []struct {
		roles, want string
	}{
		{`["router"]`, `Node "lan-1": the role must be server, client, bridge or relay, not "router"`},
		{`["bridge", "bridge"]`, `Node "lan-1": role "bridge" is listed twice`},
		{`["Bridge"]`, `not "Bridge"`},
	} {
		_, err := Apply(base, doc(res(KindNode, "lan-1", `{"publicKey": "`+key3+`", "vrfs": ["dc"], "roles": `+c.roles+`}`)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("the roles %s: the error is %v, want one with %q", c.roles, err, c.want)
		}
	}
}

// A Network that a Stretch binds and a Node that is the gateway of one cannot be deleted; the Stretch can, and then they can.
func TestDeleteStretch(t *testing.T) {
	in, err := Apply(stretchBase(t), doc(res(KindStretch, "s", stretchFields+`}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindNetwork, "dc-l2"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Network "dc-l2" is used by Stretch "s"`) {
		t.Errorf("deleting the Network of a Stretch: %v", err)
	}
	if _, err := Delete(in, KindNode, "gw-1"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "gw-1" is the gateway of Stretch "s"`) {
		t.Errorf("deleting the gateway of a Stretch: %v", err)
	}
	if _, err := Delete(in, KindStretch, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a Stretch that does not exist: %v", err)
	}
	// A Network and a Node that no Stretch binds go as before
	if _, err := Delete(in, KindNetwork, "dc-l2b"); err != nil {
		t.Errorf("deleting a Network that no Stretch binds: %v", err)
	}
	if _, err := Delete(in, KindNode, "gw-2"); err != nil {
		t.Errorf("deleting a Node that is no gateway: %v", err)
	}
	next, err := Delete(in, KindStretch, "s")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Stretches) != 0 || len(in.Stretches) != 1 {
		t.Errorf("after the delete the Stretches are %v, and the intent it started from has %v", next.Stretches, in.Stretches)
	}
	for _, c := range []struct{ kind, name string }{{KindNetwork, "dc-l2"}, {KindNode, "gw-1"}} {
		if _, err := Delete(next, c.kind, c.name); err != nil {
			t.Errorf("deleting %s %q once its Stretch is gone: %v", c.kind, c.name, err)
		}
	}
	// A Node that leaves the VRF of the Network of its Stretch is refused as well
	if _, err := Apply(in, doc(res(KindNode, "gw-1", `{"publicKey": "`+key1+`", "vrfs": ["lab"]}`)), nil); err == nil ||
		!strings.Contains(err.Error(), `Stretch "s": Node "gw-1" is no member of VRF "dc", the VRF of Network "dc-l2"`) {
		t.Errorf("moving the gateway of a Stretch out of the VRF of its Network: %v", err)
	}
}

// WithoutStretches leaves the intent it was given as it is, and Clone shares no route target with it.
func TestWithoutStretches(t *testing.T) {
	in, err := Apply(stretchBase(t), doc(res(KindNode, "gw-1", `{"publicKey": "`+key1+`", "vrfs": ["dc"], "roles": ["bridge"]}`), res(KindStretch, "s", stretchFields+`}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	without := in.WithoutStretches()
	if len(without.Stretches) != 0 || len(in.Stretches) != 1 {
		t.Errorf("WithoutStretches has %d Stretches and left %d in the intent, want 0 and 1", len(without.Stretches), len(in.Stretches))
	}
	if len(without.Nodes) != len(in.Nodes) || len(without.Networks) != len(in.Networks) {
		t.Errorf("WithoutStretches changed the Nodes or the Networks: %d and %d of %d and %d", len(without.Nodes), len(without.Networks), len(in.Nodes), len(in.Networks))
	}
	if again := without.WithoutStretches(); len(again.Stretches) != 0 {
		t.Errorf("an intent without Stretches has %d after WithoutStretches", len(again.Stretches))
	}

	clone := in.Clone()
	s := clone.Stretches["s"]
	s.RouteTargets[0] = "65000:1"
	if got := in.Stretches["s"].RouteTargets[0]; got != "65000:5010" {
		t.Errorf("a route target of the clone changed the intent: %s", got)
	}
	n := clone.Nodes["gw-1"]
	n.Roles[0] = RoleRelay
	if got := in.Nodes["gw-1"].Roles[0]; got != RoleBridge {
		t.Errorf("a role of the clone changed the intent: %s", got)
	}
}

// ParseESI takes ten octets in either case and gives them back in lower case, and refuses what is not ten, or is not hexadecimal,
// or is all zeros, the identifier of a single-homed site.
func TestParseESI(t *testing.T) {
	esi, err := ParseESI("00:AB:cd:03:04:05:06:07:08:ff")
	if err != nil || !slices.Equal(esi, []byte{0x00, 0xab, 0xcd, 3, 4, 5, 6, 7, 8, 0xff}) {
		t.Errorf("ParseESI gave %x, %v", esi, err)
	}
	if got := formatESI(esi); got != "00:ab:cd:03:04:05:06:07:08:ff" {
		t.Errorf("the ESI is written as %s", got)
	}
	for _, s := range []string{"", "00", "00:11:22:33:44:55:66:77:88", "00:11:22:33:44:55:66:77:88:99:aa", "0:1:2:3:4:5:6:7:8:9", "000:11:22:33:44:55:66:77:88:99",
		"00-11-22-33-44-55-66-77-88-99", "00:11:22:33:44:55:66:77:88:zz", "+1:11:22:33:44:55:66:77:88:99", "00:00:00:00:00:00:00:00:00:00"} {
		if esi, err := ParseESI(s); err == nil {
			t.Errorf("ParseESI(%q) = %x, want an error", s, esi)
		}
	}
	for _, s := range []string{"ff:ff:ff:ff:ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00:00:00:00:01"} {
		if _, err := ParseESI(s); err != nil {
			t.Errorf("ParseESI(%q): %v", s, err)
		}
	}
	// A Stretch that has the largest limits the intent allows is whole
	spec := fmt.Sprintf(`{"gateway": "gw-1", "network": "dc-l2", "vni": %d, "routeTargets": ["65000:1"], "macImportLimit": %d, "staleTimer": %d}`, MaxVNI, MaxMACImportLimit, MaxStaleTimer)
	if _, err := Apply(stretchBase(t), doc(res(KindStretch, "s", spec)), nil); err != nil {
		t.Errorf("a Stretch with the largest VNI and limits: %v", err)
	}
}
