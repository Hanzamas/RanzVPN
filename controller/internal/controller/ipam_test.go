// Controller conformance for IPAM (ADR-0028, SDN-10 #186), with the harness and the node
// simulator of conformance_test.go: the controller alone allocates the addresses of the overlay,
// from the pools of each VRF; a Node gets them only from the pools of its own VRFs and the
// reservations are honoured; a gateway LAN subnet is a route and never an allocation; an event
// fires at the threshold of a pool; and no DHCP runs inside the overlay.
package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// stateAddresses returns the addresses that the state of the simulated node s holds: one line for
// the node itself, "self", and one for each of its peers, "peer NAME", each with the addresses as
// "network vrf prefix", comma-separated.
func stateAddresses(s *sim) []string {
	_, st := s.State()
	var out []string
	for _, o := range st.Objects() {
		switch k := o.GetKind().(type) {
		case *controlpb.Object_Node:
			out = append(out, "self "+addressLine(k.Node.GetAddresses()))
		case *controlpb.Object_Peer:
			out = append(out, "peer "+k.Peer.GetName()+" "+addressLine(k.Peer.GetAddresses()))
		}
	}
	return out
}

func addressLine(addresses []*controlpb.Address) string {
	var out []string
	for _, a := range addresses {
		ip, _ := netip.AddrFromSlice(a.GetPrefix().GetAddress())
		out = append(out, fmt.Sprintf("%s %d %s", a.GetNetwork(), a.GetVrfId(), netip.PrefixFrom(ip, int(a.GetPrefix().GetLength()))))
	}
	return strings.Join(out, ", ")
}

// poolLines writes each pool as a line: its Network and prefix, how many addresses it has, how
// many Nodes hold and the Network reserves, how many are free, how full it is and its threshold.
func poolLines(pools []intent.PoolUse) string {
	var out []string
	for _, u := range pools {
		out = append(out, fmt.Sprintf("%s %s size=%d allocated=%d reserved=%d free=%d percent=%d threshold=%d near=%v",
			u.Network, u.Pool, u.Size, u.Allocated, u.Reserved, u.Free, u.Percent, u.Threshold, u.NearExhaustion))
	}
	return strings.Join(out, "\n")
}

// routeLines writes each route as a line: its VRF, its prefix and the gateway Node.
func routeLines(routes []intent.Route) string {
	var out []string
	for _, r := range routes {
		out = append(out, r.VRF+" "+r.Prefix.String()+" via "+r.Via)
	}
	return strings.Join(out, "\n")
}

// ipamNode returns the Node resource name with the static key key and the members of its spec in
// spec.
func ipamNode(name string, key *keys.Soft, spec string) intent.Resource {
	b := fmt.Sprintf(`{"publicKey": %q, %s}`, base64.StdEncoding.EncodeToString(key.Public()), spec)
	return intent.Resource{Kind: intent.KindNode, Name: name, Spec: json.RawMessage(b)}
}

// checkRefused checks that err is a refusal of the intent, 400 Bad Request, that says want.
func checkRefused(t *testing.T, err error, want string) {
	t.Helper()
	var e *api.Error
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest || !strings.Contains(e.Message, want) {
		t.Errorf("the answer is %v, want 400 Bad Request with %q", err, want)
	}
}

// TestNodesGetAddressesOnlyFromTheirVRFPool is the first criterion of #186: the Nodes of a VRF get
// their IPv4 and IPv6 addresses from the pools of that VRF and no other, also where two VRFs use
// the same IPv4 range; a reservation that a Node declares is its own, and one that a Network makes
// is given to no Node, also when a Node joins later.
func TestNodesGetAddressesOnlyFromTheirVRFPool(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("ipam-pools.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	lab := h.sim("lab-1", keyLab1)
	for _, s := range []*sim{b1, b2, lab} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	// branch-1 comes first in name order, and gets the first address past the 7 that corp-lan
	// reserves; branch-2 holds what it declared; lab-1 gets the first address of the same IPv4
	// range in lab, and no node of corp sees it, nor it a node of corp
	for _, c := range []struct {
		sim  *sim
		want []string
	}{
		{b1, []string{
			"self corp-lan 10 10.10.0.8/24, corp-lan 10 fd12:3456:789a:1::1/64",
			"peer branch-2 corp-lan 10 10.10.0.50/24, corp-lan 10 fd12:3456:789a:1::50/64",
		}},
		{b2, []string{
			"self corp-lan 10 10.10.0.50/24, corp-lan 10 fd12:3456:789a:1::50/64",
			"peer branch-1 corp-lan 10 10.10.0.8/24, corp-lan 10 fd12:3456:789a:1::1/64",
		}},
		{lab, []string{
			"self lab-lan 20 10.10.0.1/24, lab-lan 20 fd12:3456:789b:1::1/64",
		}},
	} {
		if got := stateAddresses(c.sim); !slices.Equal(got, c.want) {
			t.Errorf("%s holds the addresses\n%s\nwant\n%s", c.sim.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
	rep, err := h.api.IPAM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := "corp-lan 10.10.0.0/24 size=254 allocated=2 reserved=7 free=245 percent=3 threshold=80 near=false\n" +
		"corp-lan fd12:3456:789a:1::/64 size=9007199254740992 allocated=2 reserved=0 free=9007199254740990 percent=0 threshold=80 near=false\n" +
		"lab-lan 10.10.0.0/24 size=254 allocated=1 reserved=0 free=253 percent=0 threshold=80 near=false\n" +
		"lab-lan fd12:3456:789b:1::/64 size=9007199254740992 allocated=1 reserved=0 free=9007199254740991 percent=0 threshold=80 near=false"
	if got := poolLines(rep.Pools); got != want {
		t.Errorf("the pools are\n%s\nwant\n%s", got, want)
	}

	// A Node that joins corp later gets the next free address of each pool, past the ones held
	// and the ones reserved; a declared address that is held or reserved is refused
	if _, err := h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("aaa", nodeKey(1), `"vrfs": ["corp"]`)}}); err != nil {
		t.Fatal(err)
	}
	rs, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Nodes["aaa"].Addresses["corp-lan"] + " " + in.Nodes["aaa"].IPv6Addresses["corp-lan"]; got != "10.10.0.9 fd12:3456:789a:1::2" {
		t.Errorf("aaa, which joined later and comes first in name order, holds %q, want the next free address of each pool", got)
	}
	before := h.resources()
	_, err = h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("bbb", nodeKey(2), `"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.50"}`)}})
	checkRefused(t, err, `address 10.10.0.50 of Network "corp-lan" is already the address of Node "branch-2"`)
	_, err = h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("bbb", nodeKey(2), `"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.3"}`)}})
	checkRefused(t, err, `address 10.10.0.3 of Network "corp-lan" is reserved by the Network`)
	_, err = h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("bbb", nodeKey(2), `"vrfs": ["corp"], "ipv6Addresses": {"corp-lan": "fd12:3456:789b:1::5"}`)}})
	checkRefused(t, err, `is not a host address of the pool fd12:3456:789a:1::/64 of Network "corp-lan"`)
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
}

// TestGatewayLANSubnetIsARouteNotAnAllocation is the second criterion of #186: the LAN subnet
// behind a gateway Node is a route that the controller reports, and never an allocation: no Node
// holds an address in it, no pool may cover it, and a Node cannot declare an address in it. A
// second gateway may advertise the same subnet.
func TestGatewayLANSubnetIsARouteNotAnAllocation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("ipam-gateway.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	for _, s := range []*sim{b1, b2} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	for _, c := range []struct {
		sim  *sim
		want []string
	}{
		{b1, []string{"self corp-lan 10 10.10.0.1/24", "peer branch-2 corp-lan 10 10.10.0.2/24"}},
		{b2, []string{"self corp-lan 10 10.10.0.2/24", "peer branch-1 corp-lan 10 10.10.0.1/24"}},
	} {
		got := stateAddresses(c.sim)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s holds the addresses\n%s\nwant\n%s", c.sim.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
		if all := strings.Join(got, "\n"); strings.Contains(all, "192.168.1.") {
			t.Errorf("%s holds an address in the LAN subnet 192.168.1.0/24, which branch-1 advertises:\n%s", c.sim.name, all)
		}
	}
	rep, err := h.api.IPAM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := routeLines(rep.Routes), "corp 192.168.1.0/24 via branch-1"; got != want {
		t.Errorf("the routes are %q, want %q", got, want)
	}
	if got, want := poolLines(rep.Pools), "corp-lan 10.10.0.0/24 size=254 allocated=2 reserved=0 free=252 percent=0 threshold=80 near=false"; got != want {
		t.Errorf("the pools are %q, want %q: the LAN subnet is no pool", got, want)
	}

	// No pool covers the subnet, and no Node declares an address in it
	before := h.resources()
	_, err = h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindNetwork, Name: "office", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "192.168.1.0/25"}`)},
	}})
	checkRefused(t, err, `Network "office": the pool 192.168.1.0/25 overlaps the LAN subnet 192.168.1.0/24 that Node "branch-1" advertises in VRF "corp": a LAN subnet is a route and never an allocation`)
	_, err = h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("lab-gw", keyLab1, `"vrfs": ["corp"], "addresses": {"corp-lan": "192.168.1.10"}`)}})
	checkRefused(t, err, `Node "lab-gw": address 192.168.1.10 is not a host address of the pool 10.10.0.0/24 of Network "corp-lan"`)
	if after := h.resources(); after != before {
		t.Errorf("a refused apply changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}

	// A second gateway advertises the same subnet: two routes, and still no allocation
	if _, err := h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{ipamNode("lab-gw", keyLab1, `"vrfs": ["corp"], "lanSubnets": {"corp": ["192.168.1.0/24"]}`)}}); err != nil {
		t.Fatal(err)
	}
	if rep, err = h.api.IPAM(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := routeLines(rep.Routes), "corp 192.168.1.0/24 via branch-1\ncorp 192.168.1.0/24 via lab-gw"; got != want {
		t.Errorf("the routes with a second gateway are\n%s\nwant\n%s", got, want)
	}
}

// TestPoolThresholdEvent is the third criterion of #186: an event fires when a change takes a pool
// to the threshold that its Network sets, once, and again when the pool has fallen below the
// threshold and is taken there again; the API lists the events and reports the pool as near
// exhaustion.
func TestPoolThresholdEvent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// A /29 holds 6 host addresses, and its Network sets the threshold at 50 percent: 3 of them
	poolDoc := func(n int) intent.Document {
		rs := []intent.Resource{
			{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
			{Kind: intent.KindNetwork, Name: "lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.60.0.0/29", "poolThreshold": 50}`)},
		}
		for i := 1; i <= n; i++ {
			rs = append(rs, ipamNode(nodeName(i), nodeKey(i), `"vrfs": ["corp"]`))
		}
		return intent.Document{Resources: rs}
	}
	apply := func(n int) uint64 {
		t.Helper()
		res, err := h.api.Apply(ctx, poolDoc(n))
		if err != nil {
			t.Fatalf("applying %d Nodes: %v", n, err)
		}
		return res.Revision
	}
	const message = `Network "lan" of VRF "corp": the IPv4 pool 10.60.0.0/29 is 50% used (3 of its 6 addresses), at or above its threshold of 50%`
	checkEvents := func(revisions ...uint64) {
		t.Helper()
		evs := h.events()
		if len(evs) != len(revisions) {
			t.Fatalf("the events are %+v, want %d of them", evs, len(revisions))
		}
		for i, e := range evs {
			if e.Type != event.PoolNearExhaustion || e.Revision != revisions[i] || e.Message != message || e.ID == 0 || e.Time.IsZero() {
				t.Errorf("event %d is %+v, want a %s event of revision %d that says %q", i, e, event.PoolNearExhaustion, revisions[i], message)
			}
		}
	}

	apply(2)
	checkEvents()
	atThreshold := apply(3)
	checkEvents(atThreshold)
	rep, err := h.api.IPAM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := poolLines(rep.Pools), "lan 10.60.0.0/29 size=6 allocated=3 reserved=0 free=3 percent=50 threshold=50 near=true"; got != want {
		t.Errorf("the pools at the threshold are %q, want %q", got, want)
	}
	// Still at the threshold, so no second event
	apply(4)
	checkEvents(atThreshold)
	// Below it again, and taken there again: a second event
	for _, i := range []int{4, 3} {
		if _, err := h.api.Delete(ctx, intent.KindNode, nodeName(i)); err != nil {
			t.Fatal(err)
		}
	}
	checkEvents(atThreshold)
	again := apply(3)
	checkEvents(atThreshold, again)
}

// TestNoDHCPInTheOverlay is the fourth criterion of #186 (ADR-0028 decision 1): a node gets its
// addresses from the controller alone. The simulated node is a protocol-only node with no data
// plane and no DHCP client, and it holds its allocated addresses from the one Update it
// received; and the control protocol has no DHCP inside the overlay: the only messages, fields and
// enums named after it are the ones of the DHCP responder of an L2 Network (SDN-43 #236), listed
// here, which answers the clients of the LAN that the Network bridges and never a node (an L3
// Network has none, internal/intent dhcp.go). A ticket that adds DHCP to the protocol changes this
// test and names what it adds.
func TestNoDHCPInTheOverlay(t *testing.T) {
	h := newHarness(t)
	h.apply("ipam-pools.json")
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	h.checkState(b1)
	if got := stateAddresses(b1); len(got) == 0 || got[0] != "self corp-lan 10 10.10.0.8/24, corp-lan 10 fd12:3456:789a:1::1/64" {
		t.Errorf("branch-1 holds the addresses %v, want the ones the controller allocated", got)
	}
	for _, m := range received(b1) {
		if m.GetUpdate() == nil && m.GetControllers() == nil {
			t.Errorf("branch-1 received a frame that is neither an update of its state nor the controllers:\n%s", show(m))
		}
	}

	names := protocolNames()
	if !slices.Contains(names, "ranz.control.v1.Address") {
		t.Fatalf("the names of the control protocol are %v, which lack Address", names)
	}
	// The DHCP responder of an L2 Network (SDN-43 #236); the values of an enum are named in the scope
	// of the enum, as protobuf names them
	responder := []string{
		"ranz.control.v1.DHCP_MODE_OFF",
		"ranz.control.v1.DHCP_MODE_POOL",
		"ranz.control.v1.DHCP_MODE_UNSPECIFIED",
		"ranz.control.v1.Dhcp",
		"ranz.control.v1.Dhcp.address",
		"ranz.control.v1.Dhcp.dns",
		"ranz.control.v1.Dhcp.gateway",
		"ranz.control.v1.Dhcp.lease_time",
		"ranz.control.v1.Dhcp.mode",
		"ranz.control.v1.Dhcp.reserved",
		"ranz.control.v1.DhcpMode",
		"ranz.control.v1.Network.dhcp",
	}
	var dhcp []string
	for _, name := range names {
		if strings.Contains(strings.ToLower(name), "dhcp") {
			dhcp = append(dhcp, name)
		}
	}
	slices.Sort(dhcp)
	if !slices.Equal(dhcp, responder) {
		t.Errorf("the names of the control protocol after DHCP are\n%s\nwant the ones of the responder of an L2 Network alone\n%s: no DHCP runs inside the overlay",
			strings.Join(dhcp, "\n"), strings.Join(responder, "\n"))
	}
}

// protocolNames returns the full name of every message, field, enum and enum value of the control
// protocol.
func protocolNames() []string {
	var out []string
	enums := func(es protoreflect.EnumDescriptors) {
		for i := 0; i < es.Len(); i++ {
			out = append(out, string(es.Get(i).FullName()))
			for j := 0; j < es.Get(i).Values().Len(); j++ {
				out = append(out, string(es.Get(i).Values().Get(j).FullName()))
			}
		}
	}
	var messages func(ms protoreflect.MessageDescriptors)
	messages = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			m := ms.Get(i)
			out = append(out, string(m.FullName()))
			for j := 0; j < m.Fields().Len(); j++ {
				out = append(out, string(m.Fields().Get(j).FullName()))
			}
			enums(m.Enums())
			messages(m.Messages())
		}
	}
	fd := controlpb.File_ranz_control_v1_control_proto
	messages(fd.Messages())
	enums(fd.Enums())
	return out
}
