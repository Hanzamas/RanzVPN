// Controller conformance for overlay DNS (ADR-0028 decisions 6 to 8, SDN-11 #187), with the
// harness and the node simulator of conformance_test.go: each member of a VRF with overlay DNS on
// gets the zone of the VRF in its Vrf object, with the DnsRecord resources of the VRF and the
// addresses that each answers, so the same name means different hosts in two VRFs; a change of a
// record reaches the members of its VRF alone.
package controller_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
)

// stateZone writes the zone of the VRF vrf that the state of the simulated node s holds: its
// suffix, then one line per record with its name and its addresses; "off" for a Vrf object without
// a zone, "none" for no Vrf object.
func stateZone(s *sim, vrf string) string {
	_, st := s.State()
	o, ok := st[desired.Key{Kind: controlpb.Kind_KIND_VRF, Name: vrf}]
	if !ok {
		return "none"
	}
	z := o.GetVrf().GetDns()
	if z == nil {
		return "off"
	}
	lines := []string{z.GetSuffix()}
	for _, r := range z.GetRecords() {
		line := r.GetName()
		for _, b := range r.GetAddresses() {
			a, _ := netip.AddrFromSlice(b)
			line += " " + a.String()
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// TestDNSZonesPerVRF is the controller's side of the criteria of #187: red and blue both have the
// suffix corp.internal, and the DnsRecord fileserver of each names another node, so
// fileserver.corp.internal answers lab-1 on branch-1, a member of red, and relay-1 on branch-2, a
// member of blue. Each gets the zone of its own VRF alone, which its stub resolver answers and its
// NRPT rule sends the names under corp.internal to. A change of the record of blue gives branch-2 a
// new generation with the zone that answers the new addresses, and branch-1 none.
func TestDNSZonesPerVRF(t *testing.T) {
	h := newHarness(t)
	h.apply("dns.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	for _, s := range []*sim{b1, b2} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	for _, c := range []struct {
		s         *sim
		vrf, want string
	}{
		{b1, "red", "corp.internal\nfileserver 10.1.0.2 fd00:101:0:1::2"},
		{b1, "blue", "none"},
		{b2, "blue", "corp.internal\nfileserver 10.2.0.2"},
		{b2, "red", "none"},
	} {
		if got := stateZone(c.s, c.vrf); got != c.want {
			t.Errorf("%s holds the zone of %s\n%s\nwant\n%s", c.s.name, c.vrf, got, c.want)
		}
	}

	res := h.apply("dns-change.json")
	if want := []controller.NodeGeneration{{Name: "branch-2", Generation: 2}, {Name: "relay-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("dns-change.json changed %+v, want %+v: the members of blue alone", res.Nodes, want)
	}
	b2.update(t)
	h.waitNode("branch-2", 2, true)
	h.checkState(b2)
	if got, want := stateZone(b2, "blue"), "corp.internal\nfileserver 192.168.7.20 fd00:7::20"; got != want {
		t.Errorf("after the change branch-2 holds the zone of blue\n%s\nwant\n%s", got, want)
	}
	h.waitNode("branch-1", 1, true)
}
