package sidecar

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// The vteps of a learned message (SDN-25-R3 #571): the next hop of every route that the peers offer for a prefix, each once
// and in order, IPv4 before IPv6; one leaf under two route distinguishers is one VTEP; and of more than maxEVPNVTEPs leaves,
// the next hop of the route of the message stays, with the lowest of the others.
func TestOfferVTEPs(t *testing.T) {
	route := func(nextHop string) evpnRoute {
		return evpnRoute{nextHop: netip.MustParseAddr(nextHop), vni: 10101, mac: testFabricMAC, peer: netip.MustParseAddr("127.0.0.3")}
	}

	if got := offerVTEPs(nil, netip.Addr{}); got != nil {
		t.Errorf("the vteps of no offer: %v, want none", got)
	}

	offers := map[string]evpnRoute{
		"[rd:192.0.2.12:1]":  route("192.0.2.12"),
		"[rd:192.0.2.10:1]":  route("192.0.2.10"),
		"[rd:192.0.2.10:2]":  route("192.0.2.10"),
		"[rd:2001:db8::1:1]": route("2001:db8::10"),
		"[rd:192.0.2.11:1]":  route("192.0.2.11"),
	}
	want := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "2001:db8::10"}
	if got := vtepTexts(offerVTEPs(offers, netip.MustParseAddr("192.0.2.10"))); !slices.Equal(got, want) {
		t.Errorf("the vteps of five offers of four leaves: %v, want %v", got, want)
	}

	// More leaves than a message names: the next hop of the route of the message, here the highest of them, stays
	many := map[string]evpnRoute{}
	for i := 1; i <= maxEVPNVTEPs+4; i++ {
		many[fmt.Sprintf("[rd:198.51.100.%d:1]", i)] = route(fmt.Sprintf("198.51.100.%d", i))
	}
	next := netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", maxEVPNVTEPs+4))
	got := offerVTEPs(many, next)
	if len(got) != maxEVPNVTEPs || !slices.Contains(got, next) || !slices.IsSortedFunc(got, netip.Addr.Compare) || got[0].String() != "198.51.100.1" ||
		got[maxEVPNVTEPs-2].String() != fmt.Sprintf("198.51.100.%d", maxEVPNVTEPs-1) {
		t.Errorf("the vteps of %d leaves with the next hop %s: %v, want the next hop and the %d lowest others", len(many), next, got, maxEVPNVTEPs-1)
	}
	if lowest := offerVTEPs(many, netip.MustParseAddr("198.51.100.1")); len(lowest) != maxEVPNVTEPs || lowest[maxEVPNVTEPs-1].String() != fmt.Sprintf("198.51.100.%d", maxEVPNVTEPs) {
		t.Errorf("the vteps of %d leaves with the lowest next hop: %v, want the %d lowest", len(many), lowest, maxEVPNVTEPs)
	}
}
