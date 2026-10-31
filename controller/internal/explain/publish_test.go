package explain

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// An Endpoint is reached by its name and its port (SDN-24 #200, ADR-0025 decision 10): the zone of overlay DNS of the consumer VRF
// answers the name of the service with its published address, and the flow to that address on that port, which the policy of both
// VRFs allow, ends at the host of the Node that serves it, as the address that the service has in the source VRF, though the two
// VRFs use one range and the consumer holds that very address itself.
func TestPublishedEndpointByName(t *testing.T) {
	s := scenario(t, "endpoint")
	in, states, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var zone *controlpb.DnsZone
	for _, o := range states["vendor-1"].Objects() {
		if v := o.GetVrf(); v.GetName() == "vendor" {
			zone = v.GetDns()
		}
	}
	var answer netip.Addr
	for _, r := range zone.GetRecords() {
		if r.GetName() == "billing" && len(r.GetAddresses()) == 1 {
			answer, _ = netip.AddrFromSlice(r.GetAddresses()[0])
		}
	}
	if name := "billing." + zone.GetSuffix(); name != "billing.vendor.ranz.internal" || answer != netip.MustParseAddr("172.16.1.1") {
		t.Fatalf("the zone of vendor answers %s with %s, want billing.vendor.ranz.internal with 172.16.1.1", name, answer)
	}

	r, err := New(in, states).Explain(Query{From: "vendor-1", To: answer.String(), Protocol: "tcp", SourcePort: 40100, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if v := r.Verdict; !v.Delivered || v.Node != "corp-app" || v.VRF != "corp" || v.Source.String() != "172.16.2.1" || v.Destination.String() != "10.0.0.1" {
		t.Errorf("the flow of vendor-1 to the name ends as %+v, want delivered to corp-app in corp, as 172.16.2.1 > 10.0.0.1", v)
	}
}

// Nothing else of the source VRF is reachable (SDN-24 #200): of every address of the range that the two VRFs share and of the range
// that the Endpoint is published in, on a few ports of TCP and UDP and with an ICMP echo, from each Node of the consumer VRF, the only
// flow that ends in the source VRF is the one of the Endpoint, from the Node that has its tag.
func TestPublishedEndpointReachesNothingElse(t *testing.T) {
	m, _ := model(t, scenario(t, "endpoint"))
	flows := []struct {
		protocol string
		port     uint16
	}{{"tcp", 22}, {"tcp", 443}, {"tcp", 8443}, {"udp", 53}, {"udp", 443}, {"icmp", 0}}
	var reached []string
	for _, from := range []string{"vendor-1", "vendor-2"} {
		for _, base := range []string{"10.0.0.", "172.16.1."} {
			for host := 0; host < 256; host++ {
				to := base + strconv.Itoa(host)
				for _, f := range flows {
					r, err := m.Explain(Query{From: from, To: to, Protocol: f.protocol, SourcePort: 40200, Port: f.port})
					if err != nil {
						t.Fatalf("%s to %s, %s %d: %v", from, to, f.protocol, f.port, err)
					}
					if r.Verdict.Delivered && r.Verdict.VRF == "corp" {
						reached = append(reached, fmt.Sprintf("%s to %s, %s %d", from, to, f.protocol, f.port))
					}
				}
			}
		}
	}
	if want := []string{"vendor-1 to 172.16.1.1, tcp 443"}; !slices.Equal(reached, want) {
		t.Errorf("the flows of vendor that end in corp are %q, want %q", reached, want)
	}
}
