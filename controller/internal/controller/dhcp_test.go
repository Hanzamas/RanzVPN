// Controller conformance for the DHCP responder of an L2 Network (SDN-43 #236, ADR-0028), with the
// harness and the node simulator of conformance_test.go: the node that answers DHCP for the
// Network gets the responder in its state and no other node does, no node gets one while the mode
// is off, and the leases that the responder reports are listed by IPAM.
package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// responderLine writes the DHCP responder d of a Network object as one line, "none" for none.
func responderLine(d *controlpb.Dhcp) string {
	if d == nil {
		return "none"
	}
	addr := func(b []byte) string {
		a, ok := netip.AddrFromSlice(b)
		if !ok {
			return "-"
		}
		return a.String()
	}
	var dns, reserved []string
	for _, b := range d.GetDns() {
		dns = append(dns, addr(b))
	}
	for _, p := range d.GetReserved() {
		a, _ := netip.AddrFromSlice(p.GetAddress())
		reserved = append(reserved, netip.PrefixFrom(a, int(p.GetLength())).String())
	}
	return fmt.Sprintf("mode=%s address=%s gateway=%s dns=%s lease=%d reserved=%s", d.GetMode(), addr(d.GetAddress()), addr(d.GetGateway()),
		strings.Join(dns, ","), d.GetLeaseTime(), strings.Join(reserved, ","))
}

// leaseLines writes each lease as a line: its Network, its node, the MAC address and the address
// of the client and the host name it sent, if any.
func leaseLines(leases []store.DHCPLease) string {
	var out []string
	for _, l := range leases {
		line := fmt.Sprintf("%s %s %s %s", l.Network, l.Node, l.MAC, l.Address)
		if l.HostName != "" {
			line += " " + l.HostName
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// waitLeases waits until IPAM lists the leases want, as leaseLines writes them.
func (h *harness) waitLeases(want string) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		leases, err := h.api.DHCPLeases(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		got := leaseLines(leases)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("IPAM lists the leases\n%s\nwant\n%s", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitTelemetry waits until the controller holds a summary of the node name: every frame that the
// node sent before it on its stream has been read.
func (h *harness) waitTelemetry(name string) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		snaps, err := h.api.Telemetry(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		for _, s := range snaps {
			if s.Node == name {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the controller holds no summary of %s within %v", name, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dhcpLease returns the lease of the client whose MAC address ends in last, of the address address
// with the host name host, which expires after d.
func dhcpLease(last byte, address, host string, d time.Duration) *controlpb.Lease {
	return &controlpb.Lease{Mac: []byte{0x02, 0x00, 0x5e, 0x10, 0x00, last}, Address: netip.MustParseAddr(address).AsSlice(),
		ExpiresMs: uint64(time.Now().Add(d).UnixMilli()), HostName: host}
}

// TestDHCPResponderLeasesInIPAM is the controller's side of #236: branch-1 answers DHCP for the L2
// Network corp-dmz and gets the responder in its state, with its own address past the reservation,
// the gateway, the DNS server and the lease time; branch-2, in the same VRF, gets the Network
// without one. IPAM lists the leases that branch-1 reports, each report in place of the one before;
// a report of branch-2, of an L3 Network, or a lease outside the pool, without a whole MAC address
// or of a MAC address listed before is dropped. With the mode off, branch-1 gets the Network
// without the responder, so it never answers, and the lease it reported stays listed until it
// expires, as the client holds it until then.
func TestDHCPResponderLeasesInIPAM(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("dhcp.json")
	b1 := h.sim("branch-1", keyBranch1)
	b2 := h.sim("branch-2", keyBranch2)
	for _, s := range []*sim{b1, b2} {
		s.update(t)
		h.waitNode(s.name, 1, true)
		h.checkState(s)
	}
	dmz := desired.Key{Kind: controlpb.Kind_KIND_NETWORK, Name: "corp-dmz"}
	_, st := b1.State()
	want := "mode=DHCP_MODE_POOL address=10.20.0.8 gateway=10.20.0.1 dns=10.20.0.1 lease=3600 reserved=10.20.0.0/29"
	if got := responderLine(st[dmz].GetNetwork().GetDhcp()); got != want {
		t.Errorf("branch-1, which answers DHCP for corp-dmz, has the responder\n%s\nwant\n%s", got, want)
	}
	_, st = b2.State()
	if got := responderLine(st[dmz].GetNetwork().GetDhcp()); got != "none" || st[dmz].GetNetwork().GetMode() != controlpb.NetworkMode_NETWORK_MODE_L2 {
		t.Errorf("branch-2 has the L2 Network corp-dmz of mode %s with the responder %s, want none", st[dmz].GetNetwork().GetMode(), got)
	}

	// branch-2 does not answer DHCP for corp-dmz, so its report is dropped; the summary after it on
	// its stream tells when the controller has read it
	if err := b2.Leases(&controlpb.Leases{Network: "corp-dmz", Leases: []*controlpb.Lease{dhcpLease(0x20, "10.20.0.20", "intruder", time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := b2.Telemetry(&controlpb.Telemetry{Vrfs: []*controlpb.VrfCounters{{VrfId: 10, TxPackets: 1, TxBytes: 100}}}); err != nil {
		t.Fatal(err)
	}
	h.waitTelemetry("branch-2")
	// branch-1 reports leases of corp-lan, an L3 Network, which has no responder, then those of
	// corp-dmz, which it answers DHCP for
	if err := b1.Leases(&controlpb.Leases{Network: "corp-lan", Leases: []*controlpb.Lease{dhcpLease(0x21, "10.10.0.21", "", time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	short := dhcpLease(0x0e, "10.20.0.14", "short", time.Hour)
	short.Mac = short.GetMac()[:5]
	if err := b1.Leases(&controlpb.Leases{Network: "corp-dmz", Leases: []*controlpb.Lease{
		dhcpLease(0x0b, "10.20.0.10", "", time.Hour),
		dhcpLease(0x0a, "10.20.0.9", "laptop-a", time.Hour),
		dhcpLease(0x0c, "10.30.0.1", "outside", time.Hour),
		short,
		dhcpLease(0x0a, "10.20.0.11", "twice", time.Hour),
		dhcpLease(0x0d, "10.20.0.12", "gone", -time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	h.waitLeases("corp-dmz branch-1 02:00:5e:10:00:0a 10.20.0.9 laptop-a\ncorp-dmz branch-1 02:00:5e:10:00:0b 10.20.0.10")

	// The next report takes the place of the one before
	if err := b1.Leases(&controlpb.Leases{Network: "corp-dmz", Leases: []*controlpb.Lease{dhcpLease(0x0b, "10.20.0.10", "laptop-b", 2*time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	h.waitLeases("corp-dmz branch-1 02:00:5e:10:00:0b 10.20.0.10 laptop-b")

	// The mode off: only the state of branch-1 changes, and its corp-dmz has no responder
	res, err := h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{{Kind: intent.KindNetwork, Name: "corp-dmz",
		Spec: json.RawMessage(`{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "reserved": ["10.20.0.0/29"], "dhcp": {"mode": "off", "node": "branch-1"}}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the mode off changed %+v, want %+v", res.Nodes, want)
	}
	b1.update(t)
	h.waitNode("branch-1", 2, true)
	h.checkState(b1)
	_, st = b1.State()
	if got := responderLine(st[dmz].GetNetwork().GetDhcp()); got != "none" {
		t.Errorf("with the mode off branch-1 has the responder %s, want none", got)
	}
	h.waitLeases("corp-dmz branch-1 02:00:5e:10:00:0b 10.20.0.10 laptop-b")
}
