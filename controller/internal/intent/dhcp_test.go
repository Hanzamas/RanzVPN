package intent

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// dhcpBase is an intent with VRF corp, a Node in it and one outside it, for the DHCP responder of
// an L2 Network of corp.
func dhcpBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "lab-1", `{"publicKey": "`+key2+`", "vrfs": ["lab"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// dmz returns the L2 Network dmz of VRF corp, with the pool 10.20.0.0/24, the reservations
// reserved (a JSON list, or "" for none) and the DHCP responder dhcp (a JSON object).
func dmz(reserved, dhcp string) Resource {
	spec := `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24"`
	if reserved != "" {
		spec += `, "reserved": ` + reserved
	}
	return res(KindNetwork, "dmz", spec+`, "dhcp": `+dhcp+`}`)
}

// responderLine writes the responder r as one line.
func responderLine(r Responder) string {
	return fmt.Sprintf("node=%s pool=%s address=%s gateway=%v dns=%v lease=%d reserved=%v", r.Node, r.Pool, r.Address, r.Gateway, r.DNS, r.LeaseTime, r.Reserved)
}

// The controller fills in the mode, the lease time and the responder's own address, which steps
// over the reservations, the gateway and the DNS servers and stays the same while it is free; the
// node that answers DHCP gets the responder as Responders reports it.
func TestDHCPResponderCompletes(t *testing.T) {
	in, err := Apply(dhcpBase(t), doc(dmz(`["10.20.0.2"]`, `{"mode": "pool", "node": "branch-1", "gateway": "10.20.0.1", "dns": ["10.20.0.3", "9.9.9.9"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := in.Networks["dmz"].DHCP
	if d == nil || d.Mode != DHCPPool || d.LeaseTime != DefaultLeaseTime || d.Address != "10.20.0.4" {
		t.Fatalf("the responder is %+v, want mode pool, lease time %d and the address 10.20.0.4, past the gateway, the reservation and the DNS server", d, DefaultLeaseTime)
	}
	rs := in.Responders()
	want := "node=branch-1 pool=10.20.0.0/24 address=10.20.0.4 gateway=10.20.0.1 dns=[10.20.0.3 9.9.9.9] lease=7200 reserved=[10.20.0.2/32]"
	if got := responderLine(rs["dmz"]); len(rs) != 1 || got != want {
		t.Errorf("the responders are %v: dmz is\n%s\nwant\n%s", rs, got, want)
	}

	// Applied again without an address, it keeps the one it has; once that is the gateway, it gets
	// the lowest free one
	again, err := Apply(in, doc(dmz(`["10.20.0.2"]`, `{"mode": "pool", "node": "branch-1", "gateway": "10.20.0.1", "leaseTime": 600}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := again.Networks["dmz"].DHCP; d.Address != "10.20.0.4" || d.LeaseTime != 600 {
		t.Errorf("applied again the responder is %+v, want the address 10.20.0.4 that it had and the lease time 600", d)
	}
	moved, err := Apply(again, doc(dmz(`["10.20.0.2"]`, `{"mode": "pool", "node": "branch-1", "gateway": "10.20.0.4"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := moved.Networks["dmz"].DHCP; d.Address != "10.20.0.1" {
		t.Errorf("with 10.20.0.4 as the gateway the responder has the address %s, want 10.20.0.1, the lowest free one", d.Address)
	}
	// A declared address is the responder's, in its one form
	declared, err := Apply(in, doc(dmz("", `{"mode": "pool", "node": "branch-1", "address": "10.20.0.254"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := declared.Responders()["dmz"].Address; got != netip.MustParseAddr("10.20.0.254") {
		t.Errorf("the declared address of the responder is %s, want 10.20.0.254", got)
	}
}

// A responder that is off, or a Network without one, gets no Node a responder: the node answers
// no DHCP.
func TestDHCPResponderOff(t *testing.T) {
	in, err := Apply(dhcpBase(t), doc(
		dmz("", `{"node": "branch-1", "gateway": "10.20.0.1"}`),
		res(KindNetwork, "plain", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.30.0.0/24"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := in.Networks["dmz"].DHCP; d.Mode != DHCPOff || d.Address != "" {
		t.Errorf("a responder without a mode is %+v, want off and no address", d)
	}
	if rs := in.Responders(); len(rs) != 0 {
		t.Errorf("the responders are %v, want none: one is off and the other Network has none", rs)
	}
	if in.Networks["plain"].DHCP != nil {
		t.Errorf("a Network without a responder got %+v", in.Networks["plain"].DHCP)
	}
}

// What a responder cannot be: one of an L3 Network or of a Network without a usable pool, of a
// Node outside its VRF, with addresses outside its pool or taken, too many DNS servers, another
// mode or a lease time out of bounds.
func TestDHCPResponderRejects(t *testing.T) {
	base := dhcpBase(t)
	on := `"mode": "pool", "node": "branch-1"`
	for _, c := range []struct {
		r    Resource
		want string
	}{
		{res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24", "dhcp": {`+on+`}}`), `Network "lan": dhcp: only an L2 Network has a DHCP responder`},
		{res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "dhcp": {`+on+`}}`), `the responder gives the addresses of the ipv4Pool, and the Network has none`},
		{res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.0.0.0/8", "dhcp": {`+on+`}}`), `the ipv4Pool 10.0.0.0/8 is not a /16 to a /30`},
		{dmz("", `{"mode": "pool", "node": "nobody"}`), `node "nobody" is not a Node: a Node of VRF "corp" answers DHCP`},
		{dmz("", `{"mode": "pool", "node": "lab-1"}`), `Node "lab-1" is not in VRF "corp" of the Network`},
		{dmz("", `{`+on+`, "gateway": "10.99.0.1"}`), `gateway 10.99.0.1 is not a host address of the ipv4Pool 10.20.0.0/24`},
		{dmz("", `{`+on+`, "gateway": "10.20.0.255"}`), `gateway 10.20.0.255 is not a host address`},
		{dmz("", `{`+on+`, "gateway": "fd12:3456:789a::1"}`), `gateway "fd12:3456:789a::1" is not an IPv4 address`},
		{dmz(`["10.20.0.0/29"]`, `{`+on+`, "address": "10.20.0.3"}`), `address 10.20.0.3 is reserved by the Network`},
		{dmz("", `{`+on+`, "address": "10.20.0.1", "gateway": "10.20.0.1"}`), `address 10.20.0.1 is the gateway`},
		{dmz("", `{`+on+`, "address": "10.20.0.9", "dns": ["10.20.0.9"]}`), `address 10.20.0.9 is a DNS server`},
		{dmz("", `{`+on+`, "dns": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]}`), `5 DNS servers, and a responder gives at most 4`},
		{dmz("", `{`+on+`, "dns": ["fd12:3456:789a::1"]}`), `DNS server "fd12:3456:789a::1" is not an IPv4 address`},
		{dmz("", `{`+on+`, "dns": ["1.1.1.1", "1.1.1.1"]}`), `DNS server 1.1.1.1 is listed twice`},
		{dmz("", `{"mode": "relay", "node": "branch-1"}`), `the mode must be off or pool, not "relay"`},
		{dmz("", `{`+on+`, "leaseTime": 30}`), `leaseTime 30 is not between 60 and 31536000 seconds`},
		{dmz("", `{"mode": "off", "node": "nobody"}`), `node "nobody" is not a Node`},
		{res(KindNetwork, "tiny", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.40.0.0/30", "dhcp": {`+on+`, "gateway": "10.40.0.1", "dns": ["10.40.0.2"]}}`), `the ipv4Pool 10.40.0.0/30 has no free address for the responder`},
	} {
		refuses(t, base, c.want, c.r)
	}
}

// A Node that answers DHCP for a Network cannot be deleted while it does.
func TestDeleteDHCPNode(t *testing.T) {
	in, err := Apply(dhcpBase(t), doc(dmz("", `{"mode": "pool", "node": "branch-1"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Delete(in, KindNode, "branch-1")
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "branch-1" answers DHCP for Network "dmz"`) {
		t.Errorf("deleting the Node that answers DHCP gave %v", err)
	}
	off, err := Apply(in, doc(dmz("", `{"mode": "off"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(off, KindNode, "branch-1"); err != nil {
		t.Errorf("deleting the Node once no Network names it as its responder: %v", err)
	}
}
