package intent

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// The DHCP responder of an L2 Network (SDN-43 #236, ADR-0028). When the LAN that an L2 Network is
// bridged to has no DHCP server, one Node of the Network answers the DHCP clients of the Network
// from its IPv4 pool: the Node that DHCP.Node names, a Node of the VRF of the Network. The pool
// stays the controller's: the responder only hands out its addresses, and never the first or the
// last address of the pool, a reservation of the Network, the gateway, a DNS server or its own
// address, its server identifier, which the controller fills in. The node answers nothing while
// the mode is off, nor while a DHCP server of the LAN answers, and it reports its leases to the
// controller, which lists them with IPAM (GET /api/v1/ipam/leases). An L3 Network never has one:
// no DHCP runs inside the overlay.

// The modes of a DHCP responder.
const (
	DHCPOff  = "off"  // the node answers no DHCP: the default
	DHCPPool = "pool" // the node answers from the IPv4 pool while no DHCP server of the LAN answers
)

const (
	// DefaultLeaseTime is the lease time of a responder that sets none, in seconds: two hours, the
	// lease time of the virtual DHCP server of SecureNAT.
	DefaultLeaseTime = 7200
	// MinLeaseTime and MaxLeaseTime bound the lease time of a responder, in seconds.
	MinLeaseTime = 60
	MaxLeaseTime = 365 * 24 * 60 * 60
	// MaxDHCPServers is the most DNS servers that a responder gives its clients, and MaxDHCPReserved
	// the most reservations of its Network in the pool: the Dhcp message of the C node holds that
	// many (proto/ranz/control/v1/control.options).
	MaxDHCPServers  = 4
	MaxDHCPReserved = 16
	// MinDHCPPoolBits and MaxDHCPPoolBits bound the length of the IPv4 pool of a responder: a /16
	// at most, and a /30 at least, which holds the responder and one client.
	MinDHCPPoolBits = 16
	MaxDHCPPoolBits = 30
	// MaxLeases is the most leases that one responder holds and reports in one Leases message
	// (NODE_DHCP_MAX_LEASES of the node, Leases.leases of control.options).
	MaxLeases = 1024
)

// DHCP is the DHCP responder of an L2 Network (Network.DHCP).
type DHCP struct {
	// Mode is DHCPOff, the default, or DHCPPool.
	Mode string `json:"mode,omitempty"`
	// Node is the Node that answers DHCP for the Network, a Node of its VRF.
	Node string `json:"node,omitempty"`
	// Address is the responder's own address, a host address of the IPv4 pool and its server
	// identifier. Left out, the controller fills in the one it had, else the lowest host address of
	// the pool that is not reserved, the gateway or a DNS server.
	Address string `json:"address,omitempty"`
	// Gateway is the router that the clients get, a host address of the pool. Left out, they get
	// none.
	Gateway string `json:"gateway,omitempty"`
	// DNS holds the DNS servers that the clients get, IPv4 addresses, at most MaxDHCPServers.
	DNS []string `json:"dns,omitempty"`
	// LeaseTime is the lease time in seconds, from MinLeaseTime to MaxLeaseTime; DefaultLeaseTime
	// when it is left out.
	LeaseTime uint32 `json:"leaseTime,omitempty"`
}

// Responder is the DHCP responder of an L2 Network that is on, as the node that answers DHCP for
// the Network runs it (Responders).
type Responder struct {
	Node      string         // the Node that answers DHCP for the Network
	Pool      netip.Prefix   // the IPv4 pool of the Network
	Address   netip.Addr     // the responder's own address
	Gateway   netip.Addr     // the router of the clients, the zero Addr for none
	DNS       []netip.Addr   // the DNS servers of the clients
	LeaseTime uint32         // seconds
	Reserved  []netip.Prefix // the reservations of the Network in the pool
}

// Responders returns the DHCP responders of in that are on (DHCPPool), by Network name. in must
// be an intent that Apply returned.
func (in Intent) Responders() map[string]Responder {
	out := map[string]Responder{}
	for name, n := range in.Networks {
		d := n.DHCP
		if d == nil || d.Mode != DHCPPool || n.Mode != ModeL2 {
			continue
		}
		pool, err := ParsePool(n.IPv4Pool, 4)
		address, aerr := netip.ParseAddr(d.Address)
		if err != nil || aerr != nil {
			continue
		}
		r := Responder{Node: d.Node, Pool: pool, Address: address, LeaseTime: d.LeaseTime, Reserved: in.reservedIn(name, pool)}
		if g, err := netip.ParseAddr(d.Gateway); err == nil {
			r.Gateway = g
		}
		for _, s := range d.DNS {
			if a, err := netip.ParseAddr(s); err == nil {
				r.DNS = append(r.DNS, a)
			}
		}
		out[name] = r
	}
	return out
}

// clone returns a copy of d that shares nothing with it.
func (d *DHCP) clone() *DHCP {
	if d == nil {
		return nil
	}
	c := *d
	c.DNS = slices.Clone(d.DNS)
	return &c
}

// completeDHCP fills in what the DHCP responder of each Network leaves out: the mode off, the
// lease time, the one form of its addresses, and the responder's own address while it is on,
// which it keeps from prev while that is still free (responderAddress).
func (in Intent) completeDHCP(prev Intent) {
	for name, n := range in.Networks {
		d := n.DHCP
		if d == nil {
			continue
		}
		if d.Mode == "" {
			d.Mode = DHCPOff
		}
		if d.LeaseTime == 0 {
			d.LeaseTime = DefaultLeaseTime
		}
		d.Address = canonicalAddr(d.Address)
		d.Gateway = canonicalAddr(d.Gateway)
		for i, s := range d.DNS {
			d.DNS[i] = canonicalAddr(s)
		}
		if d.Mode == DHCPPool && d.Address == "" {
			d.Address = in.responderAddress(name, prev)
		}
		in.Networks[name] = n
	}
}

// responderAddress returns the address that complete fills in for the responder of the Network
// network: the one it had in prev while that is still free, else the lowest free host address of
// the IPv4 pool; "" when the pool does not parse or has none free. An address is free when the
// Network does not reserve it and it is neither the gateway nor a DNS server.
func (in Intent) responderAddress(network string, prev Intent) string {
	n := in.Networks[network]
	pool, err := ParsePool(n.IPv4Pool, 4)
	if err != nil {
		return ""
	}
	reserved := in.reservedIn(network, pool)
	free := func(a netip.Addr) bool {
		return hostAddress(pool, a) && !within(reserved, a) && a.String() != n.DHCP.Gateway && !slices.Contains(n.DHCP.DNS, a.String())
	}
	if old := prev.Networks[network].DHCP; old != nil {
		if a, err := netip.ParseAddr(old.Address); err == nil && free(a) {
			return a.String()
		}
	}
	for a := pool.Addr(); a.IsValid() && pool.Contains(a); a = after(reserved, a) {
		if free(a) {
			return a.String()
		}
	}
	return ""
}

// canonicalAddr returns the address s in its one form, or s itself when it is no address, for
// validateDHCP to refuse.
func canonicalAddr(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

// dhcpUsers returns the Networks of in whose DHCP responder the Node node is, each as Network
// "name": a Node that answers DHCP for a Network cannot be deleted.
func (in Intent) dhcpUsers(node string) []string {
	var out []string
	for _, name := range sortedNames(in.Networks) {
		if d := in.Networks[name].DHCP; d != nil && d.Node == node {
			out = append(out, KindNetwork+" "+strconv.Quote(name))
		}
	}
	return out
}

// validateDHCP checks the DHCP responder of each Network of a completed intent. What a responder
// sets must be valid in either mode; one that is on also needs an L2 Network with an IPv4 pool of
// MinDHCPPoolBits to MaxDHCPPoolBits and a Node of its VRF.
func (in Intent) validateDHCP() []error {
	var problems []error
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		d := n.DHCP
		if d == nil {
			continue
		}
		bad := func(format string, args ...any) {
			problems = append(problems, fmt.Errorf("Network %q: dhcp: %s", name, fmt.Sprintf(format, args...)))
		}
		if d.Mode != DHCPOff && d.Mode != DHCPPool {
			bad("the mode must be %s or %s, not %q", DHCPOff, DHCPPool, d.Mode)
			continue
		}
		if d.LeaseTime < MinLeaseTime || d.LeaseTime > MaxLeaseTime {
			bad("leaseTime %d is not between %d and %d seconds", d.LeaseTime, MinLeaseTime, MaxLeaseTime)
		}
		pool, poolErr := ParsePool(n.IPv4Pool, 4)
		if d.Mode == DHCPPool {
			switch {
			case n.Mode != ModeL2:
				bad("only an L2 Network has a DHCP responder: the Nodes of an L3 Network get their addresses from the controller alone, and no DHCP runs inside the overlay")
			case poolErr != nil:
				bad("the responder gives the addresses of the ipv4Pool, and the Network has none")
			case pool.Bits() < MinDHCPPoolBits || pool.Bits() > MaxDHCPPoolBits:
				bad("the ipv4Pool %s is not a /%d to a /%d, the pools a responder serves", pool, MinDHCPPoolBits, MaxDHCPPoolBits)
			}
			if node, ok := in.Nodes[d.Node]; !ok {
				bad("node %q is not a Node: a Node of VRF %q answers DHCP for the Network", d.Node, n.VRF)
			} else if !slices.Contains(node.VRFs, n.VRF) {
				bad("Node %q is not in VRF %q of the Network", d.Node, n.VRF)
			}
			if poolErr == nil && len(in.reservedIn(name, pool)) > MaxDHCPReserved {
				bad("the Network reserves %d prefixes of its pool, and a responder carries at most %d", len(in.reservedIn(name, pool)), MaxDHCPReserved)
			}
			if d.Address == "" && poolErr == nil {
				bad("the ipv4Pool %s has no free address for the responder", pool)
			}
		} else if d.Node != "" {
			if _, ok := in.Nodes[d.Node]; !ok {
				bad("node %q is not a Node", d.Node)
			}
		}
		// inPool returns the address s of the field of the responder when it is a host address of the
		// pool
		inPool := func(field, s string) (netip.Addr, bool) {
			a, err := netip.ParseAddr(s)
			switch {
			case err != nil || !a.Is4():
				bad("%s %q is not an IPv4 address", field, s)
			case poolErr != nil:
				bad("%s %s needs the ipv4Pool of the Network, and it has none", field, a)
			case !hostAddress(pool, a):
				bad("%s %s is not a host address of the ipv4Pool %s", field, a, pool)
			default:
				return a, true
			}
			return netip.Addr{}, false
		}
		var gateway netip.Addr
		if d.Gateway != "" {
			gateway, _ = inPool("gateway", d.Gateway)
		}
		if d.Address != "" {
			if a, ok := inPool("address", d.Address); ok {
				switch {
				case within(in.reservedIn(name, pool), a):
					bad("address %s is reserved by the Network", a)
				case a == gateway:
					bad("address %s is the gateway", a)
				case slices.Contains(d.DNS, a.String()):
					bad("address %s is a DNS server", a)
				}
			}
		}
		if len(d.DNS) > MaxDHCPServers {
			bad("%d DNS servers, and a responder gives at most %d", len(d.DNS), MaxDHCPServers)
		}
		for i, s := range d.DNS {
			a, err := netip.ParseAddr(s)
			switch {
			case err != nil || !a.Is4() || a.IsUnspecified():
				bad("DNS server %q is not an IPv4 address", s)
			case slices.Contains(d.DNS[:i], s):
				bad("DNS server %s is listed twice", a)
			}
		}
	}
	return problems
}
