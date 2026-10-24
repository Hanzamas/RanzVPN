package controller

import (
	"context"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The DHCP responder of an L2 Network (SDN-43 #236, ADR-0028). The node that answers DHCP for the
// Network gets the responder in its desired state (internal/desired) and reports the leases it
// holds over its control stream, all the leases of one Network in one Leases message, after its
// Hello and whenever they change. The controller keeps each report in the store in place of the one
// before (takeLeases), and IPAM lists them (DHCPLeases, GET /api/v1/ipam/leases): the pool stays
// the controller's, and the responder only hands out its addresses.

// maxHostName bounds the host name of a lease: Lease.host_name of the C node (control.options),
// without the terminating NUL.
const maxHostName = 63

// takeLeases takes the leases that the node of s reported for one Network: the store keeps them, in
// place of the ones the node reported for that Network before, when the node answers DHCP for the
// Network. A report of a node that does not is dropped. A lease without a 6-byte MAC address or
// with an address outside the pool, a second lease of one MAC address, and every lease past
// intent.MaxLeases are left out.
func (c *Controller) takeLeases(s *stream, l *controlpb.Leases) {
	network := l.GetNetwork()
	c.mu.Lock()
	r, ok := c.intent.Responders()[network]
	c.mu.Unlock()
	if !ok || r.Node != s.name {
		c.log.Warn("DHCP leases of a Network that the node does not answer DHCP for, dropped", "node", s.name, "network", clip(network, maxSubject))
		return
	}
	leases := []store.DHCPLease{}
	seen := map[string]bool{}
	for _, x := range l.GetLeases() {
		a, ok := netip.AddrFromSlice(x.GetAddress())
		if len(leases) == intent.MaxLeases || !ok || len(x.GetMac()) != 6 || !r.Pool.Contains(a) || x.GetExpiresMs() > math.MaxInt64 {
			continue
		}
		mac := net.HardwareAddr(x.GetMac()).String()
		if seen[mac] {
			continue
		}
		seen[mac] = true
		leases = append(leases, store.DHCPLease{Network: network, Node: s.name, MAC: mac, Address: a, Expires: time.UnixMilli(int64(x.GetExpiresMs())).UTC(),
			HostName: clip(x.GetHostName(), maxHostName)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.store.SetDHCPLeases(ctx, s.name, network, leases); err != nil {
		c.log.Error("storing the DHCP leases that a node reported", "node", s.name, "network", network, "err", err)
	}
}

// DHCPLeases returns the leases of the DHCP responders of the L2 Networks (GET
// /api/v1/ipam/leases), ordered by Network, then address: the ones that the node answering DHCP
// for each Network reported last and that have not expired, also while the responder is off, as
// the clients hold them until then. A lease of a node that no longer answers DHCP for its Network,
// or outside the pool of the Network now, is left out.
func (c *Controller) DHCPLeases(ctx context.Context) ([]store.DHCPLease, error) {
	all, err := c.store.DHCPLeases(ctx)
	if err != nil {
		return nil, err
	}
	type responder struct {
		node string
		pool netip.Prefix
	}
	c.mu.Lock()
	responders := map[string]responder{}
	for name, n := range c.intent.Networks {
		if n.DHCP == nil {
			continue
		}
		if pool, err := intent.ParsePool(n.IPv4Pool, 4); err == nil {
			responders[name] = responder{node: n.DHCP.Node, pool: pool}
		}
	}
	c.mu.Unlock()
	now := time.Now()
	out := []store.DHCPLease{}
	for _, l := range all {
		r, ok := responders[l.Network]
		if ok && r.node == l.Node && r.pool.Contains(l.Address) && l.Expires.After(now) {
			out = append(out, l)
		}
	}
	return out, nil
}
