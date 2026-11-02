package sidecar

// The symmetric IRB of a stretch (ADR-0032 amendment of 2026-10-22; SDN-67 #294; RFC 9135 section 5): with irb the gateway
// routes between the stretched L2 Network and the other Networks of its VRF through the L3 VNI of that VRF, as a leaf of a
// fabric with symmetric IRB does. It is off by default: on a normal data-centre VLAN the fabric owns the default gateway, and
// two owners of one address break ARP.
//
// A stretch with irb names the EVPN VRF of its Network (vrf), whose L3 VNI and route targets the IRB uses, and the gateway IPs
// of the Network with the prefix length of their subnet (gateway_ips), one IPv4 and one IPv6 at most, which the node answers
// ARP and neighbour discovery for with its router MAC, and routes for (src/Cedar/NodeIrb.c). A stretch without irb names
// neither, so the gateway announces no gateway IP or MAC of its Network.
//
// Into the fabric: each MAC/IP advertisement route (type 2) of the gateway in the MAC plus IP form carries the L3 VNI of the
// VRF as its second label, the export route targets of the VRF besides those of the stretch, and the router MAC of the
// gateway, so that the fabric routes to the host through the L3 VNI; the MAC only form stays as it is. At start the sidecar
// announces each gateway IP as a type-2 route of the router MAC in the same form, with the default gateway extended
// community (RFC 7432 section 7.8).
//
// Out of the fabric: a type-2 route of a peer that the stretch takes, in the MAC plus IP form, with a second label, a router
// MAC and an import route target of the VRF, whose IP address lies in a gateway IP prefix of the stretch, is also a host route
// of the VRF, a /32 or a /128: the node gets it in a learned message with the vrf, the second label as its vni, the router MAC
// and the VTEP of the fabric as its next hop, as it gets an IP prefix route of the fabric (evpn.go), so that a packet of the
// VRF to the host goes through the L3 VNI and the node takes the frames of the host from the L3 VNI. A route of the MAC plus
// IP form without a second label, as a fabric without symmetric IRB sends it, and a route of a default gateway give none. The
// gateway IP prefixes, not the accept list of the VRF, hold what the fabric may give the VRF this way. The watch of the EVPN
// (onEVPNPaths) takes these routes, so that the routes of the VRFs stay the state of one goroutine.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// maxGatewayIPs is the number of gateway IPs of a stretch with irb at most: one IPv4 and one IPv6, as a Network has one pool of
// each.
const maxGatewayIPs = 2

// stretchIRB is the IRB of a stretch, checked: the EVPN VRF of its Network and its gateway IPs with the prefix length of their
// subnet.
type stretchIRB struct {
	vrf      *evpnVRF
	gateways []netip.Prefix
}

// parseIRB checks the IRB of a stretch of an evpn object whose VRFs are vrfs; nil for a stretch without irb.
func parseIRB(s EVPNStretch, vrfs map[uint32]*evpnVRF) (*stretchIRB, error) {
	if !s.IRB {
		if s.VRF != 0 || len(s.GatewayIPs) != 0 {
			return nil, errors.New("vrf and gateway_ips are of irb, and a stretch without irb names neither")
		}
		return nil, nil
	}
	v := vrfs[s.VRF]
	if v == nil {
		return nil, fmt.Errorf("irb: vrf %d is no EVPN VRF of the gateway", s.VRF)
	}
	if len(s.GatewayIPs) == 0 || len(s.GatewayIPs) > maxGatewayIPs {
		return nil, fmt.Errorf("irb: gateway_ips holds 1 to %d addresses, one IPv4 and one IPv6 at most, not %d", maxGatewayIPs, len(s.GatewayIPs))
	}
	irb := &stretchIRB{vrf: v}
	for _, text := range s.GatewayIPs {
		g, err := parseGatewayIP(text)
		if err != nil {
			return nil, fmt.Errorf("irb: %w", err)
		}
		if slices.ContainsFunc(irb.gateways, func(o netip.Prefix) bool { return o.Addr().Is4() == g.Addr().Is4() }) {
			return nil, fmt.Errorf("irb: gateway_ips holds two addresses of the family of %s", g)
		}
		irb.gateways = append(irb.gateways, g)
	}
	return irb, nil
}

// parseGatewayIP parses a gateway IP with the prefix length of its subnet, as 10.50.0.1/24: the address of one host in a prefix
// of /1 to /31 for IPv4 and /1 to /127 for IPv6, which is not the first address of the prefix nor, for IPv4, its broadcast
// address. Both addresses of an IPv4 /31 and of an IPv6 /127 are hosts (RFC 3021, RFC 6164).
func parseGatewayIP(text string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(text)
	if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("gateway IP %q is not an address with the prefix length of its subnet", text)
	}
	a := p.Addr()
	if p.Bits() == 0 || p.Bits() >= a.BitLen() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return netip.Prefix{}, fmt.Errorf("gateway IP %q is not the address of one host in a subnet", text)
	}
	if p.Bits() < a.BitLen()-1 && a == p.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("gateway IP %q is the first address of its subnet, which names the subnet", text)
	}
	if a.Is4() && p.Bits() < 31 && a == lastAddr4(p) {
		return netip.Prefix{}, fmt.Errorf("gateway IP %q is the broadcast address of its subnet", text)
	}
	return p, nil
}

// lastAddr4 is the last address of the IPv4 prefix p, of /1 to /32: its broadcast address.
func lastAddr4(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])|(uint32(1)<<(32-p.Bits())-1))
	return netip.AddrFrom4(b)
}

// irbPath is the path of a type-2 route of the gateway on the stretch v with irb, whose NLRI is nlri: the VTEP as its next hop,
// the route targets of the stretch and the export route targets of its VRF, the VXLAN encapsulation and the router MAC of the
// gateway, and for a gateway IP the default gateway extended community.
func (e *evpnState) irbPath(v *stretchVNI, nlri bgp.NLRI, gateway bool) (*apiutil.Path, error) {
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, e.vtep)
	if err != nil {
		return nil, err
	}
	ecs := slices.Concat(v.targets, v.irb.vrf.exports)
	ecs = append(ecs, bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN), bgp.NewRoutersMacExtended(e.mac))
	if gateway {
		ecs = append(ecs, bgp.NewDefaultGatewayExtended())
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), reach, bgp.NewPathAttributeExtendedCommunities(ecs)}
	return &apiutil.Path{Family: bgp.RF_EVPN, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix()}, nil
}

// gatewayPath is the type-2 route of the gateway IP g of the stretch v with irb: the router MAC of the gateway with g, the L2 VNI
// and the L3 VNI of the VRF as its labels, as irbPath makes it, with the default gateway extended community.
func (e *evpnState) gatewayPath(v *stretchVNI, g netip.Prefix) (*apiutil.Path, error) {
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(v.rd, bgp.EthernetSegmentIdentifier{}, 0, e.mac, g.Addr(), []uint32{v.vni, v.irb.vrf.vni})
	if err != nil {
		return nil, err
	}
	return e.irbPath(v, nlri, true)
}

// announceGateways announces the type-2 route of each gateway IP of the stretch v (gatewayPath). Nothing for a stretch without
// irb, which announces no gateway IP or MAC of its Network.
func (s *session) announceGateways(v *stretchVNI) error {
	if v.irb == nil {
		return nil
	}
	for _, g := range v.irb.gateways {
		path, err := s.evpn.gatewayPath(v, g)
		if err == nil {
			_, err = s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
		}
		if err != nil {
			return fmt.Errorf("the gateway IP %s: %w", g, err)
		}
	}
	s.log.Info("EVPN IRB gateway announced", "vni", v.vni, "vrf", v.irb.vrf.id, "l3vni", v.irb.vrf.vni, "mac", s.evpn.mac, "gateways", v.irb.gateways)
	return nil
}

// routerMACOf is the router MAC among the extended communities of a path, as net.HardwareAddr prints it; "" for none.
func routerMACOf(attrs []bgp.PathAttributeInterface) string {
	for _, a := range attrs {
		if ecs, ok := a.(*bgp.PathAttributeExtendedCommunities); ok {
			for _, c := range ecs.Value {
				if m, ok := c.(*bgp.RouterMacExtended); ok && len(m.Mac) == 6 {
					return m.Mac.String()
				}
			}
		}
	}
	return ""
}

// hasDefaultGateway reports whether the extended communities of a path hold the default gateway one (RFC 7432 section 7.8).
func hasDefaultGateway(attrs []bgp.PathAttributeInterface) bool {
	for _, a := range attrs {
		if ecs, ok := a.(*bgp.PathAttributeExtendedCommunities); ok {
			for _, c := range ecs.Value {
				if _, ok := c.(*bgp.DefaultGatewayExtended); ok {
					return true
				}
			}
		}
	}
	return false
}

// irbHost is the host route of the VRF of a stretch with irb that the type-2 route r of the path p of a peer gives: its key, the
// route as the node is told about it, and why the gateway leaves it out, "" when it takes it. ok is false for a route that gives
// no host route at all: of no stretch with irb, or one that the stretch leaves out, in the MAC only form, in the MAC plus IP
// form without a second label, or of a default gateway.
func (e *evpnState) irbHost(p *apiutil.Path, n *bgp.EVPNNLRI, r *bgp.EVPNMacIPAdvertisementRoute) (key evpnKey, route evpnRoute, why string, ok bool) {
	if e.stretch == nil {
		return evpnKey{}, evpnRoute{}, "", false
	}
	host, vtep, skip, taken := e.stretch.routeOf(p, n)
	v := e.stretch.byVNI[host.vni]
	if !taken || skip != "" || v == nil || v.irb == nil || !host.ip.IsValid() || len(r.Labels) < 2 || hasDefaultGateway(p.Attrs) {
		return evpnKey{}, evpnRoute{}, "", false
	}
	key = evpnKey{vrf: v.irb.vrf.id, prefix: netip.PrefixFrom(host.ip, host.ip.BitLen())}
	route = evpnRoute{nextHop: vtep, vni: r.Labels[1], mac: routerMACOf(p.Attrs), peer: p.PeerAddress.Unmap()}
	switch {
	case route.vni == 0 || route.vni > maxVNI:
		why = "its second label is no VNI"
	case route.mac == "":
		why = "it has no router MAC"
	case !v.irb.vrf.importsAny(routeTargets(p.Attrs)):
		why = fmt.Sprintf("it carries no import route target of vrf %d", v.irb.vrf.id)
	case !slices.ContainsFunc(v.irb.gateways, func(g netip.Prefix) bool { return g.Masked().Contains(host.ip) }):
		why = "its IP address lies in no gateway IP prefix of the stretch"
	}
	return key, route, why, true
}

// irbOffer takes the type-2 route r of the path p of a peer, whose best path changed, into the host routes of the VRFs: the host
// route that its NLRI offered before goes, and the one that it offers now (irbHost) comes. It returns the keys whose offers
// changed, which reportEVPN tells the node about. The watch goroutine of the EVPN (onEVPNPaths) alone calls it.
func (e *evpnState) irbOffer(p *apiutil.Path, n *bgp.EVPNNLRI, r *bgp.EVPNMacIPAdvertisementRoute, log *slog.Logger) []evpnKey {
	name := n.String()
	var touched []evpnKey
	if old, had := e.irbNames[name]; had {
		delete(e.irbNames, name)
		e.drop(old, name)
		touched = append(touched, old)
	}
	key, route, why, ok := e.irbHost(p, n, r)
	if !ok || p.Withdrawal {
		return touched
	}
	if why != "" {
		log.Warn("EVPN IRB host route left out", "route", name, "peer", p.PeerAddress, "why", why)
		return touched
	}
	e.irbNames[name] = key
	e.offer(key, name, route)
	return append(touched, key)
}
