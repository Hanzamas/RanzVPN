package sidecar

// The EVPN of a gateway (ADR-0032 decisions 1 to 3; SDN-25 #201): the node hands VRFs of the overlay to a data-centre
// fabric, and the fabric hands its VRFs to the overlay, as IP prefix routes, EVPN route type 5 (RFC 9136), with VXLAN as
// their encapsulation (RFC 8365). The evpn object of a start message names the VTEP of the node, its router MAC and the
// VRFs; every peer of such a sidecar also gets the L2VPN EVPN family, which BGP uses with the peers that offer it.
//
// An announce or withdraw whose vrf is one of these VRFs is a route of that VRF: an IP prefix route with the route
// distinguisher of the VRF, no ESI, Ethernet tag 0, no gateway IP and the L3 VNI of the VRF as its label, the VTEP as its
// next hop, and the export route targets of the VRF, the VXLAN encapsulation and the router MAC as its extended
// communities: the interface-less model of RFC 9136 section 4.4.1. One with the vrf of no such VRF is refused, and so is
// one with a vrf in a session without EVPN, unless it runs the peering of the standard mode (peering.go), which has no
// evpn: the prefix of a VRF never goes to the peers as a unicast route, where the prefixes of two VRFs would meet in one
// table. An IP prefix route of a peer goes to each VRF whose
// import route targets it carries and whose accept list covers its prefix, as a learned message with the vrf, the VTEP
// of the fabric as the next hop, the VNI and the router MAC of the fabric, and the next hops of all the routes that the
// peers offer for the prefix in the VRF, which the node takes frames from (evpn_vteps.go); when it goes, as a withdrawn
// message with the vrf and the VNI. The node installs neither into the Windows routing table: its own forwarding of the VRF carries them
// in VXLAN (src/Cedar/NodeEvpn.c), so two VRFs hand over the same prefix without conflict, each in its own VRF of the
// fabric.
//
// The gateway takes the interface-less model alone: a route with a gateway IP or an ESI (an overlay index), without a
// router MAC or with another encapsulation than VXLAN is left out, and the log of the sidecar says why.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// DefaultRouterMAC is the router MAC of a gateway whose evpn names none: the inner source of the frames that its node
// sends into the L3 VNIs, the inner destination of the frames that the fabric sends it, and the Router's MAC of its
// routes. The node has the same default (NODE_EVPN_ROUTER_MAC of src/Cedar/NodeEvpn.h). Two gateways of one fabric need
// router MACs of their own.
const DefaultRouterMAC = "02:52:5a:00:00:05"

// maxVNI is the largest VNI: a VNI has 24 bits.
const maxVNI = 0xFFFFFF

// The policy of EVPN in GoBGP: the import policy of the session rejects what none of its statements takes, and an EVPN
// route matches none of its prefix sets, so this one comes after it and takes the EVPN routes of the peers, which
// onEVPNPaths sorts into the VRFs by their route targets.
const (
	evpnImportPolicy    = "ranz-import-evpn"
	evpnImportStatement = "ranz-import-evpn-routes"
)

// EVPN is the evpn object of a start message: the VTEP of the gateway, which is the next hop of its routes, its router
// MAC (DefaultRouterMAC when left out) and the VRFs that it hands to the fabric. The node reads the same object for its
// data plane, with port and fabric_port, the UDP ports of its own VTEP and of the VTEPs of the fabric, which the
// sidecar does not read.
type EVPN struct {
	VTEP      string    `json:"vtep"`
	RouterMAC string    `json:"router_mac,omitempty"`
	VRFs      []EVPNVRF `json:"vrfs"`
	// The L2 Networks that the gateway stretches into the fabric (stretch.go; SDN-64 #291)
	Stretches []EVPNStretch `json:"stretches,omitempty"`
}

// EVPNVRF is one VRF of the overlay that a gateway hands to the fabric: its id, its L3 VNI, the route distinguisher of
// its routes (the router id and the VRF id when left out), the route targets that it imports and exports (ASN:NUMBER
// or IPV4:NUMBER, at least one of each), and the prefixes that it takes from the fabric, with their more specific ones
// (with none, nothing is learned).
type EVPNVRF struct {
	VRF    uint32   `json:"vrf"`
	VNI    uint32   `json:"vni"`
	RD     string   `json:"rd,omitempty"`
	Import []string `json:"import"`
	Export []string `json:"export"`
	Accept []string `json:"accept,omitempty"`
}

// evpnVRF is a VRF of an evpn object, checked.
type evpnVRF struct {
	id      uint32
	vni     uint32
	rd      bgp.RouteDistinguisherInterface
	imports map[string]bool                  // the import route targets, as bgp prints them
	exports []bgp.ExtendedCommunityInterface // the export route targets
	accept  []netip.Prefix
}

// evpnKey is a prefix of an EVPN VRF.
type evpnKey struct {
	vrf    uint32
	prefix netip.Prefix
}

// evpnRoute is an IP prefix route of a peer as the node is told about it.
type evpnRoute struct {
	nextHop netip.Addr // the VTEP of the fabric
	vni     uint32
	mac     string // the router MAC, as net.HardwareAddr prints it
	peer    netip.Addr
}

// evpnState is the EVPN of a session, from its start message.
type evpnState struct {
	vtep netip.Addr
	mac  string // the router MAC of the gateway, as net.HardwareAddr prints it
	vrfs []*evpnVRF
	byID map[uint32]*evpnVRF

	// The read loop only: the prefixes of the VRFs that the node announces
	announced map[evpnKey]uuid.UUID

	// The watch goroutine only: the routes of the peers that offer each prefix of a VRF, by their NLRI, the next hops
	// of those routes that the node was told about (offerVTEPs), and the route that it was told about
	offers   map[evpnKey]map[string]evpnRoute
	vteps    map[evpnKey][]netip.Addr
	reported map[evpnKey]evpnRoute

	// The L2 Networks that the gateway stretches (stretch.go; SDN-64 #291), nil for none
	stretch *stretchState
}

// parseEVPN checks the evpn object of a start message whose router id is routerID; nil for a start without one.
func parseEVPN(e *EVPN, routerID netip.Addr) (*evpnState, error) {
	if e == nil {
		return nil, nil
	}
	vtep, err := netip.ParseAddr(e.VTEP)
	if err != nil || vtep.Zone() != "" || vtep.Unmap().IsUnspecified() {
		return nil, fmt.Errorf("start: evpn: vtep %q is not the IP address of a VTEP", e.VTEP)
	}
	mac := e.RouterMAC
	if mac == "" {
		mac = DefaultRouterMAC
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return nil, fmt.Errorf("start: evpn: router_mac %q is not the MAC address of one host", e.RouterMAC)
	}
	if len(e.VRFs) == 0 && len(e.Stretches) == 0 {
		return nil, errors.New("start: evpn: no vrfs and no stretches")
	}
	st := &evpnState{
		vtep:      vtep.Unmap(),
		mac:       hw.String(),
		byID:      make(map[uint32]*evpnVRF),
		announced: make(map[evpnKey]uuid.UUID),
		offers:    make(map[evpnKey]map[string]evpnRoute),
		vteps:     make(map[evpnKey][]netip.Addr),
		reported:  make(map[evpnKey]evpnRoute),
	}
	vnis := make(map[uint32]uint32)
	for _, v := range e.VRFs {
		pv, err := parseEVPNVRF(v, routerID)
		if err != nil {
			return nil, fmt.Errorf("start: evpn: vrf %d: %w", v.VRF, err)
		}
		if st.byID[pv.id] != nil {
			return nil, fmt.Errorf("start: evpn: vrf %d comes twice", pv.id)
		}
		if other, ok := vnis[pv.vni]; ok {
			return nil, fmt.Errorf("start: evpn: vrf %d: vni %d is the VNI of vrf %d", pv.id, pv.vni, other)
		}
		vnis[pv.vni] = pv.id
		st.byID[pv.id] = pv
		st.vrfs = append(st.vrfs, pv)
	}
	// ... and its stretches (stretch.go; SDN-64 #291), whose L2 VNIs are no L3 VNIs of its VRFs
	stretch, err := parseStretches(e.Stretches, routerID, vnis)
	if err != nil {
		return nil, err
	}
	st.stretch = stretch
	return st, nil
}

// parseEVPNVRF checks one VRF of an evpn object.
func parseEVPNVRF(v EVPNVRF, routerID netip.Addr) (*evpnVRF, error) {
	if v.VRF == 0 {
		return nil, errors.New("the VRF id is missing")
	}
	if v.VNI == 0 || v.VNI > maxVNI {
		return nil, fmt.Errorf("vni %d is not a VNI of 24 bits", v.VNI)
	}
	rd := v.RD
	if rd == "" {
		if v.VRF > 0xFFFF {
			return nil, errors.New("rd is missing, and the VRF id does not fit a route distinguisher of the router id")
		}
		rd = fmt.Sprintf("%s:%d", routerID, v.VRF)
	}
	parsed, err := bgp.ParseRouteDistinguisher(rd)
	if err != nil || parsed.String() != rd {
		return nil, fmt.Errorf("rd %q is not a route distinguisher", rd)
	}
	if len(v.Import) == 0 || len(v.Export) == 0 {
		return nil, errors.New("a VRF needs its import and export route targets")
	}
	pv := &evpnVRF{id: v.VRF, vni: v.VNI, rd: parsed, imports: make(map[string]bool)}
	for _, rt := range v.Import {
		ec, err := parseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("import: %w", err)
		}
		pv.imports[ec.String()] = true
	}
	for _, rt := range v.Export {
		ec, err := parseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("export: %w", err)
		}
		pv.exports = append(pv.exports, ec)
	}
	for _, a := range v.Accept {
		p, err := parsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("accept: %w", err)
		}
		pv.accept = append(pv.accept, p)
	}
	return pv, nil
}

// parseRouteTarget parses a route target: ASN:NUMBER, IPV4:NUMBER, or HIGH.LOW:NUMBER for an ASN of 32 bits.
func parseRouteTarget(s string) (bgp.ExtendedCommunityInterface, error) {
	ec, err := bgp.ParseRouteTarget(s)
	if err != nil || ec.String() != s {
		return nil, fmt.Errorf("route target %q is not of the form ASN:NUMBER or IPV4:NUMBER", s)
	}
	return ec, nil
}

// has reports whether vrf is an EVPN VRF of the session; false for a session without EVPN.
func (e *evpnState) has(vrf uint32) bool {
	return e != nil && vrf != 0 && e.byID[vrf] != nil
}

// vrf is the EVPN VRF of the vrf of an announce or withdraw message, or why there is none: a VRF that the evpn object
// does not name, also in a session without EVPN.
func (e *evpnState) vrf(id uint32) (*evpnVRF, error) {
	if !e.has(id) {
		return nil, fmt.Errorf("VRF %d is no EVPN VRF of the gateway: the prefixes of a VRF go to the peers as its IP prefix routes alone", id)
	}
	return e.byID[id], nil
}

// importsAny reports whether the VRF imports one of the route targets.
func (v *evpnVRF) importsAny(targets []string) bool {
	for _, t := range targets {
		if v.imports[t] {
			return true
		}
	}
	return false
}

// accepts reports whether the accept list of the VRF covers p.
func (v *evpnVRF) accepts(p netip.Prefix) bool {
	for _, a := range v.accept {
		if a.Addr().Is4() == p.Addr().Is4() && a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// evpnFamily is the L2VPN EVPN family of GoBGP.
func evpnFamily() *api.Family {
	return &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}
}

// startEVPN starts the EVPN of the session before its peers: the import policy that takes the EVPN routes of the
// peers, and the watch of their best paths (onEVPNPaths), which stops with the session. Nothing for a session without
// EVPN.
func (s *session) startEVPN(ctx context.Context, e *evpnState) error {
	if e == nil {
		return nil
	}
	s.evpn = e
	err := s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: evpnImportPolicy,
		Statements: []*api.Statement{{
			Name:       evpnImportStatement,
			Conditions: &api.Conditions{AfiSafiIn: []*api.Family{evpnFamily()}},
			Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}})
	if err == nil {
		err = s.bgp.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
			Name:      globalRIB,
			Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:  []*api.Policy{{Name: evpnImportPolicy}},
		}})
	}
	if err == nil {
		wctx, cancel := context.WithCancel(context.Background())
		stop := s.cancel
		s.cancel = func() {
			cancel()
			stop()
		}
		err = s.bgp.WatchEvent(wctx, server.WatchEventMessageCallbacks{OnBestPath: s.onEVPNPaths}, server.WatchBestPath(true))
	}
	// The stretches of the gateway, with the type-3 route of its VTEP on each (stretch.go; SDN-64 #291)
	if err == nil {
		err = s.startStretch()
	}
	if err != nil {
		return fmt.Errorf("EVPN did not start: %w", err)
	}
	s.log.Info("EVPN started", "vtep", e.vtep, "routerMAC", e.mac, "vrfs", len(e.vrfs))
	return nil
}

// withEVPN gives a peer of a session with EVPN the L2VPN EVPN family too, which BGP uses with a peer that offers it.
func (s *session) withEVPN(p *api.Peer) *api.Peer {
	if s.evpn != nil {
		p.AfiSafis = append(p.AfiSafis, &api.AfiSafi{Config: &api.AfiSafiConfig{Family: evpnFamily(), Enabled: true}})
	}
	return p
}

// evpnPath is the IP prefix route of prefix in the VRF v: the route distinguisher of the VRF, no ESI, Ethernet tag 0,
// no gateway IP and the L3 VNI as the label, with the VTEP as the next hop, and the export route targets, the VXLAN
// encapsulation and the router MAC as its extended communities.
func (e *evpnState) evpnPath(v *evpnVRF, prefix netip.Prefix) (*apiutil.Path, error) {
	gw := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		gw = netip.IPv6Unspecified()
	}
	nlri, err := bgp.NewEVPNIPPrefixRoute(v.rd, bgp.EthernetSegmentIdentifier{}, 0, uint8(prefix.Bits()), prefix.Addr(), gw, v.vni)
	if err != nil {
		return nil, err
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, e.vtep)
	if err != nil {
		return nil, err
	}
	communities := slices.Clone(v.exports)
	communities = append(communities, bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN), bgp.NewRoutersMacExtended(e.mac))
	return &apiutil.Path{
		Family: bgp.RF_EVPN,
		Nlri:   nlri,
		Attrs: []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			reach,
			bgp.NewPathAttributeExtendedCommunities(communities),
		},
		Age: time.Now().Unix(),
	}, nil
}

// announceEVPN applies an announce with a vrf: the prefix goes to the peers as an IP prefix route of that EVPN VRF. The
// next hop of the route is the VTEP, so the message names none.
func (s *session) announceEVPN(m Message) error {
	v, err := s.evpn.vrf(m.VRF)
	if err != nil {
		return err
	}
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	if m.NextHop != "" {
		return fmt.Errorf("prefix %s of VRF %d: an announce of an EVPN VRF names no next hop: the VTEP %s is the next hop of its routes", prefix, v.id, s.evpn.vtep)
	}
	path, err := s.evpn.evpnPath(v, prefix)
	if err != nil {
		return err
	}
	resp, err := s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	if err != nil {
		return err
	}
	// A prefix announced again replaces its route, under a new UUID.
	s.evpn.announced[evpnKey{vrf: v.id, prefix: prefix}] = resp[0].UUID
	s.log.Info("EVPN prefix announced", "vrf", v.id, "prefix", prefix, "rd", v.rd, "vni", v.vni)
	return nil
}

// withdrawEVPN applies a withdraw with a vrf, of a prefix of that EVPN VRF.
func (s *session) withdrawEVPN(m Message) error {
	v, err := s.evpn.vrf(m.VRF)
	if err != nil {
		return err
	}
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	key := evpnKey{vrf: v.id, prefix: prefix}
	id, ok := s.evpn.announced[key]
	if !ok {
		return fmt.Errorf("prefix %s is not announced in VRF %d", prefix, v.id)
	}
	if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return err
	}
	delete(s.evpn.announced, key)
	s.log.Info("EVPN prefix withdrawn", "vrf", v.id, "prefix", prefix)
	return nil
}

// routeTargets are the route targets among the extended communities of a path, as bgp prints them.
func routeTargets(attrs []bgp.PathAttributeInterface) []string {
	var out []string
	for _, a := range attrs {
		ecs, ok := a.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ecs.Value {
			var sub bgp.ExtendedCommunityAttrSubType
			switch c := c.(type) {
			case *bgp.TwoOctetAsSpecificExtended:
				sub = c.SubType
			case *bgp.IPv4AddressSpecificExtended:
				sub = c.SubType
			case *bgp.FourOctetAsSpecificExtended:
				sub = c.SubType
			case *bgp.IPv6AddressSpecificExtended:
				sub = c.SubType
			default:
				continue
			}
			if sub == bgp.EC_SUBTYPE_ROUTE_TARGET {
				out = append(out, c.String())
			}
		}
	}
	return out
}

// evpnRouteOf is the route of the IP prefix route r of the path p as the node is told about it, or why the gateway
// leaves it out: it takes the interface-less model of RFC 9136 section 4.4.1 alone.
func evpnRouteOf(p *apiutil.Path, r *bgp.EVPNIPPrefixRoute) (evpnRoute, string) {
	route := evpnRoute{nextHop: pathNextHop(p).Unmap(), vni: r.Label, peer: p.PeerAddress.Unmap()}
	encap := bgp.TUNNEL_TYPE_VXLAN
	for _, a := range p.Attrs {
		ecs, ok := a.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ecs.Value {
			switch c := c.(type) {
			case *bgp.RouterMacExtended:
				if len(c.Mac) == 6 {
					route.mac = c.Mac.String()
				}
			case *bgp.EncapExtended:
				encap = c.TunnelType
			}
		}
	}
	esi := r.ESI.Type != 0 || slices.ContainsFunc(r.ESI.Value, func(b byte) bool { return b != 0 })
	switch {
	case !route.nextHop.IsValid() || route.nextHop.IsUnspecified():
		return route, "it has no next hop"
	case route.vni == 0 || route.vni > maxVNI:
		return route, "its label is no VNI"
	case r.GWIPAddress.IsValid() && !r.GWIPAddress.IsUnspecified():
		return route, "it has a gateway IP, an overlay index that the gateway does not resolve"
	case esi:
		return route, "it has an ESI, an overlay index that the gateway does not resolve"
	case encap != bgp.TUNNEL_TYPE_VXLAN:
		return route, fmt.Sprintf("its encapsulation is %s, not VXLAN", encap)
	case route.mac == "":
		return route, "it has no router MAC"
	}
	return route, ""
}

// onEVPNPaths sorts the IP prefix routes of the peers whose best path changed into the EVPN VRFs: a route goes to each
// VRF whose import route targets it carries and whose accept list covers its prefix, and leaves the others. The
// gateway's own routes are no routes of a peer.
func (s *session) onEVPNPaths(paths []*apiutil.Path, _ time.Time) {
	e := s.evpn
	touched := make(map[evpnKey]bool)
	var order []evpnKey
	for _, p := range paths {
		n, ok := p.Nlri.(*bgp.EVPNNLRI)
		if !ok || p.Family != bgp.RF_EVPN || !p.PeerAddress.IsValid() {
			continue
		}
		r, ok := n.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
		if !ok {
			continue
		}
		prefix := netip.PrefixFrom(r.IPPrefix.Unmap(), int(r.IPPrefixLength)).Masked()
		if !prefix.IsValid() {
			continue
		}
		name := n.String()
		route, why := evpnRouteOf(p, r)
		if why != "" && !p.Withdrawal {
			s.log.Warn("EVPN route left out", "route", name, "peer", p.PeerAddress, "why", why)
		}
		targets := routeTargets(p.Attrs)
		for _, v := range e.vrfs {
			key := evpnKey{vrf: v.id, prefix: prefix}
			if !touched[key] {
				touched[key] = true
				order = append(order, key)
			}
			if p.Withdrawal || why != "" || !v.importsAny(targets) || !v.accepts(prefix) {
				e.drop(key, name)
			} else {
				e.offer(key, name, route)
			}
		}
	}
	for _, key := range order {
		s.reportEVPN(key)
	}
}

// offer records route as the route of the NLRI name for a prefix of a VRF.
func (e *evpnState) offer(key evpnKey, name string, route evpnRoute) {
	o := e.offers[key]
	if o == nil {
		o = make(map[string]evpnRoute)
		e.offers[key] = o
	}
	o[name] = route
}

// drop forgets the route of the NLRI name for a prefix of a VRF.
func (e *evpnState) drop(key evpnKey, name string) {
	if o := e.offers[key]; o != nil {
		delete(o, name)
		if len(o) == 0 {
			delete(e.offers, key)
		}
	}
}

// reportEVPN tells the node about a prefix of a VRF when its route changed. Of the routes that the peers offer for it
// (one peer under several route distinguishers, or several peers), the node has one: the one it has while a peer still
// offers it, else the one of the lowest NLRI. A route that moves to another one is one learned message, without a
// withdrawn message between, and a prefix that none offers any more is a withdrawn message with the VNI of its route.
// The learned message names the next hops of all the routes that the peers offer for the prefix (offerVTEPs), so that
// the node takes the frames of a leaf whose route lost too, and it goes again when they change (SDN-25-R3 #571).
func (s *session) reportEVPN(key evpnKey) {
	e := s.evpn
	old, had := e.reported[key]
	offers := e.offers[key]
	var next evpnRoute
	found := false
	if had {
		for _, r := range offers {
			if r == old {
				next, found = r, true
				break
			}
		}
	}
	if !found && len(offers) != 0 {
		next, found = offers[slices.Min(slices.Collect(maps.Keys(offers)))], true
	}
	vteps := offerVTEPs(offers, next.nextHop)
	switch {
	case !found && had:
		delete(e.reported, key)
		delete(e.vteps, key)
		s.log.Info("EVPN route withdrawn", "vrf", key.vrf, "prefix", key.prefix, "peer", old.peer)
		s.send(Message{Type: TypeWithdrawn, VRF: key.vrf, Prefix: key.prefix.String(), VNI: old.vni, Peer: old.peer.String()})
	case found && (!had || old != next || !slices.Equal(e.vteps[key], vteps)):
		e.reported[key] = next
		e.vteps[key] = vteps
		s.log.Info("EVPN route learned", "vrf", key.vrf, "prefix", key.prefix, "nextHop", next.nextHop, "vni", next.vni, "routerMAC", next.mac, "peer", next.peer, "vteps", vteps)
		s.send(Message{Type: TypeLearned, VRF: key.vrf, Prefix: key.prefix.String(), NextHop: next.nextHop.String(), VTEPs: vtepTexts(vteps), VNI: next.vni,
			RouterMAC: next.mac, Peer: next.peer.String()})
	}
}
