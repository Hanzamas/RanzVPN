package sidecar

// The L2 stretch of a gateway (ADR-0032 amendment of 2026-10-22; SDN-64 #291): the gateway extends L2 Networks of the
// overlay into a data-centre fabric, each on its own L2 VNI, with EVPN route types 2 and 3 (RFC 7432), VXLAN being their
// encapsulation (RFC 8365). The stretches of the evpn object of a start message name the L2 VNI of each Network, its route
// distinguisher (the router id and the VNI when left out) and its route targets, which the Network imports and exports.
//
// Into the fabric: at start the sidecar announces, for each stretch, the inclusive multicast Ethernet tag route (type 3) of
// the VTEP of the gateway, with a PMSI tunnel attribute of ingress replication whose label is the VNI (RFC 8365 section
// 5.1.3), so that the fabric floods the broadcast domain of the VNI to the gateway too. The node announces the MAC/IP
// advertisement routes (type 2) of the MAC addresses of the Network that it knows, MAC only, and MAC plus IP for an address
// that a MAC holds, in stretch messages of MaxStretchRoutes routes at most: a route with withdraw leaves the peers again. A
// message with full starts a full resync, which the node sends after the pipe came up: the routes of it and of the messages
// with more that follow it, to the one without more, are then every route of the gateway, and the sidecar withdraws each
// other route that it announced. Each type-2 route of the gateway has the route distinguisher of its stretch, no ESI,
// Ethernet tag 0 and the VNI as its label, the VTEP as its next hop, and the route targets of the stretch and the VXLAN
// encapsulation as its extended communities.
//
// Out of the fabric: a type-2 or type-3 route of a peer that carries a route target of a stretch, and the VNI of that stretch
// as its label (type 2) or as the label of its PMSI tunnel of ingress replication (type 3), goes to the node in stretch
// messages of MaxStretchRoutes routes at most, as learned, and with withdraw once it went: a type-2 route with its MAC, its IP
// when it has one and the VTEP of the fabric, its next hop, as next_hop; a type-3 route without a MAC, with the VTEP of its
// tunnel as next_hop. Of the routes that the peers offer for one MAC and IP of a VNI, or for one VTEP of a VNI, the node has
// one: the one that it has while a peer still offers it, else the one of the lowest NLRI; a route that moves to another VTEP
// is one learned route, without a withdraw between. The node holds the MAC addresses of the fabric behind each VTEP, and the
// type-3 routes are the flood list of each VNI. When the pipe closes, the session ends, and the next sidecar learns every
// route of the peers again, which is the full resync of this direction.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// MaxStretchRoutes is the number of routes of one stretch message at most, either way (ADR-0032 amendment of 2026-10-22).
const MaxStretchRoutes = 500

// maxStretchTargets is the number of route targets of one stretch at most, as the Stretch resource has them (SDN-63 #290).
const maxStretchTargets = 8

// EVPNStretch is one L2 Network that a gateway stretches into the fabric, in the evpn object of a start message: its L2
// VNI, the route distinguisher of its routes (the router id and the VNI when left out) and its route targets, which the
// Network imports and exports. The node reads the same object, with network, the name of the L2 Network, which the sidecar
// does not read.
type EVPNStretch struct {
	VNI          uint32   `json:"vni"`
	RD           string   `json:"rd,omitempty"`
	RouteTargets []string `json:"route_targets"`
}

// StretchRoute is one EVPN route of an L2 VNI in a stretch message: a MAC/IP advertisement route (type 2) when it has a
// mac, with an ip for the MAC plus IP form, or an inclusive multicast Ethernet tag route (type 3) when it has none. A
// route of the sidecar has the VTEP of the fabric as next_hop; a route of the node has none. With withdraw, the route goes.
type StretchRoute struct {
	VNI      uint32 `json:"vni"`
	MAC      string `json:"mac,omitempty"`
	IP       string `json:"ip,omitempty"`
	NextHop  string `json:"next_hop,omitempty"`
	Withdraw bool   `json:"withdraw,omitempty"`
}

// stretchVNI is a stretch of an evpn object, checked.
type stretchVNI struct {
	vni     uint32
	rd      bgp.RouteDistinguisherInterface
	targets []bgp.ExtendedCommunityInterface // imported and exported
	imports map[string]bool                  // the same, as bgp prints them
}

// stretchKey is a route of a VNI: a type-2 route with its MAC, as net.HardwareAddr prints it, and its IP (the zero Addr for
// MAC only), or a type-3 route, whose MAC is "", with its VTEP as the IP.
type stretchKey struct {
	vni uint32
	mac string
	ip  netip.Addr
}

// stretchState is the stretch of a session, from its start message.
type stretchState struct {
	list  []*stretchVNI
	byVNI map[uint32]*stretchVNI

	// The read loop only: the type-2 routes that the node announces, and the routes of a full resync so far, nil outside one
	announced map[stretchKey]uuid.UUID
	full      map[stretchKey]bool

	// The watch goroutine only: the NLRI of each route of a peer that the sidecar takes, with its key and its VTEP; the VTEPs
	// that offer each key, by NLRI; and the VTEP of each key that the node was told about
	names    map[string]stretchKey
	offers   map[stretchKey]map[string]netip.Addr
	reported map[stretchKey]netip.Addr
}

// parseStretches checks the stretches of an evpn object whose router id is routerID, and whose VRFs have the L3 VNIs l3;
// nil for none.
func parseStretches(list []EVPNStretch, routerID netip.Addr, l3 map[uint32]uint32) (*stretchState, error) {
	if len(list) == 0 {
		return nil, nil
	}
	st := &stretchState{
		byVNI:     make(map[uint32]*stretchVNI),
		announced: make(map[stretchKey]uuid.UUID),
		names:     make(map[string]stretchKey),
		offers:    make(map[stretchKey]map[string]netip.Addr),
		reported:  make(map[stretchKey]netip.Addr),
	}
	for _, s := range list {
		v, err := parseStretch(s, routerID)
		if err != nil {
			return nil, fmt.Errorf("start: evpn: stretch of vni %d: %w", s.VNI, err)
		}
		if st.byVNI[v.vni] != nil {
			return nil, fmt.Errorf("start: evpn: stretch of vni %d comes twice", v.vni)
		}
		if vrf, ok := l3[v.vni]; ok {
			return nil, fmt.Errorf("start: evpn: stretch of vni %d: the VNI is the L3 VNI of vrf %d", v.vni, vrf)
		}
		st.byVNI[v.vni] = v
		st.list = append(st.list, v)
	}
	return st, nil
}

// parseStretch checks one stretch of an evpn object.
func parseStretch(s EVPNStretch, routerID netip.Addr) (*stretchVNI, error) {
	if s.VNI == 0 || s.VNI > maxVNI {
		return nil, fmt.Errorf("vni %d is not a VNI of 24 bits", s.VNI)
	}
	rd := s.RD
	if rd == "" {
		if s.VNI > 0xFFFF {
			return nil, errors.New("rd is missing, and the VNI does not fit a route distinguisher of the router id")
		}
		rd = fmt.Sprintf("%s:%d", routerID, s.VNI)
	}
	parsed, err := bgp.ParseRouteDistinguisher(rd)
	if err != nil || parsed.String() != rd {
		return nil, fmt.Errorf("rd %q is not a route distinguisher", rd)
	}
	if len(s.RouteTargets) == 0 || len(s.RouteTargets) > maxStretchTargets {
		return nil, fmt.Errorf("a stretch has 1 to %d route targets, not %d", maxStretchTargets, len(s.RouteTargets))
	}
	v := &stretchVNI{vni: s.VNI, rd: parsed, imports: make(map[string]bool)}
	for _, rt := range s.RouteTargets {
		ec, err := parseRouteTarget(rt)
		if err != nil {
			return nil, err
		}
		v.targets = append(v.targets, ec)
		v.imports[ec.String()] = true
	}
	return v, nil
}

// stretches is the stretch of the session, nil for a session without one.
func (s *session) stretches() *stretchState {
	if s.evpn == nil {
		return nil
	}
	return s.evpn.stretch
}

// communities are the extended communities of a route of the stretch v: its route targets and the VXLAN encapsulation.
func (v *stretchVNI) communities() bgp.PathAttributeInterface {
	ecs := slices.Clone(v.targets)
	ecs = append(ecs, bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN))
	return bgp.NewPathAttributeExtendedCommunities(ecs)
}

// stretchPath is the path of a route of the gateway on the stretch v, whose NLRI is nlri: the VTEP as its next hop, and the
// attributes extra besides its origin, its next hop and its extended communities.
func (e *evpnState) stretchPath(v *stretchVNI, nlri bgp.NLRI, extra ...bgp.PathAttributeInterface) (*apiutil.Path, error) {
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, e.vtep)
	if err != nil {
		return nil, err
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), reach, v.communities()}
	return &apiutil.Path{Family: bgp.RF_EVPN, Nlri: nlri, Attrs: append(attrs, extra...), Age: time.Now().Unix()}, nil
}

// imetPath is the inclusive multicast Ethernet tag route (type 3) of the VTEP of the gateway on the stretch v, with a PMSI
// tunnel of ingress replication to the VTEP whose label is the VNI.
func (e *evpnState) imetPath(v *stretchVNI) (*apiutil.Path, error) {
	nlri, err := bgp.NewEVPNMulticastEthernetTagRoute(v.rd, 0, e.vtep)
	if err != nil {
		return nil, err
	}
	id, err := bgp.NewIngressReplTunnelID(e.vtep)
	if err != nil {
		return nil, err
	}
	return e.stretchPath(v, nlri, bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, v.vni, id))
}

// macPath is the MAC/IP advertisement route (type 2) of the gateway of key on its stretch v: no ESI, Ethernet tag 0 and the
// VNI as its label.
func (e *evpnState) macPath(v *stretchVNI, key stretchKey) (*apiutil.Path, error) {
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(v.rd, bgp.EthernetSegmentIdentifier{}, 0, key.mac, key.ip, []uint32{v.vni})
	if err != nil {
		return nil, err
	}
	return e.stretchPath(v, nlri)
}

// startStretch announces the type-3 route of the VTEP of the gateway on each stretch, and starts the watch of the best
// paths of the peers that the routes of the stretches come from (onStretchPaths), which stops with the session. Nothing for
// a session without a stretch.
func (s *session) startStretch() error {
	st := s.stretches()
	if st == nil {
		return nil
	}
	for _, v := range st.list {
		path, err := s.evpn.imetPath(v)
		if err == nil {
			_, err = s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
		}
		if err != nil {
			return fmt.Errorf("the type-3 route of vni %d: %w", v.vni, err)
		}
	}
	wctx, cancel := context.WithCancel(context.Background())
	stop := s.cancel
	s.cancel = func() {
		cancel()
		stop()
	}
	if err := s.bgp.WatchEvent(wctx, server.WatchEventMessageCallbacks{OnBestPath: s.onStretchPaths}, server.WatchBestPath(true)); err != nil {
		return err
	}
	s.log.Info("EVPN stretch started", "vtep", s.evpn.vtep, "stretches", len(st.list))
	return nil
}

// parseMAC is the MAC address of one host of text, as net.HardwareAddr prints it.
func parseMAC(text string) (string, error) {
	hw, err := net.ParseMAC(text)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 || slices.Equal(hw, make(net.HardwareAddr, 6)) {
		return "", fmt.Errorf("mac %q is not the MAC address of one host", text)
	}
	return hw.String(), nil
}

// parseHostIP is the IP address of one host of text: no zone, not unspecified, not a multicast or a loopback address.
func parseHostIP(text string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(text)
	if err == nil {
		ip = ip.Unmap()
	}
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("ip %q is not the address of one host", text)
	}
	return ip, nil
}

// keyOf checks a route of a stretch message of the node: a type-2 route of the VNI of a stretch, with the MAC of one host
// and, in the MAC plus IP form, the address of one host, and no next hop, which is the VTEP of the gateway.
func (st *stretchState) keyOf(r StretchRoute) (*stretchVNI, stretchKey, error) {
	v := st.byVNI[r.VNI]
	if v == nil {
		return nil, stretchKey{}, fmt.Errorf("vni %d is the VNI of no stretch of the gateway", r.VNI)
	}
	if r.MAC == "" {
		return nil, stretchKey{}, fmt.Errorf("vni %d: the node announces type-2 routes, which have a mac: the type-3 route of the gateway is the sidecar's", r.VNI)
	}
	if r.NextHop != "" {
		return nil, stretchKey{}, fmt.Errorf("vni %d: a route of the node names no next hop: the VTEP of the gateway is the next hop of its routes", r.VNI)
	}
	mac, err := parseMAC(r.MAC)
	if err != nil {
		return nil, stretchKey{}, err
	}
	key := stretchKey{vni: v.vni, mac: mac}
	if r.IP != "" {
		if key.ip, err = parseHostIP(r.IP); err != nil {
			return nil, stretchKey{}, err
		}
	}
	return v, key, nil
}

// stretchMessage applies a stretch message of the node: each route is a type-2 route of the gateway, which goes to the
// peers, or leaves them with withdraw; a message with full starts a full resync, which the one without more ends, and the
// routes that it did not name leave the peers then. A message of a route that is none is refused whole.
func (s *session) stretchMessage(m Message) error {
	st := s.stretches()
	if st == nil {
		return errors.New("stretch: the evpn object of the start names no stretch")
	}
	if len(m.Routes) > MaxStretchRoutes {
		return fmt.Errorf("stretch: %d routes in one message, more than %d", len(m.Routes), MaxStretchRoutes)
	}
	vs := make([]*stretchVNI, len(m.Routes))
	keys := make([]stretchKey, len(m.Routes))
	for i, r := range m.Routes {
		v, key, err := st.keyOf(r)
		if err == nil && r.Withdraw && (m.Full || st.full != nil) {
			err = errors.New("a full resync announces its routes and withdraws none")
		}
		if err != nil {
			return fmt.Errorf("stretch: route %d: %w", i, err)
		}
		vs[i], keys[i] = v, key
	}
	if m.Full {
		st.full = make(map[stretchKey]bool)
	}

	added, withdrawn := 0, 0
	for i, r := range m.Routes {
		key := keys[i]
		if st.full != nil {
			st.full[key] = true
		}
		id, had := st.announced[key]
		switch {
		case r.Withdraw && had:
			if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
				return fmt.Errorf("stretch: the withdraw of %s %s of vni %d: %w", key.mac, key.ip, key.vni, err)
			}
			delete(st.announced, key)
			withdrawn++
		case !r.Withdraw && !had:
			path, err := s.evpn.macPath(vs[i], key)
			var resp []apiutil.AddPathResponse
			if err == nil {
				resp, err = s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
			}
			if err != nil {
				return fmt.Errorf("stretch: the route of %s %s of vni %d: %w", key.mac, key.ip, key.vni, err)
			}
			st.announced[key] = resp[0].UUID
			added++
		}
	}

	// The last message of a full resync: the routes that it did not name go
	if st.full != nil && !m.More {
		for _, key := range slices.Collect(maps.Keys(st.announced)) {
			if st.full[key] {
				continue
			}
			if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{st.announced[key]}}); err != nil {
				return fmt.Errorf("stretch: the withdraw of %s %s of vni %d after the resync: %w", key.mac, key.ip, key.vni, err)
			}
			delete(st.announced, key)
			withdrawn++
		}
		s.log.Info("EVPN stretch resynced", "routes", len(st.announced), "withdrawn", withdrawn)
		st.full = nil
	}
	s.log.Info("EVPN stretch routes", "announced", added, "withdrawn", withdrawn, "full", m.Full, "more", m.More, "total", len(st.announced))
	return nil
}

// targetsOf are the route targets among the attributes of a path, as bgp prints them, and its encapsulation (VXLAN when it
// names none) and PMSI tunnel (nil for none).
func targetsOf(p *apiutil.Path) ([]string, bgp.TunnelType, *bgp.PathAttributePmsiTunnel) {
	encap := bgp.TUNNEL_TYPE_VXLAN
	var pmsi *bgp.PathAttributePmsiTunnel
	for _, a := range p.Attrs {
		switch a := a.(type) {
		case *bgp.PathAttributeExtendedCommunities:
			for _, c := range a.Value {
				if e, ok := c.(*bgp.EncapExtended); ok {
					encap = e.TunnelType
				}
			}
		case *bgp.PathAttributePmsiTunnel:
			pmsi = a
		}
	}
	return routeTargets(p.Attrs), encap, pmsi
}

// routeOf is the key and the VTEP of a type-2 or type-3 route of a peer, or why the gateway leaves it out; ok is false for
// any other route, and for a route of no stretch: one that carries no route target of a stretch, which a fabric has many
// of, and which the log does not name.
func (st *stretchState) routeOf(p *apiutil.Path, n *bgp.EVPNNLRI) (key stretchKey, vtep netip.Addr, why string, ok bool) {
	var vni uint32
	switch r := n.RouteTypeData.(type) {
	case *bgp.EVPNMacIPAdvertisementRoute:
		if len(r.Labels) != 0 {
			vni = r.Labels[0]
		}
		key.mac = r.MacAddress.String()
		if r.IPAddressLength != 0 {
			key.ip = r.IPAddress.Unmap()
		}
		vtep = pathNextHop(p).Unmap()
		switch {
		case r.MacAddressLength != 48 || len(r.MacAddress) != 6 || r.MacAddress[0]&1 != 0:
			why = "its MAC address is not the one of a host"
		case r.IPAddressLength != 0 && !key.ip.IsValid():
			why = "its IP address is none"
		}
	case *bgp.EVPNMulticastEthernetTagRoute:
		_, _, pmsi := targetsOf(p)
		if pmsi != nil {
			vni = pmsi.Label
			if id, ok := pmsi.TunnelID.(*bgp.IngressReplTunnelID); ok {
				vtep = id.Value.Unmap()
			}
		}
		key.ip = vtep
		if pmsi == nil || pmsi.TunnelType != bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL {
			why = "it has no PMSI tunnel of ingress replication"
		}
	default:
		return stretchKey{}, netip.Addr{}, "", false
	}

	targets, encap, _ := targetsOf(p)
	var v *stretchVNI
	for _, c := range st.list {
		for _, t := range targets {
			if c.imports[t] && (v == nil || c.vni == vni) {
				v = c
			}
		}
	}
	if v == nil {
		return stretchKey{}, netip.Addr{}, "", false
	}
	key.vni = v.vni
	switch {
	case why != "":
	case vni != v.vni:
		why = fmt.Sprintf("its VNI %d is not the L2 VNI %d of the stretch of its route target", vni, v.vni)
	case !vtep.IsValid() || vtep.IsUnspecified():
		why = "it names no VTEP"
	case encap != bgp.TUNNEL_TYPE_VXLAN:
		why = fmt.Sprintf("its encapsulation is %s, not VXLAN", encap)
	}
	return key, vtep, why, true
}

// onStretchPaths takes the type-2 and type-3 routes of the peers whose best path changed: a route of a stretch that the
// gateway takes is offered under its key, and one that went, or that the gateway leaves out, is no longer offered; the node
// is told about the keys whose route changed (reportStretch), in stretch messages. The gateway's own routes are no routes of
// a peer.
func (s *session) onStretchPaths(paths []*apiutil.Path, _ time.Time) {
	st := s.stretches()
	touched := make(map[stretchKey]bool)
	var order []stretchKey
	touch := func(key stretchKey) {
		if !touched[key] {
			touched[key] = true
			order = append(order, key)
		}
	}
	for _, p := range paths {
		n, ok := p.Nlri.(*bgp.EVPNNLRI)
		if !ok || p.Family != bgp.RF_EVPN || !p.PeerAddress.IsValid() {
			continue
		}
		name := n.String()
		key, vtep, why, ok := st.routeOf(p, n)
		if ok && why != "" && !p.Withdrawal {
			s.log.Warn("EVPN stretch route left out", "route", name, "peer", p.PeerAddress, "why", why)
		}
		// The route that the NLRI offered before goes, and the one that it offers now comes
		if old, had := st.names[name]; had {
			st.drop(old, name)
			touch(old)
		}
		if ok && why == "" && !p.Withdrawal {
			st.offer(key, name, vtep)
			touch(key)
		}
	}
	var routes []StretchRoute
	for _, key := range order {
		if r, changed := st.report(key); changed {
			routes = append(routes, r)
		}
	}
	s.sendStretch(routes)
}

// offer records vtep as the VTEP that the NLRI name offers for key.
func (st *stretchState) offer(key stretchKey, name string, vtep netip.Addr) {
	o := st.offers[key]
	if o == nil {
		o = make(map[string]netip.Addr)
		st.offers[key] = o
	}
	o[name] = vtep
	st.names[name] = key
}

// drop forgets what the NLRI name offered for key.
func (st *stretchState) drop(key stretchKey, name string) {
	delete(st.names, name)
	if o := st.offers[key]; o != nil {
		delete(o, name)
		if len(o) == 0 {
			delete(st.offers, key)
		}
	}
}

// report is the route of key that the node is told about when it changed: of the VTEPs that the peers offer for the key, the
// node has one, the one that it has while a peer still offers it, else the one of the lowest NLRI; a key that none offers
// any more is withdrawn with the VTEP that the node had.
func (st *stretchState) report(key stretchKey) (StretchRoute, bool) {
	old, had := st.reported[key]
	offers := st.offers[key]
	next, found := old, false
	if had {
		for _, vtep := range offers {
			if vtep == old {
				found = true
				break
			}
		}
	}
	if !found && len(offers) != 0 {
		next, found = offers[slices.Min(slices.Collect(maps.Keys(offers)))], true
	}
	r := StretchRoute{VNI: key.vni, MAC: key.mac}
	if key.mac != "" && key.ip.IsValid() {
		r.IP = key.ip.String()
	}
	switch {
	case !found && had:
		delete(st.reported, key)
		r.NextHop, r.Withdraw = old.String(), true
		return r, true
	case found && (!had || old != next):
		st.reported[key] = next
		r.NextHop = next.String()
		return r, true
	}
	return StretchRoute{}, false
}

// stretchLine is the size of the line of a stretch message of routes, with its newline.
func stretchLine(routes []StretchRoute) int {
	b, err := json.Marshal(Message{Type: TypeStretch, Routes: routes})
	if err != nil {
		return MaxLine + 1
	}
	return len(b) + 1
}

// sendStretch tells the node about routes, in stretch messages of MaxStretchRoutes routes at most, each a line of MaxLine
// bytes at most: a message whose line would be longer takes half of its routes, until it fits.
func (s *session) sendStretch(routes []StretchRoute) {
	for len(routes) != 0 {
		n := min(len(routes), MaxStretchRoutes)
		for n > 1 && stretchLine(routes[:n]) > MaxLine {
			n /= 2
		}
		s.send(Message{Type: TypeStretch, Routes: routes[:n]})
		learned := 0
		for _, r := range routes[:n] {
			if !r.Withdraw {
				learned++
			}
		}
		s.log.Info("EVPN stretch routes of the fabric", "learned", learned, "withdrawn", n-learned)
		routes = routes[n:]
	}
}
