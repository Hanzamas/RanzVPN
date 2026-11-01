package sidecar

// The peering of the standard mode (SDN-77 #357): two Ranz nodes exchange the prefixes of the VRFs
// that they share by BGP, as routers do, on a network that the operator trusts. The Controller names
// the peers of each node and what each may announce in each VRF; it is not in the path of the routes.
// All the nodes are in one AS, so each node has a session with every other node of a VRF (a full
// mesh) or with a route reflector (SDN-79), and passes on nothing that it learned. A route is a VPN
// route (RFC 4364) whose route distinguisher and route target hold the VRF id, so the routes of two
// VRFs stay apart over the one session of two nodes, even for the same prefix. The node announces
// its LAN subnets and its addresses in each VRF and installs in the forwarding table of a VRF what it
// learns there; the sidecar reports a learned route only when the peer may announce it in that VRF
// (accepts): exactly a prefix of its accept list, so a peer that announces more specific prefixes,
// as many as it likes, fills the node with none of them (SDN-77-R1 #531). A path that a node may not
// announce takes no part in the choice of the best path either, so it hides no path of another node,
// whatever its route distinguisher and LOCAL_PREF, and a node that announces more paths than the
// maximum loses its session (SDN-77-R3 #570; peerfilter.go). Of two nodes,
// the one of the lower address connects and the other waits, so the two never race for the session.
// GoBGP refuses a session from an address that no peer has, and the sidecar tells the node about each
// one (refused).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	// rdAdmin is the administrator field of the route distinguisher and of the route target of a VPN
	// route of the peering: their assigned number is the VRF id.
	rdAdmin = 0
	// defaultHoldTime is the BGP hold time in seconds of a session with a Ranz node that names none,
	// and minHoldTime the shortest one other than 0 (RFC 4271 section 4.2).
	defaultHoldTime = 90
	minHoldTime     = 3
	// nodeConnectRetry is the time in seconds between two connects to a Ranz node that does not answer.
	nodeConnectRetry = 2
	// gobgpRefused is what GoBGP logs when it closes a session from an address that no peer has
	// (passConnToPeer of its server).
	gobgpRefused = "Can't find configuration for a new passive connection"
)

// routeKey is a prefix of a VRF: VRF 0 for the routes of the routers of the operator.
type routeKey struct {
	vrf    uint32
	prefix netip.Prefix
}

// parsePeeringAddress checks the address of a start message of the peering of the standard mode:
// the address of one node, which takes the place of listen_addresses and of accept.
func parsePeeringAddress(m Message) (netip.Addr, error) {
	a, err := netip.ParseAddr(m.Address)
	if err != nil || a.Zone() != "" || a.Unmap().IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("start: address %q is not the address of one node", m.Address)
	}
	if len(m.ListenAddresses) > 0 || len(m.Accept) > 0 {
		return netip.Addr{}, errors.New("start: with an address the sidecar listens there and takes from each peer the prefixes of its vrfs, so listen_addresses and accept are not given")
	}
	return a.Unmap(), nil
}

// parsePeer checks a peer of a start or a peers message: a router of the operator when local, the
// node's own address, is the zero Addr, and a Ranz node of the peering of the standard mode
// otherwise, which has an address of the family of local, a hold time and the VRFs that it shares.
func parsePeer(p Peer, local netip.Addr) (peerConfig, error) {
	addr, err := netip.ParseAddr(p.Address)
	if err != nil {
		return peerConfig{}, fmt.Errorf("peer address %q: %v", p.Address, err)
	}
	pc := peerConfig{address: addr, asn: p.ASN, port: p.Port, passive: p.Passive}
	if p.ASN == 0 {
		return pc, fmt.Errorf("peer %s has no asn", addr)
	}
	if p.Port > 65535 {
		return pc, fmt.Errorf("peer %s: port %d is not a TCP port", addr, p.Port)
	}
	if !local.IsValid() {
		if p.HoldTime != 0 || len(p.VRFs) > 0 {
			return pc, fmt.Errorf("peer %s: hold_time and vrfs are of the peering of the standard mode, which only a start with an address runs", addr)
		}
		return pc, nil
	}

	pc.address = addr.Unmap()
	if pc.address.Is4() != local.Is4() || pc.address == local {
		return pc, fmt.Errorf("peer %s is not another address of the family of the node's address %s", pc.address, local)
	}
	if p.HoldTime != 0 && (p.HoldTime < minHoldTime || p.HoldTime > 65535) {
		return pc, fmt.Errorf("peer %s: hold_time %d is not 0 or from %d to 65535", pc.address, p.HoldTime, minHoldTime)
	}
	if len(p.VRFs) == 0 {
		return pc, fmt.Errorf("peer %s shares no vrfs with the node", pc.address)
	}
	pc.holdTime = p.HoldTime
	pc.vrfs = make(map[uint32][]netip.Prefix)
	for _, v := range p.VRFs {
		if v.ID == 0 {
			return pc, fmt.Errorf("peer %s: a VRF without an id", pc.address)
		}
		if _, ok := pc.vrfs[v.ID]; ok {
			return pc, fmt.Errorf("peer %s: VRF %d comes twice", pc.address, v.ID)
		}
		accept := []netip.Prefix{}
		for _, a := range v.Accept {
			prefix, err := parsePrefix(a)
			if err != nil {
				return pc, fmt.Errorf("peer %s: VRF %d: accept: %v", pc.address, v.ID, err)
			}
			accept = append(accept, prefix)
		}
		pc.vrfs[v.ID] = accept
		// The role of the peer in a VRF of route reflectors (reflector.go; SDN-79 #359)
		if err := pc.setRole(v); err != nil {
			return pc, err
		}
	}
	return pc, nil
}

// equal reports whether two Ranz nodes of the peering have the same settings.
func (p peerConfig) equal(q peerConfig) bool {
	return p.address == q.address && p.asn == q.asn && p.port == q.port && p.holdTime == q.holdTime &&
		maps.EqualFunc(p.vrfs, q.vrfs, func(a, b []netip.Prefix) bool { return slices.Equal(a, b) }) && maps.Equal(p.roles, q.roles)
}

// nodePeer is the GoBGP peer of a Ranz node in the peering of the standard mode, with IPv4 and IPv6
// VPN routes, whose session goes from local, the node's own address: the node of the higher address
// waits for the other to connect.
func nodePeer(p peerConfig, local netip.Addr) *api.Peer {
	hold := uint64(p.holdTime)
	if hold == 0 {
		hold = defaultHoldTime
	}
	return &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.address.String(),
			PeerAsn:         p.asn,
		},
		Transport: &api.Transport{
			LocalAddress: local.String(),
			PassiveMode:  local.Compare(p.address) > 0,
			RemotePort:   p.port,
		},
		Timers: &api.Timers{Config: &api.TimersConfig{
			ConnectRetry:           nodeConnectRetry,
			HoldTime:               hold,
			KeepaliveInterval:      max(hold/3, 1),
			IdleHoldTimeAfterReset: 1,
		}},
		AfiSafis: []*api.AfiSafi{vpn(api.Family_AFI_IP), vpn(api.Family_AFI_IP6)},
	}
}

// vpn is the VPN family of afi with the maximum of paths that a Ranz node may hold in it (peerMaxPaths, peerfilter.go).
func vpn(afi api.Family_Afi) *api.AfiSafi {
	family := &api.Family{Afi: afi, Safi: api.Family_SAFI_MPLS_VPN}
	return &api.AfiSafi{
		Config:       &api.AfiSafiConfig{Family: family, Enabled: true},
		PrefixLimits: &api.PrefixLimit{Family: family, MaxPrefixes: peerMaxPaths},
	}
}

// setPeers applies a peers message: its Ranz nodes take the place of the ones before. A node that
// went or whose settings changed leaves, which ends its session, and a new or changed one comes; the
// routes of a node that leaves are withdrawn. A peers message with more holds part of the nodes:
// they wait for the next message without more, with which they all apply (SDN-77-R1 #531).
func (s *session) setPeers(ctx context.Context, m Message) error {
	if !s.address.IsValid() {
		return errors.New("peers: the sidecar runs no peering of the standard mode, which only a start with an address runs")
	}
	s.pending = append(s.pending, m.Peers...)
	if m.More {
		return nil
	}
	peers := s.pending
	s.pending = nil

	next := make(map[netip.Addr]peerConfig)
	var order []netip.Addr
	for _, p := range peers {
		pc, err := parsePeer(p, s.address)
		if err != nil {
			return fmt.Errorf("peers: %w", err)
		}
		if _, ok := next[pc.address]; ok {
			return fmt.Errorf("peers: peer %s comes twice", pc.address)
		}
		next[pc.address] = pc
		order = append(order, pc.address)
	}

	// The import policy of the new peers is in place before a session of them starts, and the peers that went leave it before
	// their session ends (peerfilter.go; SDN-77-R3 #570)
	if err := s.setImport(ctx, next); err != nil {
		return fmt.Errorf("peers: %w", err)
	}

	s.mu.Lock()
	prev := s.nodes
	s.nodes = next
	s.mu.Unlock()

	// The export policy of a route reflector, before a session of a new client starts (reflector.go; SDN-79 #359)
	s.setReflectorExport(ctx, next)

	for _, addr := range slices.SortedFunc(maps.Keys(prev), netip.Addr.Compare) {
		if pc, ok := next[addr]; ok && pc.equal(prev[addr]) {
			continue
		}
		// A node whose routes come through the reflectors has no session, so no peer in GoBGP (reflector.go)
		if !prev[addr].session() {
			continue
		}
		if err := s.bgp.DeletePeer(ctx, &api.DeletePeerRequest{Address: addr.String()}); err != nil {
			s.send(Message{Type: TypeError, Peer: addr.String(), Error: fmt.Sprintf("peer %s: %v", addr, err)})
			continue
		}
		s.log.Info("peer removed", "address", addr)
	}
	for _, addr := range order {
		if old, ok := prev[addr]; ok && old.equal(next[addr]) {
			continue
		}
		if !next[addr].session() {
			s.log.Info("peer known without a session: its routes come through the route reflectors", "address", addr, "vrfs", len(next[addr].vrfs))
			continue
		}
		if err := s.bgp.AddPeer(ctx, &api.AddPeerRequest{Peer: s.peerRequest(next[addr])}); err != nil {
			s.send(Message{Type: TypeError, Peer: addr.String(), Error: fmt.Sprintf("peer %s: %v", addr, err)})
			continue
		}
		s.log.Info("peer added", "address", addr, "asn", next[addr].asn, "vrfs", len(next[addr].vrfs))
	}
	// The maximum of paths of a route reflector that stays follows the nodes of its VRFs (reflector.go; SDN-79 #359)
	s.updateReflectorLimits(ctx, prev, next)
	// What the peers may announce changed, so what the node learns may have changed too
	s.kick()
	return nil
}

// vpnPath is the path of an announce message with a VRF: a VPN route of prefix in that VRF via next,
// the node's own address when it is empty, whose route distinguisher and route target hold the VRF id.
// Its LOCAL_PREF is the highest there is, so that no path that the node learned ranks above it in GoBGP: a
// prefix that the node announces stays announced to its peers, whatever another node announces for it
// (SDN-77-R3 #570).
func (s *session) vpnPath(vrf uint32, prefix netip.Prefix, next string) (*apiutil.Path, error) {
	if !s.address.IsValid() {
		return nil, fmt.Errorf("vrf %d: the sidecar runs no peering of the standard mode, which only a start with an address runs", vrf)
	}
	nextHop := s.address
	if next != "" {
		var err error
		if nextHop, err = netip.ParseAddr(next); err != nil {
			return nil, fmt.Errorf("next hop %q: %v", next, err)
		}
	}
	family := bgp.RF_IPv4_VPN
	if prefix.Addr().Is6() {
		family = bgp.RF_IPv6_VPN
	}
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(), bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, vrf))
	if err != nil {
		return nil, err
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
	if err != nil {
		return nil, err
	}
	target := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, rdAdmin, vrf, true)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		reach,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{target}),
		bgp.NewPathAttributeLocalPref(math.MaxUint32),
	}
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix()}, nil
}

// pathKey is the key of a best path: its prefix in VRF 0 for a unicast path, or in the VRF of its
// route distinguisher for a VPN path of the peering; false for any other path.
func pathKey(p *apiutil.Path) (routeKey, bool) {
	switch n := p.Nlri.(type) {
	case *bgp.IPAddrPrefix:
		if p.Family == bgp.RF_IPv4_UC || p.Family == bgp.RF_IPv6_UC {
			return routeKey{prefix: n.Prefix}, true
		}
	case *bgp.LabeledVPNIPAddrPrefix:
		rd, ok := n.RD.(*bgp.RouteDistinguisherTwoOctetAS)
		if ok && rd.Admin == rdAdmin && rd.Assigned != 0 && (p.Family == bgp.RF_IPv4_VPN || p.Family == bgp.RF_IPv6_VPN) {
			return routeKey{vrf: rd.Assigned, prefix: n.Prefix}, true
		}
	}
	return routeKey{}, false
}

// accepts reports whether the Ranz node at peer may announce the prefix of key in its VRF: a VRF
// that the two share, and exactly a prefix that the node may announce there, its address or one of
// its LAN subnets. A more specific prefix is none of them, so a node can make the sidecar report no
// more routes than its accept list holds (SDN-77-R1 #531).
func (s *session) accepts(peer netip.Addr, key routeKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.nodes[peer.Unmap()]
	if !ok {
		return false
	}
	prefix := key.prefix.Masked()
	for _, a := range p.vrfs[key.vrf] {
		if a == prefix {
			return true
		}
	}
	// A route reflector of the VRF passes on what the other nodes of the VRF may announce there (reflector.go)
	return s.reflects(p, key.vrf, prefix)
}

// refused tells the node about a session that GoBGP refused: no peer has its address.
func (s *session) refused(addr string) {
	if a, err := netip.ParseAddr(addr); err == nil {
		addr = a.Unmap().String()
	}
	s.log.Warn("session refused: no peer has its address", "peer", addr)
	s.send(Message{Type: TypeRefused, Peer: addr})
}

// refusalHandler is the handler of GoBGP's log: it passes each record to the handler of the log of
// the sidecar, and calls refused for each session that GoBGP refused, whatever the level of that log.
type refusalHandler struct {
	slog.Handler
	refused func(addr string)
}

func (h refusalHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level == slog.LevelInfo || h.Handler.Enabled(ctx, level)
}

func (h refusalHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == gobgpRefused {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key != "Key" {
				return true
			}
			h.refused(a.Value.String())
			return false
		})
	}
	if !h.Handler.Enabled(ctx, r.Level) {
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

func (h refusalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return refusalHandler{Handler: h.Handler.WithAttrs(attrs), refused: h.refused}
}

func (h refusalHandler) WithGroup(name string) slog.Handler {
	return refusalHandler{Handler: h.Handler.WithGroup(name), refused: h.refused}
}
