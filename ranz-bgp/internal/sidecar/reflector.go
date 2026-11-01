package sidecar

// The route reflector of the peering of the standard mode (SDN-79 #359). In a VRF whose Intent names
// route reflectors, its other nodes are their clients: a client has a session with each reflector of
// the VRF and with no other client, and a reflector passes on the routes of each client to the other
// clients, so that a VRF of many nodes needs no full mesh. The node gives each VRF of a peer a role
// (PeerVRF.Role): client, the peer is a client of this node there; reflector, the peer is a reflector
// of the VRF; reflected, both are clients there, and the routes of the peer come through the
// reflectors. A peer whose every VRF is reflected has no session, and GoBGP refuses one from it.
//
// A reflector does not let GoBGP reflect what it learned, as RFC 4456 does: GoBGP would pass on the best
// path of a prefix of a route distinguisher, and no policy of GoBGP sees the route distinguisher, so a
// client could announce a prefix that it may announce in one VRF with the route distinguisher of another,
// where it would hide the path of the node that owns the prefix there. The copies goroutine reads the
// table instead (syncCopies) and takes a path of a client only when the client may announce it: its
// route distinguisher names a VRF of the client of this reflector, its prefix is exactly one of the accept
// list of the client there, and its next hop is the client itself. For each such path the reflector holds
// a copy of its own: the same route in the same VRF via the client, with the BGP identifier of the client
// as its ORIGINATOR_ID, so the client drops its own route when it comes back, and a large community that
// marks it as a copy. GoBGP sends the copies only to the clients of their VRF (the export policy of
// setReflectorExport), every copy of a prefix with ADD-PATH (RFC 7911), and adds the CLUSTER_LIST, as the
// clients are route reflector clients to it. A copy has the lowest LOCAL_PREF, so a path that the
// reflector learned or announces itself ranks above it and stays the one that the reflector itself uses.
//
// A client takes a path from a reflector of its VRF when any node of the VRF that the sidecar knows may
// announce its prefix there (reflects), and the node installs it as a route of the node of its next hop,
// whose accept list it checks again (NodePeering.c). A reflector never sends a copy into another VRF: a
// copy keeps the route distinguisher and the route target of the VRF of the client's path, and goes only to
// the clients of that VRF.

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// The roles of a VRF of a peer (PeerVRF.Role).
const (
	RoleClient    = "client"
	RoleReflector = "reflector"
	RoleReflected = "reflected"
)

const (
	// reflectorSendMax is the most paths of one prefix that a reflector sends a client with ADD-PATH: its
	// own path and the copies of the clients that announce the prefix.
	reflectorSendMax = 16
	// reflectorMark is the first local data of the large community that marks a copy, after the AS of the
	// overlay; the second is 1.
	reflectorMark = 79
	// reflectorExport names the export policy of a reflector, with its generation after it. Its statements
	// and sets carry the generation too, so a new policy is added while the old one holds.
	reflectorExport = "ranz-reflector-export"
	// reflectorRetry is how long the copies goroutine waits before it reads again a table that it could not
	// read, or adds again a copy that GoBGP did not take.
	reflectorRetry = time.Second
)

// reflector is the route reflector of a sidecar of the peering.
type reflector struct {
	asn       uint32
	clusterID netip.Addr // the router id of the node: the CLUSTER_ID of its copies (RFC 4456)
	kicks     chan struct{}

	// The export policy that GoBGP holds and its generation, the read loop's; exported says that it covers
	// the clients of the peers in force, so that the copies goroutine holds copies only then
	export     *exportState
	generation uint32
	exported   atomic.Bool

	// The copies that GoBGP holds, by VRF, prefix and client, and the path identifier of the next one: the
	// copies goroutine's
	copies map[copyKey]heldCopy
	nextID uint32
}

// exportState is what the export policy of a reflector holds in GoBGP.
type exportState struct {
	policy string
	sets   []*api.DefinedSet
}

// copyKey is a copy of a reflector: the route of a client in a VRF.
type copyKey struct {
	vrf    uint32
	prefix netip.Prefix
	client netip.Addr
}

// heldCopy is a copy that GoBGP holds: its UUID, and the BGP identifier of its client.
type heldCopy struct {
	id         uuid.UUID
	originator netip.Addr
}

// setRole takes the role of the VRF v of the peer of p.
func (p *peerConfig) setRole(v PeerVRF) error {
	switch v.Role {
	case "":
		return nil
	case RoleClient, RoleReflector, RoleReflected:
	default:
		return fmt.Errorf("peer %s: VRF %d: role %q is not %s, %s or %s", p.address, v.ID, v.Role, RoleClient, RoleReflector, RoleReflected)
	}
	if p.roles == nil {
		p.roles = make(map[uint32]string)
	}
	p.roles[v.ID] = v.Role
	return nil
}

// session reports whether the sidecar has a session with the peer of p: a router of the operator, or a
// Ranz node with a VRF that is not reflected.
func (p peerConfig) session() bool {
	if p.vrfs == nil {
		return true
	}
	for id := range p.vrfs {
		if p.roles[id] != RoleReflected {
			return true
		}
	}
	return false
}

// hasRole reports whether the peer of p has the role in one of its VRFs.
func (p peerConfig) hasRole(role string) bool {
	for _, r := range p.roles {
		if r == role {
			return true
		}
	}
	return false
}

// reflectorPeer gives the GoBGP peer of the Ranz node of p its part in the route reflector: a client of
// this node is a route reflector client to GoBGP, which then keeps the ORIGINATOR_ID of a copy and adds the
// CLUSTER_LIST, and gets every copy of a prefix with ADD-PATH; a reflector of a VRF of the node sends it
// every copy of a prefix.
func (s *session) reflectorPeer(peer *api.Peer, p peerConfig) *api.Peer {
	client := p.hasRole(RoleClient)
	reflects := p.hasRole(RoleReflector)
	if s.reflector == nil || (!client && !reflects) {
		return peer
	}
	if client {
		peer.RouteReflector = &api.RouteReflector{RouteReflectorClient: true, RouteReflectorClusterId: s.reflector.clusterID.String()}
	}
	config := &api.AddPathsConfig{Receive: reflects}
	if client {
		config.SendMax = reflectorSendMax
	}
	for _, a := range peer.AfiSafis {
		a.AddPaths = &api.AddPaths{Config: config}
	}
	return peer
}

// reflects reports whether the node p, a reflector of the VRF vrf, may pass on the prefix there: another
// node of the VRF that the sidecar knows may announce it there, exactly. The node checks the node of the
// next hop of the route once more when it installs it. The caller holds s.mu.
func (s *session) reflects(p peerConfig, vrf uint32, prefix netip.Prefix) bool {
	if p.roles[vrf] != RoleReflector {
		return false
	}
	for addr, q := range s.nodes {
		if addr == p.address {
			continue
		}
		if slices.Contains(q.vrfs[vrf], prefix) {
			return true
		}
	}
	return false
}

// clientMay reports whether the node at client is a client of this node in the VRF of key and may announce
// its prefix there, exactly.
func (s *session) clientMay(client netip.Addr, key routeKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.nodes[client]
	return ok && p.roles[key.vrf] == RoleClient && slices.Contains(p.vrfs[key.vrf], key.prefix.Masked())
}

// startReflector starts the route reflector of the peering: its copies goroutine, which reads the table
// whenever a path, a best path or a session changes, until ctx ends. It holds no copy until a peers message
// names a client.
func (s *session) startReflector(ctx context.Context, asn uint32, routerID netip.Addr) error {
	r := &reflector{asn: asn, clusterID: routerID, kicks: make(chan struct{}, 1), copies: make(map[copyKey]heldCopy)}
	s.reflector = r
	kick := func([]*apiutil.Path, time.Time) { r.kick() }
	err := s.bgp.WatchEvent(ctx, server.WatchEventMessageCallbacks{
		OnPathUpdate: kick,
		OnBestPath:   kick,
		OnPeerUpdate: func(*apiutil.WatchEventMessage_PeerEvent, time.Time) { r.kick() },
	}, server.WatchPostUpdate(false, "", ""), server.WatchBestPath(false), server.WatchPeer())
	if err != nil {
		return fmt.Errorf("route reflector: %w", err)
	}
	go s.watchCopies(ctx)
	return nil
}

// kick asks the copies goroutine to read the table again; kicks that come while it reads count as one.
func (r *reflector) kick() {
	select {
	case r.kicks <- struct{}{}:
	default:
	}
}

// watchCopies brings the copies in line with the table whenever it is kicked, until ctx ends. It is the only
// goroutine that changes the copies.
func (s *session) watchCopies(ctx context.Context) {
	r := s.reflector
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.kicks:
		}
		if err := s.syncCopies(); err != nil && ctx.Err() == nil {
			s.log.Warn("the copies of the route reflector are not in line with the table: another try soon", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(reflectorRetry):
			}
			r.kick()
		}
	}
}

// wantedCopies returns the copies that the table asks for: for each path of a client that the client may
// announce, a path of its own VRF, exactly a prefix of its accept list there, with itself as the next hop,
// the BGP identifier of the client by the route of the copy.
func (s *session) wantedCopies() (map[copyKey]netip.Addr, error) {
	want := make(map[copyKey]netip.Addr)
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN} {
		err := s.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(_ bgp.NLRI, paths []*apiutil.Path) {
			for _, p := range paths {
				if p.Withdrawal || !p.PeerAddress.IsValid() || !p.PeerID.Is4() {
					continue
				}
				key, ok := pathKey(p)
				client := p.PeerAddress.Unmap()
				// The next hop of an IPv6 route over an IPv4 session comes as an IPv4-mapped address
				if !ok || pathNextHop(p).Unmap() != client || !s.clientMay(client, key) {
					continue
				}
				want[copyKey{vrf: key.vrf, prefix: key.prefix.Masked(), client: client}] = p.PeerID
			}
		})
		if err != nil {
			return nil, err
		}
	}
	return want, nil
}

// syncCopies reads the table and brings the copies in line with it: a copy that the table no longer asks
// for goes, and a new one comes. While the export policy does not cover the clients of the peers in force,
// the reflector holds no copy at all, so that none goes to a node that is not a client of its VRF.
func (s *session) syncCopies() error {
	r := s.reflector
	want := make(map[copyKey]netip.Addr)
	if r.exported.Load() {
		var err error
		if want, err = s.wantedCopies(); err != nil {
			return err
		}
	}

	var failed error
	for _, key := range slices.SortedFunc(maps.Keys(r.copies), compareCopies) {
		held := r.copies[key]
		if originator, ok := want[key]; ok && originator == held.originator {
			continue
		}
		if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{held.id}}); err != nil {
			failed = fmt.Errorf("copy of %s of VRF %d via %s not withdrawn: %w", key.prefix, key.vrf, key.client, err)
			continue
		}
		delete(r.copies, key)
		s.log.Info("route reflector: copy withdrawn", "vrf", key.vrf, "prefix", key.prefix, "client", key.client)
	}
	for _, key := range slices.SortedFunc(maps.Keys(want), compareCopies) {
		if _, ok := r.copies[key]; ok {
			continue
		}
		r.nextID++
		if r.nextID == 0 {
			r.nextID = 1
		}
		path, err := r.copyPath(key, want[key], r.nextID)
		if err == nil {
			var resp []apiutil.AddPathResponse
			if resp, err = s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}}); err == nil && resp[0].Error != nil {
				err = resp[0].Error
			}
			if err == nil {
				r.copies[key] = heldCopy{id: resp[0].UUID, originator: want[key]}
				s.log.Info("route reflector: copy announced", "vrf", key.vrf, "prefix", key.prefix, "client", key.client)
				continue
			}
		}
		failed = fmt.Errorf("copy of %s of VRF %d via %s not announced: %w", key.prefix, key.vrf, key.client, err)
	}
	return failed
}

// compareCopies orders copies by VRF, prefix and client, so that the log names them in that order.
func compareCopies(a, b copyKey) int {
	return cmp.Or(cmp.Compare(a.vrf, b.vrf), a.prefix.Addr().Compare(b.prefix.Addr()), cmp.Compare(a.prefix.Bits(), b.prefix.Bits()), a.client.Compare(b.client))
}

// copyPath is the copy of key with the path identifier id: the VPN route of its prefix in its VRF via its
// client, whose route distinguisher and route target hold the VRF id as those of the client do, with the BGP
// identifier of the client as its ORIGINATOR_ID, the lowest LOCAL_PREF and the large community of a copy.
func (r *reflector) copyPath(key copyKey, originator netip.Addr, id uint32) (*apiutil.Path, error) {
	family := bgp.RF_IPv4_VPN
	if key.prefix.Addr().Is6() {
		family = bgp.RF_IPv6_VPN
	}
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(key.prefix, *bgp.NewMPLSLabelStack(), bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, key.vrf))
	if err != nil {
		return nil, err
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, key.client)
	if err != nil {
		return nil, err
	}
	from, err := bgp.NewPathAttributeOriginatorId(originator)
	if err != nil {
		return nil, err
	}
	target := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, rdAdmin, key.vrf, true)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		reach,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{target}),
		bgp.NewPathAttributeLocalPref(0),
		from,
		bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{bgp.NewLargeCommunity(r.asn, reflectorMark, 1)}),
	}
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix(), RemoteID: id}, nil
}

// setReflectorExport gives a reflector the export policy of the peers peers: a copy goes to the clients of
// its VRF and to no other peer, and every other path of the node goes to every peer as before. A node that
// has no client and never had one keeps the export policy of setPolicies. A failure is told to the node,
// and the reflector then holds no copy until a later peers message sets the policy.
func (s *session) setReflectorExport(ctx context.Context, peers map[netip.Addr]peerConfig) {
	r := s.reflector
	if r == nil {
		return
	}
	defer r.kick()

	clients := make(map[uint32][]netip.Addr)
	for _, addr := range slices.SortedFunc(maps.Keys(peers), netip.Addr.Compare) {
		for vrf, role := range peers[addr].roles {
			if role == RoleClient {
				clients[vrf] = append(clients[vrf], addr)
			}
		}
	}
	if len(clients) == 0 && r.export == nil {
		r.exported.Store(true)
		return
	}

	r.generation++
	gen := r.generation
	accepted := api.RouteAction_ROUTE_ACTION_ACCEPT
	rejected := api.RouteAction_ROUTE_ACTION_REJECT
	marker := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY,
		Name:        fmt.Sprintf("%s-mark-%d", reflectorExport, gen),
		List:        []string{fmt.Sprintf("%d:%d:1", r.asn, reflectorMark)},
	}
	sets := []*api.DefinedSet{marker}
	var statements []*api.Statement
	for _, vrf := range slices.Sorted(maps.Keys(clients)) {
		neighbors := &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR, Name: fmt.Sprintf("%s-clients-%d-%d", reflectorExport, gen, vrf)}
		for _, addr := range clients[vrf] {
			neighbors.List = append(neighbors.List, netip.PrefixFrom(addr, addr.BitLen()).String())
		}
		target := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY,
			Name:        fmt.Sprintf("%s-rt-%d-%d", reflectorExport, gen, vrf),
			List:        []string{fmt.Sprintf("rt:%d:%d", rdAdmin, vrf)},
		}
		sets = append(sets, neighbors, target)
		statements = append(statements, &api.Statement{
			Name: fmt.Sprintf("%s-copies-%d-%d", reflectorExport, gen, vrf),
			Conditions: &api.Conditions{
				RouteType:         api.Conditions_ROUTE_TYPE_LOCAL,
				NeighborSet:       &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: neighbors.Name},
				ExtCommunitySet:   &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: target.Name},
				LargeCommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: marker.Name},
			},
			Actions: &api.Actions{RouteAction: accepted},
		})
	}
	statements = append(statements, &api.Statement{
		Name:       fmt.Sprintf("%s-others-%d", reflectorExport, gen),
		Conditions: &api.Conditions{LargeCommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: marker.Name}},
		Actions:    &api.Actions{RouteAction: rejected},
	}, &api.Statement{
		Name:       fmt.Sprintf("%s-local-%d", reflectorExport, gen),
		Conditions: &api.Conditions{RouteType: api.Conditions_ROUTE_TYPE_LOCAL},
		Actions:    &api.Actions{RouteAction: accepted},
	})

	// What this call added, so that a failure takes it away again
	var state exportState
	fail := func(err error) {
		r.exported.Store(false)
		s.dropExport(ctx, state)
		s.log.Warn("the export policy of the route reflector is not set: it holds no copy", "err", err)
		s.send(Message{Type: TypeError, Error: fmt.Sprintf("peers: the export policy of the route reflector: %v", err)})
	}
	for _, set := range sets {
		if err := s.bgp.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: set}); err != nil {
			fail(err)
			return
		}
		state.sets = append(state.sets, set)
	}
	policy := fmt.Sprintf("%s-%d", reflectorExport, gen)
	if err := s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{Name: policy, Statements: statements}}); err != nil {
		fail(err)
		return
	}
	state.policy = policy
	err := s.bgp.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          globalRIB,
		Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
		Policies:      []*api.Policy{{Name: policy}},
		DefaultAction: rejected,
	}})
	if err != nil {
		fail(err)
		return
	}

	old := r.export
	r.export = &state
	r.exported.Store(true)
	if old != nil {
		s.dropExport(ctx, *old)
	}
	s.log.Info("route reflector: export policy set", "policy", policy, "vrfs", len(clients))
}

// dropExport removes the policy of an export state from GoBGP, and then its sets. A failure is logged: the
// objects stay in GoBGP and refer to nothing that matters.
func (s *session) dropExport(ctx context.Context, st exportState) {
	if st.policy != "" {
		if err := s.bgp.DeletePolicy(ctx, &api.DeletePolicyRequest{Policy: &api.Policy{Name: st.policy}, All: true}); err != nil {
			s.log.Warn("an export policy of the route reflector that is no longer in force is not removed", "policy", st.policy, "err", err)
		}
	}
	for _, set := range st.sets {
		if err := s.bgp.DeleteDefinedSet(ctx, &api.DeleteDefinedSetRequest{DefinedSet: set, All: true}); err != nil {
			s.log.Warn("a set of an export policy of the route reflector is not removed", "set", set.Name, "err", err)
		}
	}
}
