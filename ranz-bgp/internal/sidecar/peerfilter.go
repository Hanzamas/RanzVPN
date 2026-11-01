package sidecar

// The filters of the peering of the standard mode against a member that announces what it may not (SDN-77-R3, #570). The
// best-path selection of GoBGP ranks every path of a destination, so a path that its peer may not announce, with a higher
// LOCAL_PREF or a lower router id, hides the path of another peer, and the sidecar then reported the route of that peer as
// withdrawn. Three things keep such a path out:
//
//   - The import policy of GoBGP (setImport) takes a path of a peer only when its exact prefix is one that the accept lists of that
//     peer hold in some VRF. A path that no VRF of its peer may carry never reaches the table, whatever its route distinguisher.
//   - A prefix that a peer may announce in one VRF can come with the route distinguisher of another, where a second peer announces
//     it too, and GoBGP may rank the first above the second: a policy cannot see the route distinguisher. So the sidecar does not
//     take the best path of GoBGP. It reads the paths of the table, which GoBGP keeps in the order of its selection, and for each
//     prefix of each VRF takes the first whose peer may announce that very prefix in that very VRF (syncRoutes). It reads again
//     whenever a path, a session or an announcement of the node changes, which kick asks for.
//   - A peer holds at most peerMaxPaths paths of an address family in the Adj-RIB-In that GoBGP keeps for it, the paths that the
//     policy refused included. One that announces more has its session closed by GoBGP with a Cease (maximum number of prefixes
//     reached), which the sidecar logs; the session stays down until the node sends the peers again with a change of that peer.
//     That bounds the memory that a peer can take.
//
// The paths that a node announces itself have the highest LOCAL_PREF (vpnPath), so no path that it learned ranks above them:
// the best path of GoBGP for a prefix that a node announces is its own, and its peers keep getting it.

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// peeringImport names the import policy of the peering, with its generation after it. Its statements and the sets that they
// refer to carry the generation too, so that a new policy is added while the old one holds and takes its place in one step.
const peeringImport = "ranz-peering-import"

// peerMaxPaths is the most paths of one address family that a Ranz node may hold in the Adj-RIB-In of the sidecar. A node
// announces at most CONTROL_MAX_ADDRESSES addresses and CONTROL_MAX_ANNOUNCE LAN subnets (16 each, src/Core/Control.h), so an
// honest peer holds 32 at most; the maximum doubles that, for the paths of a Generation that goes out and one that comes in.
const peerMaxPaths = 64

// readRetry is how long the routes goroutine waits before it reads again a table that it could not read.
const readRetry = time.Second

// importState is what the import policy of the peering holds in GoBGP: its name, and the defined sets that its statements refer to.
type importState struct {
	policy string
	sets   []*api.DefinedSet
}

// peerPrefixes is the prefixes that a Ranz node may announce in any VRF that it shares with the sidecar, each once, as the
// entries of a prefix set that holds exactly those lengths: the IPv4 ones and the IPv6 ones, which a prefix set holds apart.
func peerPrefixes(p peerConfig) (v4, v6 []*api.Prefix) {
	seen := make(map[netip.Prefix]bool)
	for _, id := range slices.Sorted(maps.Keys(p.vrfs)) {
		for _, prefix := range p.vrfs[id] {
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			bits := uint32(prefix.Bits())
			e := &api.Prefix{IpPrefix: prefix.String(), MaskLengthMin: bits, MaskLengthMax: bits}
			if prefix.Addr().Is4() {
				v4 = append(v4, e)
			} else {
				v6 = append(v6, e)
			}
		}
	}
	return v4, v6
}

// setImport replaces the import policy of the peering with one for peers: it takes the paths of the node itself, and a path of
// a peer when it comes from that peer and its prefix is exactly one that the accept lists of that peer hold, in any VRF; it
// refuses every other. The new policy is built beside the old one and takes its place in one step, so no path meets a policy
// with a peer missing. It fails, and the old policy stays, when GoBGP refuses an object.
func (s *session) setImport(ctx context.Context, peers map[netip.Addr]peerConfig) error {
	s.generation++
	gen := s.generation
	accepted := api.RouteAction_ROUTE_ACTION_ACCEPT
	policy := fmt.Sprintf("%s-%d", peeringImport, gen)
	statements := []*api.Statement{{
		Name:       fmt.Sprintf("%s-local-%d", peeringImport, gen),
		Conditions: &api.Conditions{RouteType: api.Conditions_ROUTE_TYPE_LOCAL},
		Actions:    &api.Actions{RouteAction: accepted},
	}}
	var sets []*api.DefinedSet
	for i, addr := range slices.SortedFunc(maps.Keys(peers), netip.Addr.Compare) {
		v4, v6 := peerPrefixes(peers[addr])
		if len(v4) == 0 && len(v6) == 0 {
			continue
		}
		neighbor := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        fmt.Sprintf("%s-peer-%d-%d", peeringImport, gen, i),
			List:        []string{netip.PrefixFrom(addr, addr.BitLen()).String()},
		}
		sets = append(sets, neighbor)
		for family, prefixes := range [][]*api.Prefix{v4, v6} {
			if len(prefixes) == 0 {
				continue
			}
			set := &api.DefinedSet{
				DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        fmt.Sprintf("%s-accept-%d-%d-%d", peeringImport, gen, i, family),
				Prefixes:    prefixes,
			}
			sets = append(sets, set)
			statements = append(statements, &api.Statement{
				Name: fmt.Sprintf("%s-%d-%d-%d", peeringImport, gen, i, family),
				Conditions: &api.Conditions{
					NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: neighbor.Name},
					PrefixSet:   &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: set.Name},
				},
				Actions: &api.Actions{RouteAction: accepted},
			})
		}
	}

	// What this call added, so that a failure takes it away again
	var state importState
	fail := func(err error) error {
		s.dropImport(ctx, state)
		return fmt.Errorf("import policy: %w", err)
	}
	for _, set := range sets {
		if err := s.bgp.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: set}); err != nil {
			return fail(err)
		}
		state.sets = append(state.sets, set)
	}
	if err := s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{Name: policy, Statements: statements}}); err != nil {
		return fail(err)
	}
	state.policy = policy
	err := s.bgp.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          globalRIB,
		Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		Policies:      []*api.Policy{{Name: policy}},
		DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
	}})
	if err != nil {
		return fail(err)
	}

	old := s.imported
	s.imported = &state
	if old != nil {
		s.dropImport(ctx, *old)
	}
	return nil
}

// dropImport removes the policy of an import state from GoBGP, and then its sets, which no statement refers to any more. A
// failure is logged: the objects stay in GoBGP and refer to nothing that matters.
func (s *session) dropImport(ctx context.Context, st importState) {
	if st.policy != "" {
		if err := s.bgp.DeletePolicy(ctx, &api.DeletePolicyRequest{Policy: &api.Policy{Name: st.policy}, All: true}); err != nil {
			s.log.Warn("an import policy that no peer needs any more is not removed", "policy", st.policy, "err", err)
		}
	}
	for _, set := range st.sets {
		if err := s.bgp.DeleteDefinedSet(ctx, &api.DeleteDefinedSetRequest{DefinedSet: set, All: true}); err != nil {
			s.log.Warn("a set of an import policy that no peer needs any more is not removed", "set", set.Name, "err", err)
		}
	}
}

// kick asks the routes goroutine to read the table again. Kicks that come while it reads count as one. It does nothing for a
// sidecar that does not run the peering.
func (s *session) kick() {
	if s.resync == nil {
		return
	}
	select {
	case s.resync <- struct{}{}:
	default:
	}
}

// onUpdate is called for each path that the import policy took, or that went: the table changed.
func (s *session) onUpdate(_ []*apiutil.Path, _ time.Time) {
	s.kick()
}

// noteCapped logs a peer whose session GoBGP closed because it announced more paths than the maximum, once. It comes before the node
// hears that the session ended, so the log says why when the node looks.
func (s *session) noteCapped(p apiutil.Peer) {
	if s.resync == nil {
		return
	}
	addr := p.Conf.NeighborAddress.Unmap()
	if p.State.AdminState != api.PeerState_ADMIN_STATE_PFX_CT {
		delete(s.capped, addr)
	} else if !s.capped[addr] {
		s.capped[addr] = true
		s.log.Warn("peer announced more paths than the maximum: its session ends and stays down until the peers of the node change it",
			"peer", addr, "maximum", peerMaxPaths)
	}
}

// watchRoutes reads the table whenever it is kicked, until ctx ends, and tells the node what changed. It is the only goroutine
// that changes learned in the peering.
func (s *session) watchRoutes(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.resync:
		}
		if err := s.syncRoutes(); err != nil && ctx.Err() == nil {
			s.log.Warn("the routes of the peers are not read from the table: another try soon", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(readRetry):
			}
			s.kick()
		}
	}
}

// refusal is what vpnRoutes found of the paths that it did not take: how many, and the first.
type refusal struct {
	paths int
	key   routeKey
	peer  netip.Addr
}

// vpnRoutes is the routes that the table holds for the node: for each prefix of a VRF, the first path in the order of GoBGP
// whose peer may announce that prefix in that VRF (accepts), unless the node announces the prefix itself, which it never learns.
func (s *session) vpnRoutes() (map[routeKey]learnedRoute, refusal, error) {
	routes := make(map[routeKey]learnedRoute)
	own := make(map[routeKey]bool)
	var refused refusal
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN} {
		err := s.bgp.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family}, func(_ bgp.NLRI, paths []*apiutil.Path) {
			for _, p := range paths {
				key, ok := pathKey(p)
				if !ok {
					continue
				}
				if !p.PeerAddress.IsValid() {
					own[key] = true
					continue
				}
				if !s.accepts(p.PeerAddress, key) {
					if refused.paths == 0 {
						refused.key, refused.peer = key, p.PeerAddress.Unmap()
					}
					refused.paths++
					continue
				}
				if _, taken := routes[key]; taken {
					continue
				}
				// The next hop of an IPv6 route over an IPv4 session comes as an IPv4-mapped address
				nh := pathNextHop(p).Unmap()
				if !nh.IsValid() {
					s.log.Warn("learned path without a next hop", "vrf", key.vrf, "prefix", key.prefix, "peer", p.PeerAddress)
					continue
				}
				routes[key] = learnedRoute{nextHop: nh.String(), peer: p.PeerAddress.Unmap().String()}
			}
		})
		if err != nil {
			return nil, refusal{}, err
		}
	}
	for key := range own {
		delete(routes, key)
	}
	return routes, refused, nil
}

// compareKeys orders the routes that a read of the table changed, by VRF and then prefix, so that the node hears them in that order.
func compareKeys(a, b routeKey) int {
	if c := cmp.Compare(a.vrf, b.vrf); c != 0 {
		return c
	}
	if c := a.prefix.Addr().Compare(b.prefix.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.prefix.Bits(), b.prefix.Bits())
}

// syncRoutes reads the table and tells the node about each route that is new, changed or gone since the last read: learned for
// the first two, withdrawn for the last. One log line counts the paths that were not taken, when their number changes, so that a
// peer that announces many of them does not fill the log.
func (s *session) syncRoutes() error {
	next, refused, err := s.vpnRoutes()
	if err != nil {
		return err
	}
	if refused.paths != s.notTaken {
		s.notTaken = refused.paths
		if refused.paths > 0 {
			s.log.Warn("learned paths not taken: their peer may not announce them in their VRF", "paths", refused.paths,
				"vrf", refused.key.vrf, "prefix", refused.key.prefix, "peer", refused.peer)
		}
	}

	keys := slices.Collect(maps.Keys(s.learned))
	for key := range next {
		if _, ok := s.learned[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, compareKeys)
	for _, key := range keys {
		old, had := s.learned[key]
		r, has := next[key]
		switch {
		case had && !has:
			delete(s.learned, key)
			s.send(Message{Type: TypeWithdrawn, VRF: key.vrf, Prefix: key.prefix.String(), Peer: old.peer})
		case has && (!had || old != r):
			s.learned[key] = r
			s.send(Message{Type: TypeLearned, VRF: key.vrf, Prefix: key.prefix.String(), NextHop: r.nextHop, Peer: r.peer})
		}
	}
	return nil
}
