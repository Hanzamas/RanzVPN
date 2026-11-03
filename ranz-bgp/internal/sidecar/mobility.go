package sidecar

// MAC mobility (RFC 7432 section 15; SDN-78 #358): a MAC address that moves from one VTEP to another is announced by its new VTEP
// with a MAC Mobility extended community whose sequence number is one higher than the highest of the routes of that MAC that the
// new VTEP knows. GoBGP gives a type-2 route of the node that number when the node adds it (the MAC mobility of its server), and
// withdraws the node's own route of a MAC when a peer announces that MAC with a higher one (the MAC mobility of its table).
//
// The node hears of it: the route of the peer comes in a stretch message with moved when its sequence number is higher than that
// of every route of the same MAC on the same VNI that the node announces, as the best paths had them before that route came
// (movedAway). The node then takes the MAC off the port of its switch where it had it, and puts it at the port of the fabric, so
// that the frames to it go to the new VTEP and no longer to the old port; its withdraw of the routes of the MAC that follows is
// no error, though GoBGP withdrew them already (deleteStretch).

import (
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// macKey is a MAC address on a VNI, as net.HardwareAddr prints it.
type macKey struct {
	vni uint32
	mac string
}

// mobilitySeq is the sequence number of the MAC Mobility extended community of a path, -1 for a path without one, as GoBGP counts
// them.
func mobilitySeq(p *apiutil.Path) int64 {
	for _, a := range p.Attrs {
		ecs, ok := a.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ecs.Value {
			if m, ok := c.(*bgp.MacMobilityExtended); ok {
				return int64(m.Sequence)
			}
		}
	}
	return -1
}

// ownSeq is the highest sequence number of the routes of the MAC k that the node announces, and whether it announces one.
func (st *stretchState) ownSeq(k macKey) (int64, bool) {
	routes := st.own[k]
	if len(routes) == 0 {
		return 0, false
	}
	return slices.Max(slices.Collect(maps.Values(routes))), true
}

// movedAway is the MAC addresses of the node that paths move to a peer: the MAC of each type-2 route of a peer whose sequence number
// is higher than that of every route of the same MAC and VNI that the node announces. The routes of the node are as the best paths
// had them before paths: those of paths take their place afterwards. The watch goroutine only.
func (st *stretchState) movedAway(paths []*apiutil.Path) map[macKey]bool {
	moved := make(map[macKey]bool)
	type ownPath struct {
		key  macKey
		name string
		seq  int64
		gone bool
	}
	var own []ownPath
	for _, p := range paths {
		n, ok := p.Nlri.(*bgp.EVPNNLRI)
		if !ok || p.Family != bgp.RF_EVPN {
			continue
		}
		if _, ok := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); !ok {
			continue
		}
		key, _, why, ok := st.routeOf(p, n)
		if !ok || why != "" {
			continue
		}
		k := macKey{vni: key.vni, mac: key.mac}
		seq := mobilitySeq(p)
		if !p.PeerAddress.IsValid() {
			own = append(own, ownPath{key: k, name: n.String(), seq: seq, gone: p.Withdrawal})
			continue
		}
		if mine, ok := st.ownSeq(k); ok && !p.Withdrawal && seq > mine {
			moved[k] = true
		}
	}
	if st.own == nil {
		st.own = make(map[macKey]map[string]int64)
	}
	for _, o := range own {
		routes := st.own[o.key]
		switch {
		case o.gone && routes != nil:
			delete(routes, o.name)
			if len(routes) == 0 {
				delete(st.own, o.key)
			}
		case !o.gone:
			if routes == nil {
				routes = make(map[string]int64)
				st.own[o.key] = routes
			}
			routes[o.name] = o.seq
		}
	}
	return moved
}

// markMoved marks the routes that the node is told about whose MAC moved away (movedAway): each learned route of such a MAC in
// routes, and for a MAC none of whose routes changed, the route of it that the node has, so that the node hears of each move.
func (st *stretchState) markMoved(routes []StretchRoute, moved map[macKey]bool) []StretchRoute {
	if len(moved) == 0 {
		return routes
	}
	told := make(map[macKey]bool)
	for i := range routes {
		k := macKey{vni: routes[i].VNI, mac: routes[i].MAC}
		if routes[i].MAC != "" && !routes[i].Withdraw && moved[k] {
			routes[i].Moved = true
			told[k] = true
		}
	}
	for _, key := range slices.SortedFunc(maps.Keys(st.reported), compareStretchKeys) {
		k := macKey{vni: key.vni, mac: key.mac}
		if key.mac == "" || !moved[k] || told[k] {
			continue
		}
		r := StretchRoute{VNI: key.vni, MAC: key.mac, NextHop: st.reported[key].String(), Moved: true}
		if key.ip.IsValid() {
			r.IP = key.ip.String()
		}
		routes = append(routes, r)
		told[k] = true
	}
	return routes
}

// compareStretchKeys orders the routes of a VNI: by VNI, MAC address and IP address.
func compareStretchKeys(a, b stretchKey) int {
	switch {
	case a.vni != b.vni:
		if a.vni < b.vni {
			return -1
		}
		return 1
	case a.mac != b.mac:
		return strings.Compare(a.mac, b.mac)
	}
	return a.ip.Compare(b.ip)
}

// deleteStretch withdraws the route of the gateway whose path is id, for a withdraw of the node or at the end of a full resync. A
// path that GoBGP withdrew already, because a peer announced its MAC with a higher sequence number (RFC 7432 section 15), is gone,
// which is no error.
func (s *session) deleteStretch(id uuid.UUID) error {
	err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}})
	if err != nil && strings.Contains(err.Error(), "can't find") {
		s.log.Info("EVPN stretch route gone already: a peer announced its MAC with a higher sequence number of MAC mobility")
		return nil
	}
	return err
}
