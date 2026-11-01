package controller

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The report of the BGP peering of the standard mode (SDN-77 #357). A Node whose VRFs peer by BGP
// reports the peers of its sidecar ranz bgp, the state of each session and the prefixes that it
// learned from each, with the sessions that the sidecar refused, in a Telemetry message of its own
// whenever they change (Telemetry.peering). The controller keeps the last report of each Node in
// memory (takePeering) and shows it with the Node that the address of each peer belongs to and the
// name of the VRF of each prefix (Peering, `ranz explain NODE`). It writes nothing of it into a
// desired state: the routes go between the Nodes.

// The most that the controller takes of one report: the sizes of control.options.
const (
	maxPeeringPeers   = 64
	maxPeeringLearned = 32
	maxPeeringState   = 15
)

// PeeringRoute is a prefix that a Node learned from a peer, in a VRF.
type PeeringRoute struct {
	// VRF is the name of the VRF of the prefix, its id when no VRF of the intent has it.
	VRF    string `json:"vrf"`
	Prefix string `json:"prefix"`
}

// PeeringPeer is one peer of the sidecar of a Node, as the Node reported it.
type PeeringPeer struct {
	// Node is the Node whose tunnel endpoint has the address of the peer, "" for none.
	Node    string `json:"node,omitempty"`
	Address string `json:"address"`
	// State is the state of the BGP session: idle, connect, active, opensent, openconfirm or
	// established.
	State   string         `json:"state"`
	Learned []PeeringRoute `json:"learned"`
}

// PeeringStatus is the BGP peering of a Node: the Nodes that the intent names as its peers, and the
// peers of its sidecar as the Node reported them last.
type PeeringStatus struct {
	Node string `json:"node"`
	// ASN is the AS of the Nodes in the BGP peering, 0 while no VRF of the Node peers by BGP.
	ASN uint32 `json:"asn,omitempty"`
	// Expected are the Nodes that share a VRF that peers by BGP with the Node, in name order, but for
	// the other clients of the route reflectors of such a VRF, with which it has no session (SDN-79).
	Expected []string `json:"expected"`
	// Reported is when the Node reported its peering last, zero while it reported none since the
	// controller started.
	Reported time.Time `json:"reported,omitzero"`
	// Peers are the peers of its sidecar, in the order of their address.
	Peers []PeeringPeer `json:"peers"`
	// Refused is the number of the sessions that its sidecar refused since the Node started: from an
	// address that the controller named for no peer.
	Refused uint64 `json:"refused"`
}

// reportedRoute is a prefix of a VRF that a Node learned.
type reportedRoute struct {
	vrf    uint32
	prefix netip.Prefix
}

// reportedPeer is one peer of a report.
type reportedPeer struct {
	address netip.Addr
	state   string
	learned []reportedRoute
}

// peeringReport is the report of one Node, as the controller took it.
type peeringReport struct {
	reported time.Time
	peers    []reportedPeer
	refused  uint64
}

// peeringState holds the last report of each Node, by name. Its zero value is ready.
type peeringState struct {
	mu      sync.Mutex
	reports map[string]peeringReport
}

// takePeering keeps the report r of the BGP peering of the Node name in place of the one before. A
// peer without an address and a prefix that is not one are left out, and so are the peers and the
// prefixes past the sizes of the schema; a state is cut to its size. The controller does not hold
// c.mu.
func (c *Controller) takePeering(name string, r *controlpb.PeeringReport) {
	if r == nil {
		return
	}
	rep := peeringReport{reported: time.Now().UTC(), refused: r.GetRefused()}
	for _, p := range r.GetPeers() {
		if len(rep.peers) == maxPeeringPeers {
			break
		}
		addr, ok := netip.AddrFromSlice(p.GetAddress())
		if !ok {
			continue
		}
		peer := reportedPeer{address: addr.Unmap(), state: clip(p.GetState(), maxPeeringState)}
		for _, l := range p.GetLearned() {
			if len(peer.learned) == maxPeeringLearned {
				break
			}
			a, ok := netip.AddrFromSlice(l.GetPrefix().GetAddress())
			if !ok || l.GetPrefix().GetLength() > uint32(a.BitLen()) {
				continue
			}
			prefix, err := a.Prefix(int(l.GetPrefix().GetLength()))
			if err != nil {
				continue
			}
			peer.learned = append(peer.learned, reportedRoute{vrf: l.GetVrfId(), prefix: prefix})
		}
		rep.peers = append(rep.peers, peer)
	}
	c.peering.mu.Lock()
	defer c.peering.mu.Unlock()
	if c.peering.reports == nil {
		c.peering.reports = map[string]peeringReport{}
	}
	c.peering.reports[name] = rep
}

// Peering returns the BGP peering of the Node name: the Nodes that the intent names as its peers,
// and the report of its sidecar with the Node of each peer and the VRF of each prefix. There is no
// Node of that name when the error wraps intent.ErrNotFound.
func (c *Controller) Peering(name string) (PeeringStatus, error) {
	c.mu.Lock()
	in := c.intent
	c.mu.Unlock()
	n, ok := in.Nodes[name]
	if !ok {
		return PeeringStatus{}, fmt.Errorf("%w: Node %q", intent.ErrNotFound, name)
	}
	st := PeeringStatus{Node: name, Expected: []string{}, Peers: []PeeringPeer{}}
	mine := in.PeeringVRFs(n)
	if len(mine) > 0 {
		st.ASN = intent.PeeringASN
	}
	// The Node of the tunnel endpoint of each address, which its sidecar has; the intent gives no two
	// Nodes one address (link.go)
	vteps := map[netip.Addr]string{}
	for _, other := range slices.Sorted(maps.Keys(in.Nodes)) {
		o := in.Nodes[other]
		if a, err := intent.ParseVTEPAddress(o.VTEP.Address); err == nil {
			vteps[a.Unmap()] = other
		}
		// A client of route reflectors has a session with them and with no other client of theirs (SDN-79)
		if in.PeeringSession(name, other) {
			st.Expected = append(st.Expected, other)
		}
	}
	vrfs := map[uint32]string{}
	for vrf, v := range in.VRFs {
		vrfs[v.ID] = vrf
	}

	c.peering.mu.Lock()
	rep, reported := c.peering.reports[name]
	c.peering.mu.Unlock()
	if !reported {
		return st, nil
	}
	st.Reported, st.Refused = rep.reported, rep.refused
	for _, p := range rep.peers {
		peer := PeeringPeer{Node: vteps[p.address], Address: p.address.String(), State: p.state, Learned: []PeeringRoute{}}
		for _, l := range p.learned {
			vrf, ok := vrfs[l.vrf]
			if !ok {
				vrf = strconv.FormatUint(uint64(l.vrf), 10)
			}
			peer.Learned = append(peer.Learned, PeeringRoute{VRF: vrf, Prefix: l.prefix.String()})
		}
		st.Peers = append(st.Peers, peer)
	}
	return st, nil
}
