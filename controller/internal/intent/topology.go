package intent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The topology of a VRF and its gateways (SDN-19 #195, ADR-0025 decisions 11 and 12). A VRF is a
// full mesh unless its Topology says otherwise: every Node of the VRF is a peer of every other. A VRF
// of topology hub-and-spoke names its Hub, a Node of the VRF, and its other Nodes are its spokes: the
// hub is a peer of each spoke, two spokes are no peers in the VRF (Spokes), and a spoke reaches the
// prefixes of the VRF through the hub (GatewayRoutes), which sends the traffic of one spoke on to
// another. The traffic between two sites so passes the hub, where an inspection appliance or a Mirror
// of the VRF sees it (ADR-0029 decision 8), and two spokes never talk directly.
//
// Two gateway Nodes or more may advertise one LAN subnet in a VRF (Node.LANSubnets). Every other Node
// of the VRF gets the subnet as a route of each of them and picks a healthy one, from its own probes
// inside their Noise sessions and from the health data of the Controller; a VRF with ECMP spreads the
// flows to the subnet over the healthy ones by the hash of each flow.

// The topologies of a VRF.
const (
	TopologyFullMesh    = "full-mesh"
	TopologyHubAndSpoke = "hub-and-spoke"
)

// MaxLANSubnets is the most LAN subnets that one Node advertises in all its VRFs together: the
// NodeConfig message of the control protocol carries 16 (proto/ranz/control/v1/control.options).
const MaxLANSubnets = 16

// HubAndSpoke reports whether the VRF v is of topology hub-and-spoke.
func (v VRF) HubAndSpoke() bool {
	return v.Topology == TopologyHubAndSpoke
}

// Spokes reports whether the Nodes a and b are two spokes of the VRF vrf: the VRF is of topology
// hub-and-spoke and neither is its hub, so the two are no peers in it.
func (in Intent) Spokes(vrf, a, b string) bool {
	v := in.VRFs[vrf]
	return v.HubAndSpoke() && a != v.Hub && b != v.Hub
}

// GatewayRoutes returns the routes that lead the Node node to its peer peer besides the addresses of
// the peer, the outside prefixes of its own 1:1 NAT rules and the routes that leaks add, ordered by
// VRF, then prefix, each once. In each VRF of both of which the two are no two spokes they are the LAN
// subnets that peer advertises there; and in a VRF of topology hub-and-spoke whose hub peer is, of
// which node is a spoke, also the prefixes of the VRF that its other Nodes hold (hubPrefixes), which
// node reaches through the hub. A prefix that node advertises in the VRF itself is none of them: it
// leads to its host.
func (in Intent) GatewayRoutes(node, peer string) []Route {
	var out []Route
	if node == peer {
		return out
	}
	other := in.Nodes[peer]
	for _, vrf := range in.Nodes[node].VRFs {
		if !slices.Contains(other.VRFs, vrf) || in.Spokes(vrf, node, peer) {
			continue
		}
		var prefixes []netip.Prefix
		for _, s := range other.LANSubnets[vrf] {
			if p, err := parseLAN(s); err == nil {
				prefixes = append(prefixes, p)
			}
		}
		if v := in.VRFs[vrf]; v.HubAndSpoke() && v.Hub == peer {
			prefixes = append(prefixes, in.hubPrefixes(vrf, node, peer)...)
		}
		for _, p := range prefixes {
			if !in.advertises(node, vrf, p) {
				out = append(out, Route{VRF: vrf, Prefix: p, Via: peer})
			}
		}
	}
	slices.SortFunc(out, func(a, b Route) int {
		return cmp.Or(cmp.Compare(a.VRF, b.VRF), a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()))
	})
	return slices.Compact(out)
}

// hubPrefixes returns the prefixes of the VRF vrf of topology hub-and-spoke that its spoke spoke
// reaches through its hub hub, besides those of the hub itself: the pools of the L3 Networks of the
// VRF, the LAN subnets that its other Nodes advertise there and the outside prefixes of their 1:1 NAT
// rules of one family in it.
func (in Intent) hubPrefixes(vrf, spoke, hub string) []netip.Prefix {
	var out []netip.Prefix
	for _, network := range sortedNames(in.Networks) {
		if n := in.Networks[network]; n.VRF == vrf && n.Mode != ModeL2 {
			out = append(out, in.poolsOf(network)...)
		}
	}
	rules := in.NATRules()
	for _, name := range sortedNames(in.Nodes) {
		if name == spoke || name == hub || !slices.Contains(in.Nodes[name].VRFs, vrf) {
			continue
		}
		for _, s := range in.Nodes[name].LANSubnets[vrf] {
			if p, err := parseLAN(s); err == nil {
				out = append(out, p)
			}
		}
		for _, r := range rules[name] {
			if r.VRF == vrf && r.Inside.Addr().Is4() == r.Outside.Addr().Is4() {
				out = append(out, r.Outside)
			}
		}
	}
	return out
}

// advertises reports whether the Node node advertises the prefix p as a LAN subnet in the VRF vrf.
func (in Intent) advertises(node, vrf string, p netip.Prefix) bool {
	for _, s := range in.Nodes[node].LANSubnets[vrf] {
		if lan, err := parseLAN(s); err == nil && lan == p {
			return true
		}
	}
	return false
}

// hubUsers returns the VRFs whose hub the Node node is, as the refusal of its delete names them.
func (in Intent) hubUsers(node string) []string {
	var out []string
	for _, name := range sortedNames(in.VRFs) {
		if v := in.VRFs[name]; v.HubAndSpoke() && v.Hub == node {
			out = append(out, KindVRF+" "+strconv.Quote(name))
		}
	}
	return out
}

// completeTopologies writes the topology of each VRF in lower case. One that is not a topology stays
// as it is, for validateTopologies to refuse.
func (in Intent) completeTopologies() {
	for name, v := range in.VRFs {
		v.Topology = strings.ToLower(v.Topology)
		in.VRFs[name] = v
	}
}

// validateTopologies checks the topologies and the gateways of a completed intent: the topology of
// each VRF is full-mesh or hub-and-spoke; a VRF of topology hub-and-spoke names its hub, a Node that is
// a member of the VRF, and a VRF of another topology names none; and no Node advertises more than
// MaxLANSubnets LAN subnets.
func (in Intent) validateTopologies() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		switch v.Topology {
		case "", TopologyFullMesh:
			if v.Hub != "" {
				problems = append(problems, fmt.Errorf("VRF %q: the hub %q needs the topology %s, and the topology is %s", name, v.Hub, TopologyHubAndSpoke, TopologyFullMesh))
			}
		case TopologyHubAndSpoke:
			hub, ok := in.Nodes[v.Hub]
			switch {
			case v.Hub == "":
				problems = append(problems, fmt.Errorf("VRF %q: the topology %s needs a hub: name the Node that the spokes reach each other through", name, TopologyHubAndSpoke))
			case !ok:
				problems = append(problems, fmt.Errorf("VRF %q: the hub, Node %q, does not exist", name, v.Hub))
			case !slices.Contains(hub.VRFs, name):
				problems = append(problems, fmt.Errorf("VRF %q: the hub, Node %q, is not a member of the VRF", name, v.Hub))
			}
		default:
			problems = append(problems, fmt.Errorf("VRF %q: the topology must be %s or %s, not %q", name, TopologyFullMesh, TopologyHubAndSpoke, v.Topology))
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		count := 0
		for _, list := range in.Nodes[name].LANSubnets {
			count += len(list)
		}
		if count > MaxLANSubnets {
			problems = append(problems, fmt.Errorf("Node %q: it advertises %d LAN subnets, and the control protocol carries at most %d", name, count, MaxLANSubnets))
		}
	}
	return problems
}

// gatewayRouteCounts adds to count, by Node and peer, the routes that lead each Node to each of its
// peers as a gateway or a hub (GatewayRoutes).
func (in Intent) gatewayRouteCounts(count map[[2]string]int) {
	for _, name := range sortedNames(in.Nodes) {
		for _, peer := range sortedNames(in.Nodes) {
			if n := len(in.GatewayRoutes(name, peer)); n > 0 {
				count[[2]string{name, peer}] += n
			}
		}
	}
}
