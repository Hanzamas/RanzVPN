package intent

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The Stretches of the L2 Networks (SDN-63 #290, ADR-0032 amendment of 2026-10-22). A Stretch binds one gateway Node to one L2
// Network and extends the Network into a data-centre fabric over EVPN and VXLAN: the gateway announces the MAC addresses of the
// Network to the fabric as EVPN type-2 routes with the L2 VNI of the Stretch, and learns those of the fabric. The administrator
// of the fabric fixes the L2 VNI, the route targets and the ESI, and the Controller only validates them. A Stretch moves no
// frame yet: the Controller gives it to its gateway (internal/desired, stretch.go), which has the Capability evpn, and the data
// plane follows (SDN-64).
//
// The Intent refuses a Stretch whose gateway is no member of the VRF of its Network, whose Network is no L2 Network, that
// repeats the L2 VNI of another Stretch of its gateway, that has no ESI while another gateway stretches the same Network, and
// one on a Network where a Node other than a Stretch gateway has the Role bridge: a bridge that joins the segment to a LAN, and a
// gateway that joins it to the fabric, would join it twice and loop it. The Controller refuses a Stretch whose gateway does not
// report the Capability evpn besides (internal/capability), and delivers none to a Node while the licence in force lacks EVPN
// and BGP, an Enterprise feature (ADR-0032 decision 7, ADR-0036; internal/controller, stretch.go).
//
// A Gateway is a Node here, as it is in the topology of a VRF (topology.go): the Intent has no kind of its own for one.

// KindStretch is the kind of a Stretch.
const KindStretch = "Stretch"

const (
	// DefaultMACImportLimit is the most remote MAC addresses that a Stretch imports from the fabric when it declares no limit:
	// the v1 target of 10,000 sessions (ADR-0032 amendment of 2026-10-22).
	DefaultMACImportLimit = 10_000
	// MaxMACImportLimit is the most that a Stretch may import: the entries that the MAC table of a switch holds at most
	// (SWITCH_MAX_MACS of src/Core/Switch.h).
	MaxMACImportLimit = 1 << 20
	// DefaultStaleTimer is how long the remote MAC addresses of a Stretch stay in use after its BGP session or ranz-bgp went down,
	// in seconds, before the gateway flushes them (ADR-0032 amendment of 2026-10-22).
	DefaultStaleTimer = 120
	// MaxStaleTimer is the most that a Stretch may keep them, in seconds: an hour.
	MaxStaleTimer = 3600
	// DefaultBUMRateLimit is the rate in bits per second of broadcast, unknown-unicast and multicast frames that a gateway sends
	// the fabric for a Stretch at most, when it declares none: the limit is always on (ADR-0032 amendment of 2026-10-22).
	DefaultBUMRateLimit = 10_000_000
	// MaxStretchRouteTargets is the most route targets of a Stretch: the Stretch message of the control protocol carries that
	// many (proto/ranz/control/v1/control.options).
	MaxStretchRouteTargets = 8
	// ESISize is the size of an Ethernet segment identifier in bytes (RFC 7432 section 5).
	ESISize = 10
)

// The Roles of a Node (ADR-0011): what the Node does.
const (
	RoleServer = "server"
	RoleClient = "client"
	RoleBridge = "bridge"
	RoleRelay  = "relay"
)

// nodeRoles are the Roles that the Roles of a Node may name.
var nodeRoles = []string{RoleServer, RoleClient, RoleBridge, RoleRelay}

// Stretch binds the gateway Node Gateway to the L2 Network Network and extends the Network into a data-centre fabric.
type Stretch struct {
	// Gateway is the Node that carries the Network into the fabric: a member of the VRF of the Network, which reports the
	// Capability evpn.
	Gateway string `json:"gateway"`
	// Network is the L2 Network that the Stretch extends.
	Network string `json:"network"`
	// VNI is the L2 VNI of the Network in the fabric, from 1 to MaxVNI. A gateway carries one Network on a VNI.
	VNI uint32 `json:"vni"`
	// RouteTargets are the route targets that the Network imports from the fabric and exports to it, from 1 to
	// MaxStretchRouteTargets, each in the form of ParseRouteTarget.
	RouteTargets []string `json:"routeTargets"`
	// ESI is the Ethernet segment identifier that the gateways of the Network share for active-active multihoming (EVPN type-1
	// and type-4), in the form of ParseESI. A Network that has the Stretches of more than one gateway needs it in each of
	// them. Left out, the Network has one gateway.
	ESI string `json:"esi,omitempty"`
	// BUMRateLimit is the rate in bits per second of broadcast, unknown-unicast and multicast frames that the gateway sends the
	// fabric at most. Left out, it is DefaultBUMRateLimit.
	BUMRateLimit uint64 `json:"bumRateLimit,omitempty"`
	// MACImportLimit is the most remote MAC addresses that the gateway imports from the fabric, up to MaxMACImportLimit; it
	// drops the others and the Controller gets an event. Left out, it is DefaultMACImportLimit.
	MACImportLimit uint32 `json:"macImportLimit,omitempty"`
	// StaleTimer is how long the remote MAC addresses stay in use, in seconds up to MaxStaleTimer, after the BGP session or
	// ranz-bgp went down. Left out, it is DefaultStaleTimer.
	StaleTimer uint32 `json:"staleTimer,omitempty"`
	// IRB turns on symmetric integrated routing and bridging on the Network, which the L3 VNI of the VRF carries. Left out, it
	// is off: on an ordinary data-centre VLAN the fabric owns the default gateway, and two owners of one address break ARP.
	IRB bool `json:"irb,omitempty"`
}

// ParseESI parses the Ethernet segment identifier of a Stretch: ESISize octets, each of two hexadecimal digits in either case,
// separated by colons, as in 00:11:22:33:44:55:66:77:88:99. It returns the octets. The all-zero identifier is that of a
// single-homed site (RFC 7432 section 5), which a Stretch states by declaring none, so it is refused.
func ParseESI(s string) ([]byte, error) {
	parts := strings.Split(s, ":")
	if len(parts) != ESISize {
		return nil, fmt.Errorf("esi %q is not %d octets of two hexadecimal digits separated by colons", s, ESISize)
	}
	out := make([]byte, 0, ESISize)
	for _, p := range parts {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 1 {
			return nil, fmt.Errorf("esi %q is not %d octets of two hexadecimal digits separated by colons", s, ESISize)
		}
		out = append(out, b[0])
	}
	if !slices.ContainsFunc(out, func(b byte) bool { return b != 0 }) {
		return nil, fmt.Errorf("esi %q is all zeros, the identifier of a single-homed site: leave the esi out instead", s)
	}
	return out, nil
}

// formatESI writes the octets of an ESI in the one form that ParseESI reads: lower case digits, separated by colons.
func formatESI(esi []byte) string {
	parts := make([]string, len(esi))
	for i, b := range esi {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// cloneStretches returns a copy of the Stretches of in that shares nothing with them.
func (in Intent) cloneStretches() map[string]Stretch {
	out := make(map[string]Stretch, len(in.Stretches))
	for name, s := range in.Stretches {
		s.RouteTargets = slices.Clone(s.RouteTargets)
		out[name] = s
	}
	return out
}

// WithoutStretches returns in without its Stretches, which is how the Controller compiles the Intent while the licence in force
// lacks EVPN and BGP, so that no Node gets one. in itself is not changed.
func (in Intent) WithoutStretches() Intent {
	if len(in.Stretches) == 0 {
		return in
	}
	out := in
	out.Stretches = map[string]Stretch{}
	return out
}

// completeStretches fills in what the Stretches leave out: their limits, and the route targets and the ESI in their one form. A
// route target or an ESI that does not parse stays as it is, for validate to refuse. It also puts the Roles of each Node in order.
func (in Intent) completeStretches() {
	for name, n := range in.Nodes {
		slices.Sort(n.Roles)
		in.Nodes[name] = n
	}
	for name, s := range in.Stretches {
		s.RouteTargets = canonicalRouteTargets(s.RouteTargets)
		if esi, err := ParseESI(s.ESI); err == nil {
			s.ESI = formatESI(esi)
		}
		if s.BUMRateLimit == 0 {
			s.BUMRateLimit = DefaultBUMRateLimit
		}
		if s.MACImportLimit == 0 {
			s.MACImportLimit = DefaultMACImportLimit
		}
		if s.StaleTimer == 0 {
			s.StaleTimer = DefaultStaleTimer
		}
		in.Stretches[name] = s
	}
}

// stretchUsers returns the Stretches of in that bind the Network network, or that have the Node node as their gateway, each as
// Stretch "name"; "" for network or node leaves that one out. A Network or a Node that has any cannot be deleted.
func (in Intent) stretchUsers(network, node string) []string {
	var out []string
	for _, name := range sortedNames(in.Stretches) {
		s := in.Stretches[name]
		if (network != "" && s.Network == network) || (node != "" && s.Gateway == node) {
			out = append(out, KindStretch+" "+strconv.Quote(name))
		}
	}
	return out
}

// validateStretches checks the Stretches of a completed intent, and the Roles of its Nodes.
func (in Intent) validateStretches() []error {
	var problems []error
	for _, name := range sortedNames(in.Nodes) {
		roles := in.Nodes[name].Roles
		for i, r := range roles {
			switch {
			case !slices.Contains(nodeRoles, r):
				problems = append(problems, fmt.Errorf("Node %q: the role must be %s, %s, %s or %s, not %q", name, RoleServer, RoleClient, RoleBridge, RoleRelay, r))
			case i > 0 && roles[i-1] == r:
				problems = append(problems, fmt.Errorf("Node %q: role %q is listed twice", name, r))
			}
		}
	}
	for _, name := range sortedNames(in.Stretches) {
		problems = append(problems, in.validateStretch(name, in.Stretches[name])...)
	}
	return append(problems, in.validateStretchSet()...)
}

// validateStretch checks the Stretch s named name by itself: where it binds, and each of its values.
func (in Intent) validateStretch(name string, s Stretch) []error {
	var problems []error
	node, nodeOK := in.Nodes[s.Gateway]
	if !nodeOK {
		problems = append(problems, fmt.Errorf("Stretch %q: Node %q does not exist", name, s.Gateway))
	}
	network, networkOK := in.Networks[s.Network]
	switch {
	case !networkOK:
		problems = append(problems, fmt.Errorf("Stretch %q: Network %q does not exist", name, s.Network))
	case network.Mode != ModeL2:
		problems = append(problems, fmt.Errorf("Stretch %q: Network %q is of mode %s, and only an L2 Network is stretched", name, s.Network, network.Mode))
	case nodeOK && !slices.Contains(node.VRFs, network.VRF):
		problems = append(problems, fmt.Errorf("Stretch %q: Node %q is no member of VRF %q, the VRF of Network %q", name, s.Gateway, network.VRF, s.Network))
	}
	if s.VNI < 1 || s.VNI > MaxVNI {
		problems = append(problems, fmt.Errorf("Stretch %q: vni %d is not between 1 and %d", name, s.VNI, MaxVNI))
	}
	if len(s.RouteTargets) == 0 {
		problems = append(problems, fmt.Errorf("Stretch %q: routeTargets needs at least one route target", name))
	}
	if len(s.RouteTargets) > MaxStretchRouteTargets {
		problems = append(problems, fmt.Errorf("Stretch %q: routeTargets holds %d route targets, at most %d", name, len(s.RouteTargets), MaxStretchRouteTargets))
	}
	for i, rt := range s.RouteTargets {
		if _, err := ParseRouteTarget(rt); err != nil {
			problems = append(problems, fmt.Errorf("Stretch %q: routeTargets: %w", name, err))
		} else if i > 0 && s.RouteTargets[i-1] == rt {
			problems = append(problems, fmt.Errorf("Stretch %q: routeTargets lists the route target %s twice", name, rt))
		}
	}
	if s.ESI != "" {
		if _, err := ParseESI(s.ESI); err != nil {
			problems = append(problems, fmt.Errorf("Stretch %q: %w", name, err))
		}
	}
	if s.MACImportLimit > MaxMACImportLimit {
		problems = append(problems, fmt.Errorf("Stretch %q: macImportLimit %d is above %d", name, s.MACImportLimit, MaxMACImportLimit))
	}
	if s.StaleTimer > MaxStaleTimer {
		problems = append(problems, fmt.Errorf("Stretch %q: staleTimer %d is above %d seconds", name, s.StaleTimer, MaxStaleTimer))
	}
	return problems
}

// validateStretchSet checks the Stretches of a completed intent against each other, and against the Nodes of their Networks. Each
// problem names the Node and the Network:
//   - a Network is stretched at a gateway once;
//   - a gateway carries a VNI for one Network;
//   - a Network that more than one gateway stretches has the ESI in each Stretch, so that the gateways share its Ethernet segment;
//   - a Network that has a Stretch has no Node with the Role bridge but its Stretch gateways.
func (in Intent) validateStretchSet() []error {
	var problems []error
	pairs := map[[2]string]string{}        // the Stretch of a gateway and a Network
	vnis := map[string]map[uint32]string{} // the Stretch of a gateway that carries a VNI
	byNetwork := map[string][]string{}     // the Stretches of a Network, in name order
	for _, name := range sortedNames(in.Stretches) {
		s := in.Stretches[name]
		pair := [2]string{s.Gateway, s.Network}
		if other, ok := pairs[pair]; ok {
			problems = append(problems, fmt.Errorf("Stretch %q: Network %q is already stretched at Node %q by Stretch %q", name, s.Network, s.Gateway, other))
			continue
		}
		pairs[pair] = name
		byNetwork[s.Network] = append(byNetwork[s.Network], name)
		if s.VNI == 0 {
			continue
		}
		if vnis[s.Gateway] == nil {
			vnis[s.Gateway] = map[uint32]string{}
		}
		if other, ok := vnis[s.Gateway][s.VNI]; ok {
			problems = append(problems, fmt.Errorf("Stretch %q: Node %q carries vni %d for Network %q already (Stretch %q), so it cannot carry it for Network %q too",
				name, s.Gateway, s.VNI, in.Stretches[other].Network, other, s.Network))
		} else {
			vnis[s.Gateway][s.VNI] = name
		}
	}
	for _, network := range sortedNames(byNetwork) {
		stretches := byNetwork[network]
		gateways := make([]string, len(stretches))
		for i, name := range stretches {
			gateways[i] = in.Stretches[name].Gateway
		}
		slices.Sort(gateways)
		if len(stretches) > 1 {
			for _, name := range stretches {
				if s := in.Stretches[name]; s.ESI == "" {
					problems = append(problems, fmt.Errorf("Stretch %q: Network %q is stretched at the Nodes %s and Node %q has no esi, which the gateways of one Network need to share its Ethernet segment",
						name, network, quoted(gateways), s.Gateway))
				}
			}
		}
		nw, ok := in.Networks[network]
		if !ok || nw.Mode != ModeL2 {
			continue
		}
		for _, node := range sortedNames(in.Nodes) {
			if n := in.Nodes[node]; slices.Contains(n.Roles, RoleBridge) && slices.Contains(n.VRFs, nw.VRF) && !slices.Contains(gateways, node) {
				problems = append(problems, fmt.Errorf("Stretch %q: Network %q has Node %q, which has the role bridge and is no gateway of the Stretch (gateways: %s): a bridge to a LAN and a Stretch to the fabric would join the segment twice and loop it",
					stretches[0], network, node, quoted(gateways)))
			}
		}
	}
	return problems
}

// quoted returns the names, each quoted, in one list: "a", "b".
func quoted(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strconv.Quote(n)
	}
	return strings.Join(out, ", ")
}
