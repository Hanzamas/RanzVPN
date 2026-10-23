package intent

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// The Mirrors (SDN-23, ADR-0029 decision 9): a Mirror copies the traffic of the Nodes that its
// source selects to a sensor, such as Zeek or Suricata, in VXLAN (RFC 7348), through the VXLAN
// module of the node that the EVPN gateway uses as well (ADR-0032). The source selects the Nodes
// that have a tag, one Node by its name, the members of a VRF, or the Nodes that match several of
// these; the filter takes the packets of one IP protocol, of one port, or of both. A selected Node
// copies the packets that it sends into the overlay and the packets that it delivers to its host,
// in the VRF of the Mirror or, without one, in each of its VRFs, and a rate limit holds the copies
// of each Node, so a Mirror never takes the link.

// KindMirror is the kind of a Mirror.
const KindMirror = "Mirror"

const (
	// VXLANPort is the UDP port of a sensor that its Mirror names without one (RFC 7348 section 5).
	VXLANPort = 4789
	// MaxVNI is the largest VNI: a VNI has 24 bits.
	MaxVNI = 1<<24 - 1
	// DefaultMirrorRate is the rate limit of a Mirror that declares none, in bits per second.
	DefaultMirrorRate = 10_000_000
	// MaxMirrors is the most Mirrors that may select one Node: the most that a node takes
	// (proto/ranz/control/v1/control.options).
	MaxMirrors = 16
)

// The IP protocols of a Mirror by name; any other is given as its number.
var mirrorProtocols = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17}

// Mirror copies the packets that match it to a sensor in VXLAN. Its source is Tag, Node and VRF:
// it selects a Node that matches each of the three that it declares, and it declares at least one.
type Mirror struct {
	// Tag selects the Nodes that have the tag.
	Tag string `json:"tag,omitempty"`
	// Node selects the Node of that name; a name that no Node of the intent has selects none.
	Node string `json:"node,omitempty"`
	// VRF selects the members of the VRF and takes the packets in it. Left out, a selected Node
	// copies the packets of each of its VRFs.
	VRF string `json:"vrf,omitempty"`
	// Protocol is the IP protocol of the packets: tcp, udp, icmp (with ICMPv6 for IPv6) or a number
	// from 1 to 255. Left out, the packets of every protocol.
	Protocol string `json:"protocol,omitempty"`
	// Port is the source or the destination port of the packets, of TCP or UDP. Left out, every
	// port.
	Port uint16 `json:"port,omitempty"`
	// Sensor is where the copies go: an IP address, or an IP address and a UDP port (host:port).
	// Left out, the port is VXLANPort.
	Sensor string `json:"sensor"`
	// VNI is the VNI of the copies. Left out, the VNI of a copy is the id of the VRF of its packet,
	// so the sensor tells apart the VRFs that use the same range, and the ids of those VRFs must fit
	// in a VNI.
	VNI uint32 `json:"vni,omitempty"`
	// RateLimit is the rate in bits per second of the VXLAN datagrams that each selected Node sends
	// the sensor for the Mirror at most; DefaultMirrorRate when it is left out.
	RateLimit uint64 `json:"rateLimit,omitempty"`
}

// ParseSensor parses the sensor of a Mirror: an IP address without a zone, or an IP address and a
// UDP port other than 0 (host:port), with VXLANPort for the port when it is left out. An
// IPv4-mapped IPv6 address is taken as the IPv4 address; an unspecified or a multicast address is
// no sensor.
func ParseSensor(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.AddrPort{}, fmt.Errorf("sensor %q is neither an IP address nor an IP address and a port", s)
		}
		ap = netip.AddrPortFrom(a, VXLANPort)
	}
	a := ap.Addr()
	if ap.Port() == 0 || a.Zone() != "" || a.Unmap().IsUnspecified() || a.Unmap().IsMulticast() {
		return netip.AddrPort{}, fmt.Errorf("sensor %q needs a unicast IP address without a zone, and a port other than 0", s)
	}
	return netip.AddrPortFrom(a.Unmap(), ap.Port()), nil
}

// ParseProtocol parses the protocol of a Mirror: tcp, udp, icmp, or the number of an IP protocol
// from 1 to 255. It returns the number, and 0 for the empty string, which takes every protocol.
func ParseProtocol(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}
	if p, ok := mirrorProtocols[s]; ok {
		return p, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil || n == 0 || s != strconv.FormatUint(n, 10) {
		return 0, fmt.Errorf("protocol %q is neither tcp, udp nor icmp, nor a number from 1 to 255", s)
	}
	return uint8(n), nil
}

// selects reports whether m selects the Node n of the name name.
func (m Mirror) selects(name string, n Node) bool {
	return (m.Tag == "" || slices.Contains(n.Tags, m.Tag)) && (m.Node == "" || m.Node == name) && (m.VRF == "" || slices.Contains(n.VRFs, m.VRF))
}

// MirrorsOf returns the names of the Mirrors of in that select the Node name, in name order.
func (in Intent) MirrorsOf(name string) []string {
	var out []string
	n, ok := in.Nodes[name]
	if !ok {
		return nil
	}
	for _, m := range sortedNames(in.Mirrors) {
		if in.Mirrors[m].selects(name, n) {
			out = append(out, m)
		}
	}
	return out
}

// completeMirrors fills in what a Mirror leaves out: the port of its sensor, which it writes in the
// one form host:port, and its rate limit.
func (in Intent) completeMirrors() {
	for name, m := range in.Mirrors {
		if ap, err := ParseSensor(m.Sensor); err == nil {
			m.Sensor = ap.String()
		}
		if m.RateLimit == 0 {
			m.RateLimit = DefaultMirrorRate
		}
		in.Mirrors[name] = m
	}
}

// validateMirrors checks the Mirrors of a completed intent, and that no Node is selected by more
// than MaxMirrors of them.
func (in Intent) validateMirrors() []error {
	var problems []error
	for _, name := range sortedNames(in.Mirrors) {
		m := in.Mirrors[name]
		if m.Tag == "" && m.Node == "" && m.VRF == "" {
			problems = append(problems, fmt.Errorf("Mirror %q: the source needs a tag, a node or a vrf", name))
		}
		if m.Tag != "" && !nameRule.MatchString(m.Tag) {
			problems = append(problems, fmt.Errorf("Mirror %q: tag %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", name, m.Tag))
		}
		if m.Node != "" && !nameRule.MatchString(m.Node) {
			problems = append(problems, fmt.Errorf("Mirror %q: node %q is not the name of a Node", name, m.Node))
		}
		// The VRFs whose packets the Mirror copies
		vrfs := sortedNames(in.VRFs)
		if m.VRF != "" {
			if _, ok := in.VRFs[m.VRF]; !ok {
				problems = append(problems, fmt.Errorf("Mirror %q: VRF %q does not exist", name, m.VRF))
			}
			vrfs = []string{m.VRF}
		}
		if p, err := ParseProtocol(m.Protocol); err != nil {
			problems = append(problems, fmt.Errorf("Mirror %q: %w", name, err))
		} else if m.Port != 0 && p != 0 && p != mirrorProtocols["tcp"] && p != mirrorProtocols["udp"] {
			problems = append(problems, fmt.Errorf("Mirror %q: port %d needs the protocol tcp or udp, or none, not %q", name, m.Port, m.Protocol))
		}
		if _, err := ParseSensor(m.Sensor); err != nil {
			problems = append(problems, fmt.Errorf("Mirror %q: %w", name, err))
		}
		if m.VNI > MaxVNI {
			problems = append(problems, fmt.Errorf("Mirror %q: vni %d has more than 24 bits", name, m.VNI))
		}
		for _, v := range vrfs {
			if id := in.VRFs[v].ID; m.VNI == 0 && id > MaxVNI {
				problems = append(problems, fmt.Errorf("Mirror %q: the id %d of VRF %q has more than the 24 bits of a VNI, so the Mirror needs a vni", name, id, v))
			}
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		if ms := in.MirrorsOf(name); len(ms) > MaxMirrors {
			problems = append(problems, fmt.Errorf("Node %q: %d Mirrors select it, more than the %d that a node takes", name, len(ms), MaxMirrors))
		}
	}
	return problems
}

// mirrorUsers returns the Mirrors of in that name the VRF vrf, as the error of a delete names them.
func (in Intent) mirrorUsers(vrf string) []string {
	var users []string
	for _, name := range sortedNames(in.Mirrors) {
		if in.Mirrors[name].VRF == vrf {
			users = append(users, KindMirror+" "+strconv.Quote(name))
		}
	}
	return users
}
