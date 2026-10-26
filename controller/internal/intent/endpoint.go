package intent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The endpoints of a Node (SDN-93 #410) are the addresses under which the other Nodes reach it, each over one
// transport. A Listener (listener.go) says what a Node listens on, its ports and its certificate; an endpoint says
// where the others find that Listener: a DNS name or an IP address, which may be the one of a NAT or of a load
// balancer in front of the Node, and the port there. The Controller puts the endpoints of a Node into the Peer
// object of every Node that shares a VRF with it (desired/endpoint.go), and a Node dials a peer at the endpoints
// of its Peer object, with the race of its fallback list: the first transport that connects wins. A peer that has
// none is not dialled, and a Node that has none is dialled by no peer, so it dials them.

// The transports of an endpoint: the names that the fallback list of a Node gives its transports
// (src/Core/Transport.h).
const (
	TransportQUIC  = "quic"
	TransportTLS   = "tls"
	TransportMimic = "mimic"
)

// MaxEndpoints is the most endpoints that a Node names: the entries of a fallback list (TRANSPORT_MAX_TARGETS),
// which the control protocol carries (proto/ranz/control/v1/control.options).
const MaxEndpoints = 8

// Endpoint is one address under which the other Nodes reach a Node.
type Endpoint struct {
	// Transport is quic, tls or mimic.
	Transport string `json:"transport"`
	// Address is host:port: a DNS name or an IP address, an IPv6 address in brackets, and a port from 1 to 65535.
	// It is at most MaxAddress characters long, which fits the address field of the C node.
	Address string `json:"address"`
}

// ParseEndpointAddress parses the address of an endpoint, host:port, into its host and its port. The host of a DNS
// name is in lower case, and that of an IP address is in the form of netip.Addr.String, without the brackets of an
// IPv6 address and with an IPv4-mapped IPv6 address as the IPv4 address: the form that net.JoinHostPort writes back.
// The address is refused when it is longer than MaxAddress characters, has no port, a port that is not a number
// from 1 to 65535 or no host, when its host is the unspecified address, a multicast address, an IP address with a
// zone, or neither an IP address nor a DNS name.
func ParseEndpointAddress(s string) (string, uint16, error) {
	if len(s) > MaxAddress {
		return "", 0, fmt.Errorf("address %q is longer than %d characters", s, MaxAddress)
	}
	if !strings.Contains(s, ":") {
		return "", 0, fmt.Errorf("address %q has no port: write host:port", s)
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		reason := err.Error()
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) {
			reason = addrErr.Err
		}
		if !strings.HasPrefix(s, "[") && strings.Count(s, ":") > 1 {
			reason += ": an IPv6 address goes in brackets, as [2001:db8::1]:443"
		}
		return "", 0, fmt.Errorf("address %q is not host:port: %s", s, reason)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("address %q has the port %q, not a number from 1 to 65535", s, p)
	}
	if h == "" {
		return "", 0, fmt.Errorf("address %q has no host", s)
	}

	a, err := netip.ParseAddr(h)
	if err == nil {
		if a.Zone() != "" {
			return "", 0, fmt.Errorf("address %q: the IP address %s has a zone, which only its own host can use", s, h)
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsMulticast() {
			return "", 0, fmt.Errorf("address %q: %s is not the address of one Node", s, h)
		}
		return a.String(), uint16(n), nil
	}
	if strings.HasPrefix(s, "[") {
		return "", 0, fmt.Errorf("address %q: %q in brackets is not an IP address", s, h)
	}

	h = strings.ToLower(h)
	if err := checkACMEName(h); err != nil {
		return "", 0, fmt.Errorf("address %q: the host is not a DNS name: %w", s, err)
	}
	if last := h[strings.LastIndexByte(h, '.')+1:]; strings.Trim(last, "0123456789") == "" {
		return "", 0, fmt.Errorf("address %q: the host %q is neither an IP address nor a DNS name: the last label of a name is not a number", s, h)
	}
	return h, uint16(n), nil
}

// canonicalEndpoints returns the endpoints es in their one form: the transport in lower case and an address that
// parses as host:port, which ParseEndpointAddress writes back. The order stays: it is the order of the race. A
// transport or an address that does not parse stays as it is, for validateEndpoints to refuse.
func canonicalEndpoints(es []Endpoint) []Endpoint {
	if len(es) == 0 {
		return nil
	}
	out := make([]Endpoint, len(es))
	for i, e := range es {
		e.Transport = strings.ToLower(e.Transport)
		if host, port, err := ParseEndpointAddress(e.Address); err == nil {
			e.Address = net.JoinHostPort(host, strconv.Itoa(int(port)))
		}
		out[i] = e
	}
	return out
}

// validateEndpoints checks the endpoints of the Nodes of a completed intent: each Node has MaxEndpoints at most, each
// is over a transport that the Nodes know and at an address that ParseEndpointAddress takes, and none is listed
// twice. A problem names the Node, the endpoint by its place in the list, and what is wrong with it.
func (in Intent) validateEndpoints() []error {
	var problems []error
	for _, name := range sortedNames(in.Nodes) {
		es := in.Nodes[name].Endpoints
		if len(es) > MaxEndpoints {
			problems = append(problems, fmt.Errorf("Node %q: it has %d endpoints, more than %d", name, len(es), MaxEndpoints))
		}
		for i, e := range es {
			if e.Transport != TransportQUIC && e.Transport != TransportTLS && e.Transport != TransportMimic {
				problems = append(problems, fmt.Errorf("Node %q: endpoints[%d]: the transport must be %s, %s or %s, not %q", name, i, TransportQUIC, TransportTLS, TransportMimic, e.Transport))
			}
			if _, _, err := ParseEndpointAddress(e.Address); err != nil {
				problems = append(problems, fmt.Errorf("Node %q: endpoints[%d]: %w", name, i, err))
			}
			if slices.Contains(es[:i], e) {
				problems = append(problems, fmt.Errorf("Node %q: endpoints[%d]: %s %s is listed twice", name, i, e.Transport, e.Address))
			}
		}
	}
	return problems
}
