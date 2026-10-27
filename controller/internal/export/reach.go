package export

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// Where a target may point (AUD1-DT-9, #457, ADR-0031 amendment of 2026-10-27). The targets and the
// audit targets make the Controller connect to the host that an operator names, so a Guard refuses
// the addresses that reach what the Controller itself must keep from the network: a loopback address,
// a link-local address (which holds the metadata service of a cloud host), the unspecified address,
// and the store of the Controller, whose HTTP port asks for no credential (ST-1). An admin lists the
// hosts and the prefixes that a target may name although they are such addresses (the target hosts of
// intent.Destinations), and any other address needs no entry.
//
// The Guard decides twice. A target that is made is looked at when the API takes it (Check), so an
// operator is told at once. The connection that the exporter makes later is the place that counts
// (DialContext): it looks the name up again, checks each address that comes back and connects to an
// address that it checked, so a name that gives another address when it is used, or a target that
// was stored before the list changed, gets no connection. The check of a name in the list is the one
// exception: an admin who lists a name trusts what the name resolves to.

// ErrBlocked marks a connection that a Guard refuses.
var ErrBlocked = errors.New("the address of a target is not allowed")

// Resolver looks up the addresses of a host name. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

const (
	// DialTimeout bounds one attempt of a Guard to connect to one address.
	DialTimeout = 5 * time.Second
	// lookupTimeout bounds the look-up of a name when a target is made.
	lookupTimeout = 5 * time.Second
)

// Guard checks where the targets of the Controller may connect to. The zero value allows every address
// that is not loopback, link-local or unspecified.
type Guard struct {
	// Allowed returns the target hosts that an admin lists, as the controller keeps them (see
	// intent.Destinations). It is called at each check, so a change of the list is in force at the next
	// connection. An error makes the check fail, and so refuses the connection.
	Allowed func(ctx context.Context) ([]string, error)
	// Store returns the host and the port of the controller's own store, host:port, or an empty string
	// when it is not known. The host may be a name.
	Store func() string
	// Resolver looks names up; net.DefaultResolver when it is nil.
	Resolver Resolver
}

// reach is what a Guard reads for one check: the hosts and the prefixes that an admin lists, and the
// addresses of the store.
type reach struct {
	listed intent.HostList
	store  []netip.AddrPort
}

// read reads the list of the admin and the address of the store.
func (g *Guard) read(ctx context.Context) (reach, error) {
	var r reach
	if g.Allowed != nil {
		entries, err := g.Allowed(ctx)
		if err != nil {
			return reach{}, fmt.Errorf("reading the target hosts that an admin lists: %w", err)
		}
		for _, e := range entries {
			// An entry that does not parse allows nothing. An admin only sets entries that parse, so
			// only a store that someone changed by hand holds one.
			l, err := intent.ParseTargetHosts([]string{e})
			if err != nil {
				continue
			}
			r.listed.Names = append(r.listed.Names, l.Names...)
			r.listed.Prefixes = append(r.listed.Prefixes, l.Prefixes...)
		}
	}
	if g.Store != nil {
		r.store = g.storeAddrs(ctx, g.Store())
	}
	return r, nil
}

// storeAddrs returns the addresses that hostPort, the host and the port of the store, stands for.
func (g *Guard) storeAddrs(ctx context.Context, hostPort string) []netip.AddrPort {
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := g.lookup(lctx, host)
	if err != nil {
		return nil
	}
	out := make([]netip.AddrPort, len(addrs))
	for i, a := range addrs {
		out[i] = netip.AddrPortFrom(a, uint16(port))
	}
	return out
}

// lookup returns the addresses of host, which is an address that stands for itself or a name. An
// address comes back as an IPv4 address when it is an IPv4-mapped one, and with no zone.
func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.WithZone("").Unmap()}, nil
	}
	var r Resolver = net.DefaultResolver
	if g.Resolver != nil {
		r = g.Resolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.WithZone("").Unmap()
	}
	return out, nil
}

// special says why the address a is none that a target may name unless an admin lists it, and an
// empty string for an address that needs no entry. a is an IPv4 address when it is an IPv4-mapped one.
func special(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return "no address"
	case a.IsLoopback():
		return "a loopback address"
	case a.IsLinkLocalUnicast():
		return "a link-local address"
	case a.IsUnspecified() || (a.Is4() && a.As4()[0] == 0):
		return "the unspecified address, which reaches this host"
	}
	return ""
}

// permit returns nil when the connection to the address a at the port port is allowed, for the host
// host that the target named: any address that is no special one, and a special one that the list
// holds by the name of host or by a prefix. It returns an error that wraps ErrBlocked otherwise.
func (r reach) permit(host string, a netip.Addr, port uint16) error {
	a = a.Unmap().WithZone("")
	why := special(a)
	if why == "" && slices.Contains(r.store, netip.AddrPortFrom(a, port)) {
		why = "the store of this controller"
	}
	if why == "" || (a.IsValid() && r.listed.Contains(host, a)) {
		return nil
	}
	where := a.String()
	if h := strings.ToLower(strings.TrimSuffix(host, ".")); h != "" && h != where {
		where = h + " (" + where + ")"
	}
	return fmt.Errorf("%w: %s port %d is %s, and no admin lists a host or a prefix that holds it (ranz admin-destinations set -targets)", ErrBlocked, where, port, why)
}

// Check returns an error that wraps ErrInvalid when the URL of a target that is made names a host
// that resolves to an address that the Guard refuses. A host that does not resolve now is not refused:
// the connection checks each address that it gives then. An error of the list of the admin is returned
// as it is.
func (g *Guard) Check(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: the url does not parse: %w", ErrInvalid, err)
	}
	r, err := g.read(ctx)
	if err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := g.lookup(lctx, u.Hostname())
	if err != nil {
		return nil
	}
	port := portOf(u)
	for _, a := range addrs {
		if err := r.permit(u.Hostname(), a, port); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

// portOf returns the port of u: the one it names, or the port of its scheme (80 for http, 443 for
// https), and 0 for any other scheme that names none.
func portOf(u *url.URL) uint16 {
	if p, err := strconv.ParseUint(u.Port(), 10, 16); err == nil {
		return uint16(p)
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// DialContext connects to address, host:port, as net.Dialer does, to the first address of host that
// the Guard allows. It looks host up itself, checks each address and dials the ones it allows one
// after the other, each with its own check at the socket, so what it checked is what it connects to.
// It returns an error that wraps ErrBlocked when no address of host is allowed.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("the port %q of %s is not a number from 0 to 65535", portText, address)
	}
	r, err := g.read(ctx)
	if err != nil {
		return nil, err
	}
	addrs, err := g.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var allowed []netip.Addr
	var refused error
	for _, a := range addrs {
		if err := r.permit(host, a, uint16(port)); err != nil {
			refused = err
			continue
		}
		allowed = append(allowed, a)
	}
	if len(allowed) == 0 {
		if refused == nil {
			refused = fmt.Errorf("%w: %s has no address", ErrBlocked, host)
		}
		return nil, refused
	}
	d := &net.Dialer{Timeout: DialTimeout, ControlContext: r.control(host)}
	var last error
	for _, a := range allowed {
		conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// control returns the function that the dialer calls with the address that it is about to connect to,
// which is the check of the socket: it refuses what permit refuses, and anything that is no address.
func (r reach) control(host string) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: the address %q to connect to is no IP address and port", ErrBlocked, address)
		}
		return r.permit(host, ap.Addr(), ap.Port())
	}
}

// Verify checks an open connection to the host host, whose other end is remote, against the lists as
// they are now: an exporter that keeps a connection open calls it before it writes, so that an address
// that an admin took out of the list is not written to any more. It returns an error that wraps
// ErrBlocked when the connection is no longer allowed.
func (g *Guard) Verify(ctx context.Context, host string, remote net.Addr) error {
	if remote == nil {
		return fmt.Errorf("%w: the connection has no remote address", ErrBlocked)
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return fmt.Errorf("%w: the remote address %q of the connection is no IP address and port", ErrBlocked, remote)
	}
	r, err := g.read(ctx)
	if err != nil {
		return err
	}
	return r.permit(host, ap.Addr(), ap.Port())
}

// HTTPClient returns a client for the calls of a webhook or an OTLP endpoint that connects through
// the Guard. It follows no redirect, since the call must not go on to a host that the operator did not
// name, uses no proxy, which would be the host that the connection goes to and so the one that the
// Guard sees in place of the target, and keeps no connection open between calls, so that each call is
// checked against the list as it is then. timeout bounds one call.
func (g *Guard) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         g.DialContext,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}
