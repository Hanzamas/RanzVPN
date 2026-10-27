package export

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// stubNames is a Resolver that holds the addresses of some names, and no answer for any other.
type stubNames map[string][]string

func (s stubNames) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	list, ok := s[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, len(list))
	for i, a := range list {
		out[i] = netip.MustParseAddr(a)
	}
	return out, nil
}

// listed returns an Allowed function that gives entries.
func listed(entries ...string) func(context.Context) ([]string, error) {
	return func(context.Context) ([]string, error) { return entries, nil }
}

// permit decides for each address: the special ones are refused with their reason, any other passes,
// and the list of an admin and the store of the controller change that.
func TestPermit(t *testing.T) {
	store := netip.MustParseAddrPort("10.0.0.5:4001")
	lists := func(entries ...string) intent.HostList {
		l, err := intent.ParseTargetHosts(entries)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	for _, c := range []struct {
		name   string
		r      reach
		host   string
		addr   string
		port   uint16
		reason string // the reason that the refusal gives, none when the connection is allowed
	}{
		{"loopback of the store", reach{}, "127.0.0.1", "127.0.0.1", 4001, "a loopback address"},
		{"loopback in the whole range", reach{}, "127.255.0.9", "127.255.0.9", 80, "a loopback address"},
		{"loopback of IPv6", reach{}, "::1", "::1", 80, "a loopback address"},
		{"loopback as an IPv4-mapped address", reach{}, "::ffff:127.0.0.1", "::ffff:127.0.0.1", 80, "a loopback address"},
		{"the metadata service of a cloud host", reach{}, "169.254.169.254", "169.254.169.254", 80, "a link-local address"},
		{"link-local of IPv6 with a zone", reach{}, "fe80::1%eth0", "fe80::1%eth0", 80, "a link-local address"},
		{"the unspecified address", reach{}, "0.0.0.0", "0.0.0.0", 80, "the unspecified address, which reaches this host"},
		{"the unspecified address of IPv6", reach{}, "::", "::", 80, "the unspecified address, which reaches this host"},
		{"this network", reach{}, "0.1.2.3", "0.1.2.3", 80, "the unspecified address, which reaches this host"},
		{"no address", reach{}, "x", "", 80, "no address"},
		{"a public address", reach{}, "hooks.example.com", "198.51.100.7", 443, ""},
		{"a private address", reach{}, "10.0.0.9", "10.0.0.9", 514, ""},
		{"a unique local address", reach{}, "fd00::1", "fd00::1", 514, ""},
		{"an address of the overlay", reach{}, "100.64.0.1", "100.64.0.1", 514, ""},
		{"a public IPv6 address", reach{}, "2001:db8::1", "2001:db8::1", 514, ""},
		{"the store on its port", reach{store: []netip.AddrPort{store}}, "10.0.0.5", "10.0.0.5", 4001, "the store of this controller"},
		{"the store by a name", reach{store: []netip.AddrPort{store}}, "rqlite.corp", "10.0.0.5", 4001, "the store of this controller"},
		{"the host of the store on another port", reach{store: []netip.AddrPort{store}}, "10.0.0.5", "10.0.0.5", 4002, ""},
		{"another host on the port of the store", reach{store: []netip.AddrPort{store}}, "10.0.0.6", "10.0.0.6", 4001, ""},
		{"loopback in a listed prefix", reach{listed: lists("127.0.0.0/8")}, "127.0.0.1", "127.0.0.1", 4001, ""},
		{"loopback listed by its name", reach{listed: lists("localhost")}, "LocalHost.", "127.0.0.1", 9000, ""},
		{"loopback by another name than the listed", reach{listed: lists("localhost")}, "evil.example", "127.0.0.1", 9000, "a loopback address"},
		{"link-local outside the listed prefix", reach{listed: lists("169.254.1.0/24")}, "169.254.169.254", "169.254.169.254", 80, "a link-local address"},
		{"link-local in the listed prefix", reach{listed: lists("169.254.1.0/24")}, "169.254.1.9", "169.254.1.9", 80, ""},
		{"the store when its host is listed", reach{store: []netip.AddrPort{store}, listed: lists("10.0.0.5")}, "10.0.0.5", "10.0.0.5", 4001, ""},
	} {
		a := netip.Addr{}
		if c.addr != "" {
			a = netip.MustParseAddr(c.addr)
		}
		err := c.r.permit(c.host, a, c.port)
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%s: refused with %v", c.name, err)
		case c.reason != "" && !errors.Is(err, ErrBlocked):
			t.Errorf("%s: gave %v, want a refusal that wraps ErrBlocked", c.name, err)
		case c.reason != "" && !strings.Contains(err.Error(), " is "+c.reason+","):
			t.Errorf("%s: the refusal %q does not say it is %s", c.name, err, c.reason)
		}
	}
	err := reach{}.permit("localhost", netip.MustParseAddr("127.0.0.1"), 4001)
	want := "the address of a target is not allowed: localhost (127.0.0.1) port 4001 is a loopback address, and no admin lists a host or a prefix that holds it (ranz admin-destinations set -targets)"
	if err == nil || err.Error() != want {
		t.Errorf("the refusal is %v, want %q", err, want)
	}
}

// A target that is made is refused when it names loopback, a link-local address, the store, or a name
// that resolves to one of them, and accepted when it names any other address or a listed one. A name
// that does not resolve is accepted, since the connection checks it.
func TestCheck(t *testing.T) {
	names := stubNames{
		"metadata.test": {"169.254.169.254"},
		"loop.test":     {"127.0.0.1", "::1"},
		"rebind.test":   {"198.51.100.4", "127.0.0.1"},
		"hooks.test":    {"198.51.100.4"},
		"rqlite.test":   {"10.0.0.9"},
		"v6.test":       {"2001:db8::7", "::ffff:127.0.0.1"},
	}
	g := &Guard{Resolver: names, Store: func() string { return "rqlite.test:4001" }}
	for _, c := range []struct {
		url     string
		blocked bool
	}{
		{"http://127.0.0.1:4001/db/execute", true},
		{"http://127.0.0.1:4001", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"https://[fe80::1%25eth0]/x", true},
		{"http://[::1]:8080/", true},
		{"http://0.0.0.0/", true},
		{"udp://127.0.0.1:514", true},
		{"tcp://127.0.0.1:514", true},
		{"tls://[::1]:6514", true},
		{"http://metadata.test/", true},
		{"https://loop.test:8443/hook", true},
		{"http://rebind.test:8080/", true},
		{"http://v6.test/", true},
		{"http://10.0.0.9:4001/db/execute", true},
		{"http://rqlite.test:4001/", true},
		{"http://10.0.0.9:4002/", false},
		{"http://10.0.0.9:80/", false},
		{"https://hooks.test/services/T0/B0", false},
		{"http://203.0.113.7:8080/", false},
		{"udp://192.0.2.10:4739", false},
		{"http://never-resolves.test/", false},
	} {
		err := g.Check(context.Background(), c.url)
		switch {
		case c.blocked && (!errors.Is(err, ErrInvalid) || !errors.Is(err, ErrBlocked)):
			t.Errorf("%s: gave %v, want a refusal that wraps ErrInvalid and ErrBlocked", c.url, err)
		case !c.blocked && err != nil:
			t.Errorf("%s: refused with %v", c.url, err)
		}
	}
	if err := g.Check(context.Background(), "http://%zz"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a URL that does not parse gave %v, want ErrInvalid", err)
	}

	// The default port of the scheme counts: the HTTP port of a store on port 80
	web := &Guard{Store: func() string { return "10.0.0.5:80" }}
	if err := web.Check(context.Background(), "http://10.0.0.5/x"); !errors.Is(err, ErrBlocked) {
		t.Errorf("a URL on the default port of a store on it gave %v, want a refusal", err)
	}
	if err := web.Check(context.Background(), "https://10.0.0.5/x"); err != nil {
		t.Errorf("a URL on port 443 of a host whose store is on port 80 gave %v", err)
	}

	// What an admin lists is accepted: a prefix, and a name, which makes the addresses of the name
	for _, c := range []struct {
		allowed []string
		url     string
		blocked bool
	}{
		{[]string{"127.0.0.0/8"}, "http://127.0.0.1:4001/", false},
		{[]string{"127.0.0.1"}, "http://127.0.0.1:4001/", false},
		{[]string{"127.0.0.1"}, "http://127.0.0.2:4001/", true},
		{[]string{"169.254.0.0/16"}, "http://metadata.test/", false},
		{[]string{"loop.test"}, "https://loop.test:8443/hook", false},
		{[]string{"loop.test"}, "https://rebind.test/hook", true},
		{[]string{"LOOP.test."}, "https://loop.test/hook", false},
		{[]string{"::1"}, "https://loop.test/hook", true},
		{[]string{"???", "127.0.0.0/8"}, "http://127.0.0.1/", false},
		{[]string{"???"}, "http://127.0.0.1/", true},
		{[]string{"10.0.0.9"}, "http://10.0.0.9:4001/", false},
	} {
		withList := &Guard{Resolver: names, Allowed: listed(c.allowed...), Store: func() string { return "10.0.0.9:4001" }}
		err := withList.Check(context.Background(), c.url)
		if c.blocked != errors.Is(err, ErrBlocked) || (!c.blocked && err != nil) {
			t.Errorf("with %v listed, %s gave %v, want blocked = %v", c.allowed, c.url, err, c.blocked)
		}
	}

	// A list that cannot be read is no refusal of the target: it is an error of the controller
	failing := &Guard{Allowed: func(context.Context) ([]string, error) { return nil, errors.New("the store is down") }}
	if err := failing.Check(context.Background(), "http://203.0.113.7/"); err == nil || errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "the store is down") {
		t.Errorf("a list that cannot be read gave %v, want its error and no ErrInvalid", err)
	}
}

// A store whose address cannot be read, or whose name does not resolve, names no address that a
// target is refused for: loopback is refused all the same.
func TestStoreThatCannotBeRead(t *testing.T) {
	for _, store := range []string{"", "no-port", "host:port", "unknown.test:4001"} {
		g := &Guard{Resolver: stubNames{}, Store: func() string { return store }}
		if err := g.Check(context.Background(), "http://10.0.0.9:4001/"); err != nil {
			t.Errorf("with the store %q, a host on port 4001 was refused with %v", store, err)
		}
		if err := g.Check(context.Background(), "http://127.0.0.1:4001/"); !errors.Is(err, ErrBlocked) {
			t.Errorf("with the store %q, loopback gave %v, want a refusal", store, err)
		}
	}
}

func TestPortOf(t *testing.T) {
	for raw, want := range map[string]uint16{
		"http://h/x": 80, "https://h": 443, "http://h:8080/": 8080, "udp://h:514": 514, "tcp://h": 0, "tls://[::1]:6514": 6514, "http://h:99999/": 80,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := portOf(u); got != want {
			t.Errorf("portOf(%s) = %d, want %d", raw, got, want)
		}
	}
}

// accepts reports whether ln gets a connection within d.
func accepts(ln net.Listener, d time.Duration) bool {
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(d))
	c, err := ln.Accept()
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// The connection is the place that counts: it connects to loopback only where the list holds it, by
// its name or by a prefix, and it checks each address that a name gives.
func TestDialContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ctx := context.Background()
	names := stubNames{"loop.test": {"127.0.0.1"}, "empty.test": {}, "metadata.test": {"169.254.169.254"}}

	// Nothing is listed: loopback, by its address and by a name, gets no connection
	g := &Guard{Resolver: names}
	for _, address := range []string{ln.Addr().String(), "loop.test:" + port, "metadata.test:80", "[::1]:" + port} {
		if c, err := g.DialContext(ctx, "tcp", address); !errors.Is(err, ErrBlocked) {
			t.Errorf("dialing %s with nothing listed gave %v, want a refusal that wraps ErrBlocked", address, err)
			if c != nil {
				c.Close()
			}
		}
	}
	if accepts(ln, 100*time.Millisecond) {
		t.Error("the listener got a connection that the Guard refused")
	}

	// The prefix is listed, and the name of the host
	for _, allowed := range [][]string{{"127.0.0.0/8"}, {"loop.test"}} {
		g := &Guard{Resolver: names, Allowed: listed(allowed...)}
		address := "loop.test:" + port
		c, err := g.DialContext(ctx, "tcp", address)
		if err != nil {
			t.Fatalf("dialing %s with %v listed: %v", address, allowed, err)
		}
		c.Close()
		if !accepts(ln, 5*time.Second) {
			t.Errorf("the listener got no connection with %v listed", allowed)
		}
	}

	// The list is read at each connection: an entry that is taken out of it stops the next one
	var entries []string
	g = &Guard{Resolver: names, Allowed: func(context.Context) ([]string, error) { return entries, nil }}
	entries = []string{"127.0.0.1"}
	c, err := g.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	entries = nil
	if _, err := g.DialContext(ctx, "tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Errorf("dialing after the entry was taken out gave %v, want a refusal", err)
	}

	// An allowed address that nobody listens on is a failure of the connection, not a refusal
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	allow := &Guard{Resolver: names, Allowed: listed("127.0.0.0/8")}
	if _, err := allow.DialContext(ctx, "tcp", closedAddr); err == nil || errors.Is(err, ErrBlocked) {
		t.Errorf("dialing a port that nobody listens on gave %v, want a refusal of the connection that is no ErrBlocked", err)
	}
	// A canceled context stops the attempts
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := allow.DialContext(canceled, "tcp", ln.Addr().String()); err == nil {
		t.Error("a canceled context connected")
	}

	// What cannot be dialed
	for _, c := range []struct {
		g       *Guard
		address string
		want    string
	}{
		{allow, "no-port", "missing port"},
		{allow, "127.0.0.1:99999", "is not a number from 0 to 65535"},
		{allow, "unknown.test:80", "no such host"},
		{allow, "empty.test:80", "has no address"},
		{&Guard{Allowed: func(context.Context) ([]string, error) { return nil, errors.New("the store is down") }}, "203.0.113.7:80", "the store is down"},
	} {
		if _, err := c.g.DialContext(ctx, "tcp", c.address); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("dialing %s gave %v, want an error that says %q", c.address, err, c.want)
		}
	}
	if err := (&Guard{Resolver: names}).Check(ctx, "http://empty.test/"); err != nil {
		t.Errorf("a name with no address was refused at make time with %v", err)
	}
}

// Of the addresses that a name gives, the Guard connects to an allowed one and skips the one that it
// refuses, which is what a name that gives a public address and a loopback one meets.
func TestDialContextSkipsTheAddressesItRefuses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no listener on 127.0.0.2: %v", err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	g := &Guard{Resolver: stubNames{"multi.test": {"127.0.0.1", "127.0.0.2"}}, Allowed: listed("127.0.0.2")}
	c, err := g.DialContext(context.Background(), "tcp", "multi.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != ln.Addr().String() {
		t.Errorf("connected to %s, want %s", got, ln.Addr())
	}
}

// A datagram socket is connected through the Guard too: it is the way of the IPFIX and syslog targets.
func TestDialContextUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx := context.Background()
	if c, err := (&Guard{}).DialContext(ctx, "udp", pc.LocalAddr().String()); !errors.Is(err, ErrBlocked) {
		t.Errorf("a UDP socket to loopback with nothing listed gave %v, want a refusal", err)
		if c != nil {
			c.Close()
		}
	}
	g := &Guard{Allowed: listed("127.0.0.1")}
	c, err := g.DialContext(ctx, "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("flow")); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if n, _, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "flow" {
		t.Errorf("the datagram that the listener read is %q (%v), want flow", buf[:n], err)
	}
	// Verify looks at the connection that is open against the list as it is now
	if err := g.Verify(ctx, "127.0.0.1", c.RemoteAddr()); err != nil {
		t.Errorf("Verify of an allowed connection gave %v", err)
	}
	if err := (&Guard{}).Verify(ctx, "127.0.0.1", c.RemoteAddr()); !errors.Is(err, ErrBlocked) {
		t.Errorf("Verify after the entry was taken out gave %v, want a refusal", err)
	}
}

// fakeAddr is a net.Addr that is no address and port.
type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func TestVerifyRefusesWhatItCannotRead(t *testing.T) {
	g := &Guard{Allowed: listed("127.0.0.0/8")}
	ctx := context.Background()
	for name, addr := range map[string]net.Addr{"no address": nil, "an address that is none": fakeAddr("pipe-1")} {
		if err := g.Verify(ctx, "x", addr); !errors.Is(err, ErrBlocked) {
			t.Errorf("Verify with %s gave %v, want a refusal", name, err)
		}
	}
	if err := g.Verify(ctx, "x", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}); err != nil {
		t.Errorf("Verify of a listed address gave %v", err)
	}
	failing := &Guard{Allowed: func(context.Context) ([]string, error) { return nil, errors.New("the store is down") }}
	if err := failing.Verify(ctx, "x", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 80}); err == nil || errors.Is(err, ErrBlocked) {
		t.Errorf("Verify with a list that cannot be read gave %v, want its error", err)
	}
}

// control, the check at the socket, refuses what is no address.
func TestControlRefusesWhatIsNoAddress(t *testing.T) {
	check := reach{}.control("x")
	if err := check(context.Background(), "tcp", "not an address", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("an address that is none gave %v, want a refusal", err)
	}
	if err := check(context.Background(), "tcp4", "127.0.0.1:80", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("loopback gave %v, want a refusal", err)
	}
	if err := check(context.Background(), "tcp4", "192.0.2.1:80", nil); err != nil {
		t.Errorf("an ordinary address gave %v", err)
	}
}

// The client of the webhooks connects through the Guard, follows no redirect, uses no proxy and
// keeps no connection between two calls.
func TestHTTPClient(t *testing.T) {
	remotes := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotes <- r.RemoteAddr
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	if _, err := (&Guard{}).HTTPClient(time.Second).Get(srv.URL); !errors.Is(err, ErrBlocked) {
		t.Errorf("a call to loopback with nothing listed gave %v, want a refusal that wraps ErrBlocked", err)
	}
	g := &Guard{Allowed: listed("127.0.0.1")}
	client := g.HTTPClient(7 * time.Second)
	if client.Timeout != 7*time.Second {
		t.Errorf("the client has the timeout %v, want 7s", client.Timeout)
	}
	if tr := client.Transport.(*http.Transport); tr.Proxy != nil || !tr.DisableKeepAlives {
		t.Errorf("the transport has a proxy, or keeps connections: %+v", tr)
	}
	var ports []string
	for range 2 {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "ok" {
			t.Errorf("the call got %q, want ok", body)
		}
		ports = append(ports, <-remotes)
	}
	if ports[0] == ports[1] {
		t.Errorf("two calls came from %s, so the connection was kept between them", ports[0])
	}
	resp, err := client.Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatalf("a call that is answered with a redirect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("the call got %d, want the 302 itself, with no redirect followed", resp.StatusCode)
	}
}
