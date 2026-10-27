package port

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// clock is a clock that a test sets.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// tcp returns the address of a TCP peer, as a net.Addr.
func tcp(addr string) net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))
}

// fromConn is a connection that says it comes from another address, so a test has as many sources as it
// likes on one machine.
type fromConn struct {
	net.Conn
	remote net.Addr
}

func (c fromConn) RemoteAddr() net.Addr { return c.remote }

// from returns c as a connection from addr.
func from(c net.Conn, addr string) net.Conn { return fromConn{c, tcp(addr)} }

// waitFor waits until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not come about within 10 s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The caps of the connections that wait for their TLS handshake: in all, and for one source; a place that a
// connection gives back is taken again, and the second call of the function that gives it back does nothing.
func TestLimiterCapsPendingInAllAndForASource(t *testing.T) {
	l := newLimiter(Limits{MaxPending: 5, MaxPendingPerSource: 2}, newClock().now)
	a1, err := l.enter(tcp("192.0.2.1:1000"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.enter(tcp("192.0.2.1:1001")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.enter(tcp("192.0.2.1:1002")); !errors.Is(err, errPendingSource) {
		t.Fatalf("the third connection of a source with a cap of 2: %v, want %v", err, errPendingSource)
	}
	for _, addr := range []string{"192.0.2.2:1", "192.0.2.2:2", "192.0.2.3:1"} {
		if _, err := l.enter(tcp(addr)); err != nil {
			t.Fatalf("%s, with room in all and for its source: %v", addr, err)
		}
	}
	if _, err := l.enter(tcp("192.0.2.4:1")); !errors.Is(err, errPendingFull) {
		t.Fatalf("the sixth connection with a cap of 5 in all: %v, want %v", err, errPendingFull)
	}

	a1()
	a1()
	if got := l.refusals().Pending; got != 4 {
		t.Errorf("%d connections pending after one gave its place back twice, want 4", got)
	}
	if _, err := l.enter(tcp("192.0.2.1:1003")); err != nil {
		t.Errorf("a connection of the source whose place was given back: %v", err)
	}
	if got, want := l.refusals(), (Refusals{Pending: 5, Sources: 3, Admitted: 6, Full: 1, Source: 1}); got != want {
		t.Errorf("the counters are %+v, want %+v", got, want)
	}
}

// A source is an IPv4 address, or the /64 that an IPv6 address is in, as the cap on the streams that wait for a
// Hello counts one; an IPv4-mapped IPv6 address is its IPv4 address.
func TestLimiterCountsAnIPv6SlashSixtyFourAsOneSource(t *testing.T) {
	l := newLimiter(Limits{MaxPendingPerSource: 1}, newClock().now)
	for _, c := range []struct {
		addr string
		ok   bool
	}{
		{"[2001:db8:1:2::1]:1", true},
		{"[2001:db8:1:2:ffff::9]:2", false}, // the same /64
		{"[2001:db8:1:3::1]:3", true},       // another /64
		{"192.0.2.1:4", true},
		{"[::ffff:192.0.2.1]:5", false}, // the same IPv4 address
		{"192.0.2.2:6", true},
	} {
		_, err := l.enter(tcp(c.addr))
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want admitted %v", c.addr, err, c.ok)
		}
	}
}

// A source has a rate for its new connections and one for its TLS handshakes, each a bucket with a burst and
// a rate: the connection or the handshake over it is refused, and the bucket fills again with time.
func TestLimiterRates(t *testing.T) {
	clk := newClock()
	l := newLimiter(Limits{ConnectRate: 2, ConnectBurst: 3, HandshakeRate: 1, HandshakeBurst: 2}, clk.now)
	a, b := tcp("192.0.2.1:1"), tcp("192.0.2.2:1")

	for i := 0; i < 3; i++ {
		leave, err := l.enter(a)
		if err != nil {
			t.Fatalf("connection %d within the burst of 3: %v", i+1, err)
		}
		leave()
	}
	if _, err := l.enter(a); !errors.Is(err, errConnectRate) {
		t.Fatalf("the fourth connection in the same instant: %v, want %v", err, errConnectRate)
	}
	if _, err := l.enter(b); err != nil {
		t.Errorf("another source meanwhile: %v", err)
	}
	clk.advance(500 * time.Millisecond) // one token at 2 a second
	if _, err := l.enter(a); err != nil {
		t.Errorf("a connection after a token came back: %v", err)
	}
	if _, err := l.enter(a); !errors.Is(err, errConnectRate) {
		t.Errorf("a second one after only one token came back: %v, want %v", err, errConnectRate)
	}

	for i := 0; i < 2; i++ {
		if err := l.handshake(a); err != nil {
			t.Fatalf("handshake %d within the burst of 2: %v", i+1, err)
		}
	}
	if err := l.handshake(a); !errors.Is(err, errHandshakeRate) {
		t.Fatalf("the third handshake in the same instant: %v, want %v", err, errHandshakeRate)
	}
	if err := l.handshake(b); err != nil {
		t.Errorf("a handshake of another source meanwhile: %v", err)
	}
	clk.advance(time.Second)
	if err := l.handshake(a); err != nil {
		t.Errorf("a handshake after a second: %v", err)
	}
	if got := l.refusals(); got.Rate != 2 || got.Handshake != 1 {
		t.Errorf("the refusals are %+v, want 2 for the rate of connections and 1 for the rate of handshakes", got)
	}
}

// The table of sources is bounded: a source that holds nothing and has all its tokens is forgotten, and when
// the table is full of sources that are not, the next new source is refused as the port being full.
func TestLimiterForgetsTheSourcesThatHoldNothing(t *testing.T) {
	clk := newClock()
	l := newLimiter(Limits{}, clk.now)
	for i := 0; i < maxSources; i++ {
		leave, err := l.enter(tcp(fmt.Sprintf("10.%d.%d.%d:1", i>>16, (i>>8)&0xff, i&0xff)))
		if err != nil {
			t.Fatalf("source %d: %v", i, err)
		}
		leave()
	}
	if _, err := l.enter(tcp("192.0.2.1:1")); !errors.Is(err, errPendingFull) {
		t.Fatalf("a new source with the table full of sources that have spent a token: %v, want %v", err, errPendingFull)
	}
	clk.advance(time.Hour)
	if _, err := l.enter(tcp("192.0.2.1:1")); err != nil {
		t.Fatalf("a new source once the others have all their tokens again: %v", err)
	}
	if got := l.refusals().Sources; got != 1 {
		t.Errorf("%d sources in the table after the sweep, want only the one that holds a connection", got)
	}
}

// echo is the Control of a port that echoes what a node writes, for as long as it is connected.
func echo(connected *atomic.Int64) func(*tls.Conn) {
	return func(tc *tls.Conn) {
		connected.Add(1)
		defer tc.Close()
		_, _ = io.Copy(tc, tc)
	}
}

// tcpPair returns the two ends of a TCP connection on the loopback interface, which close with the test. A TLS
// handshake needs the buffers of TCP: over a net.Pipe, which has none, the server and the client can each wait for the
// other to read.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// dial returns a TLS client of the control stream whose connection the Server takes as one from addr.
func dial(t *testing.T, s *Server, addr string) *tls.Conn {
	t.Helper()
	cli, srv := tcpPair(t)
	go s.ServeConn(from(srv, addr))
	tc := tls.Client(cli, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	return tc
}

// node is a Node at addr that completes the TLS handshake of its control stream.
func node(t *testing.T, s *Server, addr string) *tls.Conn {
	t.Helper()
	tc := dial(t, s, addr)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the handshake of a node at %s: %v", addr, err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc
}

// echoes checks that the control stream tc carries a byte to the Control of its port and back.
func echoes(t *testing.T, tc *tls.Conn, what string) {
	t.Helper()
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	defer tc.SetDeadline(time.Time{})
	if _, err := tc.Write([]byte{7}); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(tc, b); err != nil || b[0] != 7 {
		t.Fatalf("%s: read %v, %v", what, b, err)
	}
}

// A flood of new connections from one source, which hold their places and say nothing, is cut at the cap of the
// source, and the Controller serves the connections of another source meanwhile, and the source again once the
// flood is gone: the first and the third criterion of AUD1-DT-3 (#451) for the TLS port. The connections of a
// flood are ones that the Server takes with no ClientHello, which is how a stranger holds the 10 s of a handshake.
func TestFloodFromOneSourceIsCutAtItsCap(t *testing.T) {
	const limit = 8
	var connected atomic.Int64
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: echo(&connected), Limits: Limits{MaxPending: 64, MaxPendingPerSource: limit}}
	defer s.Close()

	var held []net.Conn
	for i := 0; i < 3*limit; i++ {
		srv, cli := net.Pipe()
		held = append(held, cli)
		go s.ServeConn(from(srv, fmt.Sprintf("198.51.100.7:%d", 40000+i)))
	}
	waitFor(t, "the flood to meet its cap", func() bool { r := s.Refusals(); return r.Source == 2*limit && r.Pending == limit })
	if r := s.Refusals(); r.Admitted != limit || r.Full != 0 {
		t.Errorf("the refusals are %+v, want %d admitted for the cap of the source and none for the cap in all", r, limit)
	}

	// A connection of another source is served while the flood holds its places
	tc := node(t, s, "198.51.100.8:40000")
	defer tc.Close()
	echoes(t, tc, "a node of another source during the flood")
	if connected.Load() != 1 {
		t.Errorf("Control took %d connections during the flood, want the one of the other source", connected.Load())
	}

	// The flood ends: its places come back, and the source is served again
	for _, c := range held {
		c.Close()
	}
	waitFor(t, "the places of the flood to come back", func() bool { return s.Refusals().Pending == 0 })
	again := node(t, s, "198.51.100.7:50000")
	defer again.Close()
	echoes(t, again, "a node of the source of the flood, after it")
}

// The control stream of a Node that the Controller admitted goes on while another source floods the port to its
// cap, and while a flood from many sources fills the port as a whole the stream is still not one of the pending
// connections: the third criterion of AUD1-DT-3 (#451).
func TestAdmittedControlStreamIsNotRefusedByAFloodFromAnotherSource(t *testing.T) {
	var connected atomic.Int64
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: echo(&connected), Limits: Limits{MaxPending: 12, MaxPendingPerSource: 4}}
	defer s.Close()

	admitted := node(t, s, "203.0.113.5:1000")
	defer admitted.Close()
	echoes(t, admitted, "the admitted node before the flood")
	waitFor(t, "the admitted node to hold no place", func() bool { return s.Refusals().Pending == 0 })

	// Three sources fill the port as a whole, each to its cap
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for src := 0; src < 3; src++ {
		for i := 0; i < 4; i++ {
			srv, cli := net.Pipe()
			held = append(held, cli)
			go s.ServeConn(from(srv, fmt.Sprintf("198.51.100.%d:%d", 10+src, 40000+i)))
		}
	}
	waitFor(t, "the flood to fill the port", func() bool { return s.Refusals().Pending == 12 })

	// The admitted stream goes on, and a new connection of any source, its own too, is refused: the port is full
	echoes(t, admitted, "the admitted node during the flood")
	srv, cli := net.Pipe()
	defer cli.Close()
	go s.ServeConn(from(srv, "203.0.113.5:2000"))
	waitFor(t, "a new connection to be refused for the cap in all", func() bool { return s.Refusals().Full == 1 })
	echoes(t, admitted, "the admitted node after a new connection was refused")
	if connected.Load() != 1 {
		t.Errorf("Control took %d streams, want only the admitted node's", connected.Load())
	}
}

// 1000 Nodes behind one address connect with the defaults, all in the same moment: the fourth criterion of
// AUD1-DT-3 (#451). Each opens a TCP connection from the loopback address, which is one source, and completes the TLS
// handshake of the control stream; none is refused.
func TestThousandNodesBehindOneAddressConnectWithTheDefaults(t *testing.T) {
	const nodes = 1000
	var connected atomic.Int64
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: echo(&connected)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() {
		ln.Close()
		<-done
		s.Close()
	}()

	var wg sync.WaitGroup
	var failed atomic.Int64
	start := make(chan struct{})
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d := net.Dialer{Timeout: 60 * time.Second}
			raw, err := d.Dial("tcp", ln.Addr().String())
			if err != nil {
				failed.Add(1)
				return
			}
			defer raw.Close()
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
			_ = tc.SetDeadline(time.Now().Add(60 * time.Second))
			if err := tc.Handshake(); err != nil {
				failed.Add(1)
				return
			}
			// The stream is the node's: it holds until the test is over
			if _, err := tc.Write([]byte{1}); err != nil {
				failed.Add(1)
				return
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(tc, b); err != nil {
				failed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if failed.Load() != 0 || connected.Load() != nodes {
		t.Errorf("%d of %d Nodes behind one address did not connect, and Control took %d streams", failed.Load(), nodes, connected.Load())
	}
	r := s.Refusals()
	if r.Admitted != nodes || r.Full+r.Source+r.Rate+r.Handshake != 0 {
		t.Errorf("the refusals are %+v, want %d admitted and none refused", r, nodes)
	}
}

// A source that starts TLS handshakes faster than its rate has the excess refused at its ClientHello, and counted,
// where the connections themselves were within their rate.
func TestHandshakeRateIsCutAtTheClientHello(t *testing.T) {
	var connected atomic.Int64
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: echo(&connected), Limits: Limits{HandshakeRate: 0.001, HandshakeBurst: 2}}
	defer s.Close()

	for i := 0; i < 2; i++ {
		tc := node(t, s, "198.51.100.30:1000")
		defer tc.Close()
		echoes(t, tc, fmt.Sprintf("handshake %d within the burst", i+1))
	}
	if err := dial(t, s, "198.51.100.30:1001").Handshake(); err == nil {
		t.Error("the third handshake of a source with a burst of 2 was served")
	}
	if r := s.Refusals(); r.Handshake != 1 || r.Admitted != 3 {
		t.Errorf("the refusals are %+v, want 3 connections admitted and 1 handshake refused", r)
	}
	other := node(t, s, "198.51.100.31:1000")
	defer other.Close()
	echoes(t, other, "a handshake of another source")
}
