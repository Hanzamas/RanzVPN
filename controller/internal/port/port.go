// Package port is the controller's network port (#176 "Front door on 443"): one TCP port, 443 by
// default, that terminates TLS and routes each connection by the ALPN protocol its client asked
// for. control.ALPN goes to the node control stream; h2, http/1.1 or no ALPN at all goes to the
// HTTP of the API and, with SDN-28 (#204), the web UI. Redirect is the plain-HTTP port, port 80
// when it is on, which ADR-0020 keeps off by default.
//
// ServeConn is the seam for the front door of SDN-29 (#205). On a host that runs a node too, the
// node owns TCP 443 and hands over each connection that belongs to the controller (by TLS SNI and
// ALPN, the socket itself through WSADuplicateSocketW); the controller then serves it with
// ServeConn instead of accepting it on a listener of its own. The front door is not built yet,
// so today the controller listens itself.
package port

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// handshakeTimeout bounds the TLS handshake of a connection.
const handshakeTimeout = 10 * time.Second

// Server serves the controller's TLS port.
type Server struct {
	// TLS holds the certificate. The server asks for TLS 1.3 and offers the ALPN protocols of
	// the owners it has.
	TLS *tls.Config
	// Control takes over each connection that negotiated control.ALPN; when it is nil, such
	// connections are refused.
	Control func(*tls.Conn)
	// HTTP serves every other connection; when it is nil, they are refused.
	HTTP http.Handler
	// Log is discarded when it is nil.
	Log *slog.Logger

	once  sync.Once
	cfg   *tls.Config
	log   *slog.Logger
	queue *queue
	srv   *http.Server

	mu      sync.Mutex
	closed  bool
	shaking map[net.Conn]struct{} // the connections in their TLS handshake
	wg      sync.WaitGroup
}

func (s *Server) init() {
	s.once.Do(func() {
		s.cfg = s.TLS.Clone()
		s.cfg.MinVersion = tls.VersionTLS13
		s.cfg.NextProtos = nil
		if s.Control != nil {
			s.cfg.NextProtos = append(s.cfg.NextProtos, control.ALPN)
		}
		if s.HTTP != nil {
			s.cfg.NextProtos = append(s.cfg.NextProtos, "h2", "http/1.1")
		}
		s.log = s.Log
		if s.log == nil {
			s.log = slog.New(slog.DiscardHandler)
		}
		s.shaking = map[net.Conn]struct{}{}
		if s.HTTP != nil {
			s.queue = &queue{conns: make(chan net.Conn), done: make(chan struct{})}
			s.srv = &http.Server{
				Handler:           s.HTTP,
				ReadHeaderTimeout: 10 * time.Second,
				ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
			}
			go func() { _ = s.srv.Serve(s.queue) }()
		}
	})
}

// Serve accepts connections on ln and serves each with ServeConn, until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.init()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("accepting a connection", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.ServeConn(raw)
	}
}

// ServeConn serves one accepted TCP connection: the TLS handshake, then the owner of the ALPN
// protocol that the handshake negotiated. A control stream runs on in Control, on this goroutine.
func (s *Server) ServeConn(raw net.Conn) {
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		raw.Close()
		return
	}
	s.shaking[raw] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	tc := s.handshake(raw)
	s.mu.Lock()
	delete(s.shaking, raw)
	closed := s.closed
	s.mu.Unlock()
	s.wg.Done()
	if tc == nil {
		return
	}
	switch p := tc.ConnectionState().NegotiatedProtocol; {
	case closed:
		tc.Close()
	case p == control.ALPN && s.Control != nil:
		s.Control(tc)
	case p != control.ALPN && s.HTTP != nil:
		if !s.queue.push(tc) {
			tc.Close()
		}
	default:
		tc.Close()
	}
}

// handshake runs the TLS handshake on raw and returns the TLS connection, or nil after a failure.
func (s *Server) handshake(raw net.Conn) *tls.Conn {
	tc := tls.Server(raw, s.cfg)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		s.log.Debug("TLS handshake failed", "remote", raw.RemoteAddr().String(), "err", err)
		tc.Close()
		return nil
	}
	return tc
}

// Close stops the HTTP side and closes the connections that are in their TLS handshake. The
// listeners are the caller's to close, and the control streams belong to Control.
func (s *Server) Close() error {
	s.init()
	s.mu.Lock()
	s.closed = true
	for c := range s.shaking {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if s.srv == nil {
		return nil
	}
	s.queue.Close()
	return s.srv.Close()
}

// queue is the listener of the HTTP server: its connections are the TLS connections that
// ServeConn routed to HTTP.
type queue struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (q *queue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *queue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *queue) Addr() net.Addr {
	return queueAddr{}
}

func (q *queue) push(c net.Conn) bool {
	select {
	case q.conns <- c:
		return true
	case <-q.done:
		return false
	}
}

type queueAddr struct{}

func (queueAddr) Network() string { return "tls" }
func (queueAddr) String() string  { return "the TLS port" }
