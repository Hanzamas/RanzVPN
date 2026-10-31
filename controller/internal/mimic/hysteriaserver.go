package mimic

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
)

// The Hysteria part of the server role (hysteria.go). The library of Hysteria 2 serves QUIC and HTTP/3
// on the UDP socket of the part and calls the hooks below. A client that presents a secret of the server
// opens streams, and the part gives each of them to the node as a connection of the data pipe; the
// library answers every other request with the masquerade, the landing page of the own decoy.
//
// The binding of a stream is the SHA-256 of the certificate that the server presented on the connection
// of the stream. The library hands the hooks the remote address of a connection and not its TLS state,
// so the part remembers the certificate that it gave each remote address in the handshake
// (certificate), takes it when the client at that address authenticates, as the id of the client
// (Authenticate), and gives it to each stream of the client: the library tells the id with the request
// of a stream (TCPRequest) and then asks for the connection of that stream (TCP) on the same goroutine,
// and the client gives each stream a name of its own (streamName, hysteriaclient.go).

const (
	// maxHandshakes is the handshakes whose certificate the part remembers until their client
	// authenticates. Beyond it a handshake goes unremembered, and its client gets no binding.
	maxHandshakes = 4096
	// handshakeAge is how long the part remembers a handshake whose client did not authenticate.
	handshakeAge = time.Minute
	// noBinding is the binding of a stream whose connection has none, as the first line of the stream
	// says it.
	noBinding = "-"
)

var (
	// errNodeAway is what a client hears when the node does not take its stream: nothing more of the node.
	errNodeAway = errors.New("the stream cannot be served now")
	// errNoUDP refuses UDP, which the part does not carry.
	errNoUDP = errors.New("the Hysteria mode of ranz mimic carries no UDP")
)

// hyServer is the running Hysteria part of the server role.
type hyServer struct {
	ctx    context.Context
	cfg    *hysteriaServerConfig
	pipe   string // the data pipe of the node
	log    *slog.Logger
	emit   func(Message)
	count  *counters
	brutal func(role string, bps uint64)                        // the onBrutal option
	page   http.Handler                                         // the landing page of the own decoy
	certs  func(*tls.ClientHelloInfo) (*tls.Certificate, error) // the certificate of the own decoy
	srv    hyserver.Server
	addr   string        // where the listener listens
	done   chan struct{} // closed once Serve returned

	mu         sync.Mutex
	handshakes map[string]handshake // by the remote address of the connection
	requests   map[string]string    // the binding of each stream, by its name, from TCPRequest to TCP
	pipes      map[*hyPipe]struct{} // the connections of the data pipe that the streams hold
}

// handshake is what the part remembers of a handshake until its client authenticates.
type handshake struct {
	binding string
	at      time.Time
}

// hyPipe is a connection of the data pipe that a stream holds, which stop closes while it is open.
type hyPipe struct {
	net.Conn
	h    *hyServer
	once sync.Once
}

// Close closes the connection and forgets it.
func (p *hyPipe) Close() error {
	p.once.Do(func() {
		p.h.mu.Lock()
		delete(p.h.pipes, p)
		p.h.mu.Unlock()
	})
	return p.Conn.Close()
}

// startHysteria runs the Hysteria listener of the server role, with the certificate and the landing page
// of the own decoy d.
func startHysteria(ctx context.Context, cfg *hysteriaServerConfig, d *decoy, page []byte, pipe string, emit func(Message), count *counters, log *slog.Logger, opts Options) (*hyServer, error) {
	h := &hyServer{ctx: ctx, cfg: cfg, pipe: pipe, log: log, emit: emit, count: count, brutal: opts.onBrutal, page: landing(page),
		done: make(chan struct{}), handshakes: map[string]handshake{}, requests: map[string]string{}, pipes: map[*hyPipe]struct{}{}}
	h.certs = d.srv.TLSConfig.GetCertificate
	if h.certs == nil {
		// The self-signed decoy holds its certificate
		cert := d.srv.TLSConfig.Certificates[0]
		h.certs = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	}

	conn, err := listenUDP(cfg.listen, cfg.salamander)
	if err != nil {
		return nil, fmt.Errorf("the Hysteria listener cannot listen on %s: %w", cfg.listen, err)
	}
	h.addr = conn.LocalAddr().String()
	h.srv, err = hyserver.NewServer(&hyserver.Config{
		TLSConfig:       hyserver.TLSConfig{GetCertificate: h.certificate},
		Conn:            conn,
		Outbound:        h,
		BandwidthConfig: hyserver.BandwidthConfig{MaxTx: cfg.maxRate, MaxRx: cfg.maxRate},
		DisableUDP:      true,
		Authenticator:   h,
		EventLogger:     h,
		MasqHandler:     http.HandlerFunc(h.masquerade),
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("the Hysteria listener: %w", err)
	}
	go func() {
		defer close(h.done)
		h.srv.Serve()
	}()
	return h, nil
}

// hysteriaAddr is where the Hysteria listener of the server role listens, "" without the mode.
func (s *server) hysteriaAddr() string {
	if s.hy == nil {
		return ""
	}
	return s.hy.addr
}

// certificate gives the certificate of the own decoy to a handshake, and remembers its binding for the
// remote address of the handshake until the client there authenticates.
func (h *hyServer) certificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := h.certs(info)
	if err != nil || cert == nil || len(cert.Certificate) == 0 || info.Conn == nil {
		return cert, err
	}
	h.remember(info.Conn.RemoteAddr().String(), certBinding(cert.Certificate[0]))
	return cert, nil
}

// remember keeps the binding of a handshake. At maxHandshakes it first forgets the handshakes older than
// handshakeAge, whose clients never authenticated, and it keeps nothing when that leaves no room.
func (h *hyServer) remember(addr, binding string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if len(h.handshakes) >= maxHandshakes {
		for a, hs := range h.handshakes {
			if now.Sub(hs.at) > handshakeAge {
				delete(h.handshakes, a)
			}
		}
		if len(h.handshakes) >= maxHandshakes {
			return
		}
	}
	h.handshakes[addr] = handshake{binding: binding, at: now}
}

// Authenticate takes a client that presents one of the secrets. Its id is the binding of the certificate
// that its connection got, which the library hands to the hooks of the streams of the connection.
func (h *hyServer) Authenticate(addr net.Addr, auth string, _ uint64) (bool, string) {
	ok := false
	for _, s := range h.cfg.secrets {
		if subtle.ConstantTimeCompare([]byte(auth), []byte(s)) == 1 {
			ok = true
		}
	}
	if !ok {
		return false, ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hs, found := h.handshakes[addr.String()]
	delete(h.handshakes, addr.String())
	if !found {
		return true, noBinding
	}
	return true, hs.binding
}

// Connect counts a client that authenticated and tells the node, as the REALITY listener does.
func (h *hyServer) Connect(addr net.Addr, _ string, tx uint64) {
	h.count.accepted.Add(1)
	h.log.Info("a client authenticated", "peer", addr.String(), "mode", "hysteria", "brutal_bps", tx)
	h.emit(Message{Type: TypeAccepted, Peer: addr.String()})
	if h.brutal != nil {
		h.brutal(RoleServer, tx)
	}
}

// Disconnect logs a client that left.
func (h *hyServer) Disconnect(addr net.Addr, _ string, err error) {
	h.log.Debug("a Hysteria client left", "peer", addr.String(), "err", err)
}

// TCPRequest keeps the binding of the connection of a stream for TCP, which the library calls next for
// the stream.
func (h *hyServer) TCPRequest(_ net.Addr, id, reqAddr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests[reqAddr] = id
}

// TCPError logs how a stream ended.
func (h *hyServer) TCPError(addr net.Addr, _, _ string, err error) {
	h.log.Debug("a Hysteria stream ended", "peer", addr.String(), "err", err)
}

// UDPRequest is never called: the part carries no UDP (DisableUDP).
func (h *hyServer) UDPRequest(net.Addr, string, uint32, string) {}

// UDPError is never called either.
func (h *hyServer) UDPError(net.Addr, string, uint32, error) {}

// TCP gives a stream of a client its connection to the node: a connection of the data pipe, with the
// binding of the connection of the client in its first line.
func (h *hyServer) TCP(reqAddr string) (net.Conn, error) {
	h.mu.Lock()
	binding, ok := h.requests[reqAddr]
	delete(h.requests, reqAddr)
	h.mu.Unlock()
	if !ok {
		binding = noBinding
	}

	ctx, cancel := context.WithTimeout(h.ctx, pipeDialTimeout)
	conn, err := dialPipe(ctx, h.pipe)
	cancel()
	if err != nil {
		h.log.Error("a client cannot reach the node", "mode", "hysteria", "err", err)
		h.emit(Message{Type: TypeError, Error: "the data pipe of the node: " + oneLine(err)})
		return nil, errNodeAway
	}
	if _, err := io.WriteString(conn, "bind "+binding+"\n"); err != nil {
		conn.Close()
		h.log.Error("the node does not read its data pipe", "mode", "hysteria", "err", err)
		return nil, errNodeAway
	}
	h.count.streams.Add(1)
	p := &hyPipe{Conn: conn, h: h}
	h.mu.Lock()
	h.pipes[p] = struct{}{}
	h.mu.Unlock()
	return p, nil
}

// UDP refuses UDP.
func (h *hyServer) UDP(string) (hyserver.UDPConn, error) {
	return nil, errNoUDP
}

// CheckUDP refuses UDP.
func (h *hyServer) CheckUDP(string) error {
	return errNoUDP
}

// masquerade answers a request that is no Ranz client's (of a browser, a prober, a client with a wrong
// secret) as the own decoy site does, and counts it as a probe, logged at the debug level only: a
// stranger can send as many as it likes.
func (h *hyServer) masquerade(w http.ResponseWriter, r *http.Request) {
	h.count.probes.Add(1)
	h.log.Debug("an HTTP/3 request that is no client's was answered by the decoy", "peer", r.RemoteAddr)
	h.emit(Message{Type: TypeProbe, Peer: r.RemoteAddr, Reason: "an HTTP/3 request that is no Ranz client's"})
	h.page.ServeHTTP(w, r)
}

// stop closes the listener and its connections, and the streams to the node.
func (h *hyServer) stop() {
	h.srv.Close()
	<-h.done
	h.mu.Lock()
	pipes := make([]*hyPipe, 0, len(h.pipes))
	for p := range h.pipes {
		pipes = append(pipes, p)
	}
	h.mu.Unlock()
	for _, p := range pipes {
		p.Close()
	}
}
