package mimic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyerrors "github.com/apernet/hysteria/core/v2/errors"
)

// The Hysteria part of the client role (hysteria.go). Each link of the mode has one QUIC connection to
// its server, made at its first dial and made again once it ended, which carries every stream of the
// link: with one connection, Brutal sends at the rate of the link, and not at that rate for each stream.

var (
	errNoCertificate    = errors.New("the server presented no certificate")
	errWrongCertificate = errors.New("the server presented another certificate than the pin of the link: the pin is wrong, or something on the way redirected the connection")
)

// hyLink is a link of the mode.
type hyLink struct {
	cfg       *linkConfig
	log       *slog.Logger
	brutal    func(role string, bps uint64)                                            // the onBrutal option
	newClient func(*hyclient.Config) (hyclient.Client, *hyclient.HandshakeInfo, error) // hyclient.NewClient, unless a test sets another

	mu   sync.Mutex
	conn *hyConn // nil before the first dial, and once the connection ended
}

// hyConn is the connection of a link.
type hyConn struct {
	client  hyclient.Client
	binding string // the SHA-256 of the certificate that the server presented, as hex digits
}

// connFactory makes the socket of a connection for the client library.
type connFactory func(net.Addr) (net.PacketConn, error)

// New makes the socket of a connection to the server at addr.
func (f connFactory) New(addr net.Addr) (net.PacketConn, error) {
	return f(addr)
}

// hysteriaLinks makes the links of the mode of cfg, by address.
func hysteriaLinks(cfg *clientConfig, log *slog.Logger, opts Options) map[string]*hyLink {
	links := map[string]*hyLink{}
	for address, l := range cfg.links {
		if l.hysteria != nil {
			links[address] = &hyLink{cfg: l, log: log, brutal: opts.onBrutal, newClient: hyclient.NewClient}
		}
	}
	return links
}

// handleHysteria serves the request of the node for a link of the mode: a stream to the server on the
// connection of the link, the answer with the binding of the connection, and the inner stream.
func (c *client) handleHysteria(pipe net.Conn, link *linkConfig) {
	ctx, cancel := context.WithTimeout(c.ctx, c.cfg.dialTimeout)
	stream, binding, err := c.hysteria[link.address].dial(ctx)
	cancel()
	if err != nil {
		c.log.Warn("a link did not connect", "address", link.address, "mode", "hysteria", "err", err)
		c.refuse(pipe, oneLine(err))
		return
	}
	if _, err := io.WriteString(pipe, "ok "+binding+"\n"); err != nil {
		stream.Close()
		pipe.Close()
		return
	}
	c.count.streams.Add(1)
	c.log.Info("a link connected", "address", link.address, "mode", "hysteria")
	pump(c.log.With("address", link.address), pipe, stream, c.ctx.Done())
	c.log.Debug("a stream ended", "address", link.address)
}

// streamName is what a stream asks the server to connect to: a name of its own, by which the server
// tells the streams of its clients apart (hysteriaserver.go). It reaches nothing.
func streamName() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// dial opens a stream to the server of the link on the connection of the link, with the binding of the
// connection. A connection that ended since the stream before is made again, once.
func (l *hyLink) dial(ctx context.Context) (net.Conn, string, error) {
	for again := false; ; again = true {
		conn, err := l.connection(ctx)
		if err != nil {
			return nil, "", err
		}
		stream, err := conn.client.TCP(streamName())
		if err == nil {
			return stream, conn.binding, nil
		}
		var closed hyerrors.ClosedError
		if again || !errors.As(err, &closed) {
			return nil, "", err
		}
		l.drop(conn)
	}
}

// connection gives the connection of the link, which it makes when the link has none.
func (l *hyLink) connection(ctx context.Context) (*hyConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		conn, err := l.connect(ctx)
		if err != nil {
			return nil, err
		}
		l.conn = conn
	}
	return l.conn, nil
}

// drop closes the connection conn, which ended, and forgets it unless the link made another since.
func (l *hyLink) drop(conn *hyConn) {
	l.mu.Lock()
	if l.conn == conn {
		l.conn = nil
	}
	l.mu.Unlock()
	conn.client.Close()
}

// close closes the connection of the link, and its streams with it.
func (l *hyLink) close() {
	l.mu.Lock()
	conn := l.conn
	l.conn = nil
	l.mu.Unlock()
	if conn != nil {
		conn.client.Close()
	}
}

// connect makes the connection of the link: the QUIC handshake with the ClientHello of Chrome and the
// server name of the link, the certificate of the server checked against the pin of the link or the
// roots of the system, and the secret in the auth request of HTTP/3, with the rates of Brutal when the
// link has them. It gives up when ctx ends.
func (l *hyLink) connect(ctx context.Context) (*hyConn, error) {
	h := l.cfg.hysteria
	addr, err := net.ResolveUDPAddr("udp", l.cfg.address)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var socket net.PacketConn // the socket of the connection, which the end of ctx closes
	var binding string        // of the certificate that the server presented
	config := &hyclient.Config{
		ConnFactory: connFactory(func(net.Addr) (net.PacketConn, error) {
			pc, err := listenUDP(":0", h.salamander)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			socket = pc
			mu.Unlock()
			return pc, nil
		}),
		ServerAddr: addr,
		Auth:       h.secret,
		TLSConfig: hyclient.TLSConfig{
			ServerName: l.cfg.serverName,
			// With a pin the certificate is checked by its hash, below: no chain needs to lead to it
			InsecureSkipVerify: h.pin != nil,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errNoCertificate
				}
				sum := sha256.Sum256(raw[0])
				if h.pin != nil && subtle.ConstantTimeCompare(sum[:], h.pin) != 1 {
					return errWrongCertificate
				}
				mu.Lock()
				binding = hex.EncodeToString(sum[:])
				mu.Unlock()
				return nil
			},
		},
		BandwidthConfig: hyclient.BandwidthConfig{MaxTx: h.up, MaxRx: h.down},
	}

	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if socket != nil {
			socket.Close()
		}
	})
	client, info, err := l.newClient(config)
	if !stop() {
		// ctx ended while the connection was made, and its socket is closed
		if err == nil {
			client.Close()
		}
		return nil, fmt.Errorf("the connection to the server did not complete: %w", ctx.Err())
	}
	if err != nil {
		return nil, err
	}
	l.log.Info("a link made its connection", "address", l.cfg.address, "mode", "hysteria", "brutal_bps", info.Tx)
	if l.brutal != nil {
		l.brutal(RoleClient, info.Tx)
	}
	mu.Lock()
	defer mu.Unlock()
	return &hyConn{client: client, binding: binding}, nil
}
