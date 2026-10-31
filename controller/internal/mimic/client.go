package mimic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The client role: the sidecar listens on the data pipe, and the node connects to it once for each
// stream it wants. The node names a link of start by its address; the sidecar dials the server over
// TCP, runs the REALITY handshake with the ClientHello of the fingerprint of the link (uTLS), and
// answers ok with the channel binding, after which the pipe is the inner stream.

const (
	// maxRequest is the longest line of a request: "dial " and an address.
	maxRequest = 300
	// requestTimeout is how long the node has to send its request after it connected.
	requestTimeout = 10 * time.Second
	// maxStreams is the streams that the client role serves at once.
	maxStreams = 1024
)

// client is the running client role.
type client struct {
	cfg    *clientConfig
	log    *slog.Logger
	count  *counters
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	conns  tracker
	sem    chan struct{}

	// dialOuter makes the TCP connection to a server; tests put a tap on it
	dialOuter func(ctx context.Context, network, address string) (net.Conn, error)
	// now is the clock whose time the proof of a link carries; tests set it to another time
	now func() time.Time
	// hysteria are the links of the Hysteria mode, by address (hysteriaclient.go)
	hysteria map[string]*hyLink
}

// startClient listens on the data pipe.
func startClient(ctx context.Context, cfg *clientConfig, pipe string, count *counters, log *slog.Logger, opts Options) (*client, error) {
	ln, err := listenPipe(pipe)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &client{cfg: cfg, log: log, count: count, ln: ln, ctx: ctx, cancel: cancel, sem: make(chan struct{}, maxStreams), dialOuter: opts.dialOuter, now: opts.now}
	if c.dialOuter == nil {
		c.dialOuter = (&net.Dialer{}).DialContext
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.hysteria = hysteriaLinks(cfg, log, opts)
	c.wg.Add(1)
	go c.acceptLoop()
	return c, nil
}

func (c *client) acceptLoop() {
	defer c.wg.Done()
	for {
		pipe, err := c.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || c.ctx.Err() != nil {
				return
			}
			c.log.Warn("accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case c.sem <- struct{}{}:
		default:
			pipe.Close()
			continue
		}
		c.conns.add(pipe)
		c.wg.Add(1)
		go c.handle(pipe)
	}
}

// handle serves one connection of the node: its request, the connection to the server and the stream.
func (c *client) handle(pipe net.Conn) {
	defer c.wg.Done()
	defer func() { <-c.sem }()
	defer c.conns.remove(pipe)
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("a stream ended in a panic", "panic", r)
			pipe.Close()
		}
	}()

	pipe.SetReadDeadline(time.Now().Add(requestTimeout))
	line, err := readLine(pipe, maxRequest)
	pipe.SetReadDeadline(time.Time{})
	if err != nil {
		c.log.Warn("the node sent no request", "err", err)
		pipe.Close()
		return
	}
	address, ok := strings.CutPrefix(line, "dial ")
	link := c.cfg.links[address]
	if !ok || link == nil {
		c.refuse(pipe, "the address is not a link")
		return
	}
	if link.hysteria != nil {
		c.handleHysteria(pipe, link)
		return
	}

	ctx, cancel := context.WithTimeout(c.ctx, c.cfg.dialTimeout)
	conn, err := c.connect(ctx, link)
	cancel()
	if err != nil {
		c.log.Warn("a link did not connect", "address", address, "err", err)
		c.refuse(pipe, oneLine(err))
		return
	}

	state := conn.ConnectionState()
	c.log.Debug("the TLS session of a link", "address", address, "version", state.Version, "suite", state.CipherSuite)
	if _, err := io.WriteString(pipe, "ok "+bindingText(&state)+"\n"); err != nil {
		conn.Close()
		pipe.Close()
		return
	}
	c.count.streams.Add(1)
	c.log.Info("a link connected", "address", address, "fingerprint", link.fp.name)
	pump(c.log.With("address", address), pipe, newFrameConn(conn, link.shape), c.ctx.Done())
	c.log.Debug("a stream ended", "address", address)
}

// connect dials the server of a link and runs the handshake.
func (c *client) connect(ctx context.Context, l *linkConfig) (*utls.UConn, error) {
	raw, err := c.dialOuter(ctx, "tcp", l.address)
	if err != nil {
		return nil, err
	}
	conn, err := realityHandshake(ctx, raw, l, c.now())
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// refuse answers a request with an error and closes the pipe.
func (c *client) refuse(pipe net.Conn, reason string) {
	io.WriteString(pipe, "error "+reason+"\n")
	pipe.Close()
}

// stop closes the pipe, the streams and the connections of the links, and waits for them to end.
func (c *client) stop() {
	c.cancel()
	c.ln.Close()
	for _, l := range c.hysteria {
		l.close()
	}
	c.conns.closeAll()
	c.wg.Wait()
}
