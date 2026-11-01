package mimic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/reality"
)

// The server role: a REALITY listener on TCP (443 by default), the server side of the mimicry
// transport (ADR-0023). A client that proves the key of the server is a Ranz client: its inner
// stream goes to the node over a connection of the data pipe. A connection that does not is
// spliced to the decoy by the library, byte for byte, so a prober sees the decoy and its real
// certificate and never the sidecar; the sidecar counts it.

const (
	// maxConns is the connections that the listener serves at once, probers included; a flood
	// beyond it is closed at the accept.
	maxConns = 2048
	// pipeDialTimeout bounds the connection to the data pipe of the node.
	pipeDialTimeout = 10 * time.Second
	// destDialTimeout bounds the connection of the library to the decoy.
	destDialTimeout = 10 * time.Second
	// warmTimeout is how long start waits for the library to probe the decoy.
	warmTimeout = 30 * time.Second
)

// counters are what the sidecar counts; the node asks for them with stats.
type counters struct {
	accepted atomic.Uint64
	probes   atomic.Uint64
	streams  atomic.Uint64
}

// server is the running server role.
type server struct {
	cfg     *serverConfig
	pipe    string // the data pipe of the node
	log     *slog.Logger
	emit    func(Message)
	count   *counters
	reality *reality.Config
	ln      net.Listener
	decoy   *decoy // the own decoy; nil in the borrow mode
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	conns   tracker
	sem     chan struct{}
	// The Hysteria mode (hysteriaserver.go); nil without it
	hy *hyServer
}

// startServer runs the decoy (the own mode), the listener and the probes of the library, and
// returns once the library has probed the decoy, so that the first client does not wait for them.
func startServer(ctx context.Context, cfg *serverConfig, pipe string, emit func(Message), count *counters, log *slog.Logger, opts Options) (*server, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &server{cfg: cfg, pipe: pipe, log: log, emit: emit, count: count, ctx: ctx, cancel: cancel, sem: make(chan struct{}, maxConns)}

	dest := cfg.decoy.dest
	if cfg.decoy.mode == DecoyOwn {
		d, err := startDecoy(cfg.decoy, log)
		if err != nil {
			cancel()
			return nil, err
		}
		s.decoy = d
		dest = d.addr
	}

	s.reality = realityConfig(cfg, dest)

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		s.stop()
		return nil, fmt.Errorf("the REALITY listener cannot listen on %s: %w", cfg.listen, err)
	}
	s.ln = ln

	// The Hysteria mode beside REALITY, with the own decoy as its masquerade (hysteriaserver.go)
	if cfg.hysteria != nil {
		if s.hy, err = startHysteria(ctx, cfg.hysteria, s.decoy, cfg.decoy.page, pipe, emit, count, log, opts); err != nil {
			s.stop()
			return nil, err
		}
	}

	// The library learns what a real handshake of the decoy looks like after the Finished message, so
	// that the connections it takes look the same: it probes the decoy once for each server name and
	// kind of ClientHello, in the background. The tests need none of that.
	if opts.skipDetect {
		for _, key := range detectionKeys(dest, cfg.serverNames) {
			reality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
		}
	} else {
		go reality.DetectPostHandshakeRecordsLens(s.reality)
	}

	// The listener runs before the wait: the ACME service validates the decoy through it
	s.wg.Add(1)
	go s.acceptLoop()
	if !opts.skipDetect {
		s.warm(dest)
	}
	return s, nil
}

// realityConfig is the configuration of the library for a server of cfg whose connections that are
// no client are spliced to dest: the keys, the short ids, the names and the clock that make a
// client, and the versions of the proof that the clients of Ranz send. The library copies the
// records that the real site sends after its handshake, a session ticket among them, by writing
// over the record that carries a session ticket (its record layer), so the server sends no ticket
// of its own (SessionTicketsDisabled) and sets no ALPN protocol (NextProtos stays nil), as Xray
// configures the library.
func realityConfig(cfg *serverConfig, dest string) *reality.Config {
	names := make(map[string]bool, len(cfg.serverNames))
	for _, n := range cfg.serverNames {
		names[n] = true
	}
	dialer := &net.Dialer{Timeout: destDialTimeout}
	return &reality.Config{
		DialContext:                 dialer.DialContext,
		Type:                        "tcp",
		Dest:                        dest,
		ServerNames:                 names,
		PrivateKey:                  cfg.key,
		MinClientVer:                minClientVersion,
		MaxClientVer:                maxClientVersion,
		MaxTimeDiff:                 cfg.maxTimeDiff,
		ShortIds:                    cfg.shortIDs,
		DynamicRecordSizingDisabled: true,
		SessionTicketsDisabled:      true,
	}
}

// detectionKeys are the keys of the probes that the library makes for dest: one for each server
// name and for each kind of ClientHello (no ALPN, HTTP/1.1 only, h2).
func detectionKeys(dest string, names []string) []string {
	var keys []string
	for _, n := range names {
		for alpn := range 3 {
			keys = append(keys, dest+" "+n+" "+strconv.Itoa(alpn))
		}
	}
	return keys
}

// warm waits until the library has probed dest for every server name, or warmTimeout passed.
func (s *server) warm(dest string) {
	keys := detectionKeys(dest, s.cfg.serverNames)
	start := time.Now()
	for time.Since(start) < warmTimeout {
		done := true
		for _, key := range keys {
			// A probe that is running holds a bool; a finished one holds the record lengths it saw
			if v, ok := reality.GlobalPostHandshakeRecordsLens.Load(key); !ok {
				done = false
			} else if _, ok := v.([]int); !ok {
				done = false
			}
		}
		if done {
			s.log.Info("REALITY probed the decoy", "dest", dest, "took", time.Since(start).Round(time.Millisecond))
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	s.log.Warn("REALITY did not finish probing the decoy in time: the first clients wait for it", "dest", dest, "waited", warmTimeout)
}

// addr is where the listener listens.
func (s *server) addr() string {
	return s.ln.Addr().String()
}

// decoyAddr is where the own decoy listens, "" in the borrow mode.
func (s *server) decoyAddr() string {
	if s.decoy == nil {
		return ""
	}
	return s.decoy.addr
}

func (s *server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			s.log.Warn("accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		s.conns.add(c)
		s.wg.Add(1)
		go s.handle(c)
	}
}

// handle serves one connection: the library takes it, and a client that proved the key gets a stream
// to the node.
func (s *server) handle(raw net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.sem }()
	defer s.conns.remove(raw)
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("a connection ended in a panic", "panic", r)
			raw.Close()
		}
	}()

	peer := raw.RemoteAddr().String()
	conn, err := reality.Server(s.ctx, raw, s.reality)
	if err != nil {
		reason, spliced := strings.CutPrefix(err.Error(), "REALITY: processed invalid connection from "+peer+": ")
		if !spliced {
			// The library could not reach the decoy, so it spliced nothing
			s.log.Error("the decoy cannot be reached", "peer", peer, "err", err)
			s.emit(Message{Type: TypeError, Peer: peer, Error: oneLine(err)})
			return
		}
		// Not a Ranz client: the library spliced it to the decoy, and it is over now. It is counted, and
		// logged at the debug level only: a stranger can send as many as it likes (CORE-P2-6, #406)
		s.count.probes.Add(1)
		s.log.Debug("a connection that is no client was spliced to the decoy", "peer", peer, "reason", reason)
		s.emit(Message{Type: TypeProbe, Peer: peer, Reason: reason})
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, pipeDialTimeout)
	pipe, err := dialPipe(ctx, s.pipe)
	cancel()
	if err != nil {
		conn.Close()
		s.log.Error("a client cannot reach the node", "peer", peer, "err", err)
		s.emit(Message{Type: TypeError, Peer: peer, Error: "the data pipe of the node: " + oneLine(err)})
		return
	}
	state := conn.ConnectionState()
	s.log.Debug("the TLS session of a client", "peer", peer, "version", state.Version, "suite", state.CipherSuite)
	if _, err := io.WriteString(pipe, "bind "+bindingText(&state)+"\n"); err != nil {
		conn.Close()
		pipe.Close()
		s.log.Error("the node does not read its data pipe", "peer", peer, "err", err)
		return
	}

	s.count.accepted.Add(1)
	s.count.streams.Add(1)
	s.log.Info("a client authenticated", "peer", peer)
	s.emit(Message{Type: TypeAccepted, Peer: peer})
	pump(s.log.With("peer", peer), pipe, newFrameConn(conn, s.cfg.shape), s.ctx.Done())
	s.log.Debug("a stream ended", "peer", peer)
}

// stop closes the listener, the decoy and every connection, and waits for them to end.
func (s *server) stop() {
	s.cancel()
	if s.ln != nil {
		s.ln.Close()
	}
	if s.hy != nil {
		s.hy.stop()
	}
	s.conns.closeAll()
	if s.decoy != nil {
		s.decoy.close()
	}
	s.wg.Wait()
}
