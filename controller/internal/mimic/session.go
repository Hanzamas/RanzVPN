package mimic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync/atomic"
)

// Options are the options of a session.
type Options struct {
	Logger *slog.Logger // the log of the sidecar; none when nil

	// The tests set these: they leave out what a test has no use for, or look into what a test needs.
	skipDetect bool // the library does not probe the decoy
	dialOuter  func(ctx context.Context, network, address string) (net.Conn, error)
	started    func(*session)
}

// Version names ranz mimic, the program that runs the sidecar, and the libraries it embeds.
func Version() string {
	v := "ranz mimic"
	if bi, ok := debug.ReadBuildInfo(); ok {
		var parts []string
		for _, d := range bi.Deps {
			switch d.Path {
			case "github.com/xtls/reality":
				parts = append(parts, "REALITY "+d.Version)
			case "github.com/refraction-networking/utls":
				parts = append(parts, "uTLS "+d.Version)
			}
		}
		if len(parts) > 0 {
			v += ", " + strings.Join(parts, ", ")
		}
	}
	return v
}

// events carries the messages that the sidecar sends on its own (accepted, probe, error) to the
// node, in a queue: a node that reads slowly never holds up a connection of the sidecar, and a
// message that does not fit is counted and dropped.
type events struct {
	ch      chan Message
	dropped atomic.Uint64
	done    chan struct{}
}

func newEvents(w *Writer) *events {
	e := &events{ch: make(chan Message, 256), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		for m := range e.ch {
			w.Write(m)
		}
	}()
	return e
}

func (e *events) send(m Message) {
	select {
	case e.ch <- m:
	default:
		e.dropped.Add(1)
	}
}

// close ends the queue once what it holds is written. Nothing may send after it.
func (e *events) close() {
	close(e.ch)
	<-e.done
}

// session is one node's sidecar: the role that start asked for.
type session struct {
	role   string
	server *server
	client *client
	count  counters
	ev     *events
}

func (s *session) stop() {
	if s.server != nil {
		s.server.stop()
	}
	if s.client != nil {
		s.client.stop()
	}
}

// Run serves one node on conn until the node closes it or ctx ends: it reads start, runs the role
// that start asks for, tells the node about the connections it takes, and answers its stats
// messages. It returns nil when the node closed the pipe or ctx ended, and the error that ended the
// session otherwise.
func Run(ctx context.Context, conn net.Conn, opts Options) error {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := NewReader(conn)
	w := NewWriter(conn)
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The end of ctx closes the pipe, which ends the read loop.
	stopClose := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopClose()

	first, err := r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the node closed the pipe before start")
		}
		return err
	}
	if first.Type != TypeStart {
		err := fmt.Errorf("the first message is %q, not %q", first.Type, TypeStart)
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}

	s := &session{role: first.Role, ev: newEvents(w)}
	// The pipe first, so that nothing blocks on a node that does not read; then the role; then the queue
	defer func() {
		conn.Close()
		s.stop()
		s.ev.close()
	}()
	ready := Message{Type: TypeReady, Version: Version(), Protocol: ProtocolVersion}
	if err := s.start(ctx, first, &ready, log, opts); err != nil {
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}
	if opts.started != nil {
		opts.started(s)
	}
	if err := w.Write(ready); err != nil {
		return err
	}
	log.Info("started", "role", s.role, "listen", ready.Listen, "decoy", ready.Decoy)

	for {
		m, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch m.Type {
		case TypeStats:
			w.Write(Message{
				Type:     TypeStats,
				Accepted: s.count.accepted.Load(),
				Probes:   s.count.probes.Load(),
				Streams:  s.count.streams.Load(),
				Dropped:  s.ev.dropped.Load(),
			})
		case TypeStart:
			s.ev.send(Message{Type: TypeError, Error: "the sidecar runs already: start comes once"})
		default:
			s.ev.send(Message{Type: TypeError, Error: fmt.Sprintf("unknown message type %q", m.Type)})
		}
	}
}

// start checks the settings of the start message and runs the role, filling in what ready tells.
func (s *session) start(ctx context.Context, m Message, ready *Message, log *slog.Logger, opts Options) error {
	if m.Pipe == "" {
		return errors.New("start: pipe is missing: the data pipe of the node")
	}
	switch m.Role {
	case RoleServer:
		cfg, err := parseServer(m.Server)
		if err != nil {
			return err
		}
		srv, err := startServer(ctx, cfg, m.Pipe, s.ev.send, &s.count, log, opts)
		if err != nil {
			return err
		}
		s.server = srv
		ready.Listen = srv.addr()
		ready.Decoy = srv.decoyAddr()
	case RoleClient:
		cfg, err := parseClient(m.Client)
		if err != nil {
			return err
		}
		cl, err := startClient(ctx, cfg, m.Pipe, &s.count, log, opts)
		if err != nil {
			return err
		}
		s.client = cl
	default:
		return fmt.Errorf("start: role %q is neither %q nor %q", m.Role, RoleServer, RoleClient)
	}
	return nil
}
