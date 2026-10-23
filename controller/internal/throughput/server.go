package throughput

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// maxServed is the most connections that a server serves at once; it closes the others.
const maxServed = 256

// server is the state of one Serve.
type server struct {
	logf   func(format string, args ...any)
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// log writes a line to the log of the server, if it has one.
func (s *server) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// add records conn as served, unless the server is closed already.
func (s *server) add(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

// remove forgets conn.
func (s *server) remove(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// closeAll closes the connections that are served, and those that come after.
func (s *server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn := range s.conns {
		conn.Close()
	}
}

// Serve serves the test connections that ln accepts, up to 256 at once, until ctx ends or ln
// fails. When ctx ends it closes ln and the connections, waits for them to end and returns nil;
// when ln fails first, it returns the error. logf, if it is not nil, gets a line for each
// connection, and may be called from several goroutines at once.
func Serve(ctx context.Context, ln net.Listener, logf func(format string, args ...any)) error {
	s := &server{logf: logf, conns: make(map[net.Conn]struct{})}
	stop := context.AfterFunc(ctx, func() {
		ln.Close()
		s.closeAll()
	})
	defer stop()
	var wg sync.WaitGroup
	slots := make(chan struct{}, maxServed)
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.closeAll()
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			s.log("%s: refused, %d connections are served already", remoteName(conn), maxServed)
			conn.Close()
			continue
		}
		if !s.add(conn) {
			<-slots
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer s.remove(conn)
			s.handle(conn)
		}()
	}
}

// remoteName returns the address of the peer of conn for a log line.
func remoteName(conn net.Conn) string {
	if a := conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return "unknown"
}

// handle serves one connection and closes it: the greeting, the request, and the stream that the
// request asks for.
func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	remote := remoteName(conn)
	if err := conn.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
		s.log("%s: %v", remote, err)
		return
	}
	if _, err := io.WriteString(conn, Greeting); err != nil {
		s.log("%s: %v", remote, err)
		return
	}
	// The client may keep a connection waiting while the others of its test open
	if err := conn.SetReadDeadline(time.Now().Add(grace)); err != nil {
		s.log("%s: %v", remote, err)
		return
	}
	req, err := ReadRequest(conn)
	if err != nil {
		s.log("%s: %v", remote, err)
		return
	}
	s.log("%s: %v for %v", remote, req.Direction, req.Span)
	switch req.Direction {
	case Download:
		err = send(conn, req.Span)
	case Upload:
		err = answerUpload(conn, req.Span)
	}
	if err != nil {
		s.log("%s: %v", remote, err)
	}
}

// answerUpload receives the stream of an upload on conn, which lasts for span, and answers its end
// with the report of what arrived.
func answerUpload(conn net.Conn, span time.Duration) error {
	st, err := receive(conn, span+grace)
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(grace)); err != nil {
		return err
	}
	return Report{Bytes: st.bytes, Elapsed: st.elapsed()}.Write(conn)
}
