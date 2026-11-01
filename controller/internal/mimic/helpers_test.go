package mimic

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The helpers of the tests: the node's side of the pipes (the control pipe, the data pipes), a site
// that stands for the real site of the borrow decoy, and a tap on the outer connection of a client.
// A test is the node: it starts the sidecar the way the node does, with Run on a control pipe, and
// talks to it over the pipes of the platform (Unix sockets off Windows).

// testTimeout bounds every wait of a test; a CI runner is slow, and a hang is a failure.
const testTimeout = 60 * time.Second

var pipeCounter atomic.Uint64

// pipeName is a name for a pipe that a test makes: a named pipe on Windows, a Unix socket in a
// short folder of its own elsewhere (the path of a Unix socket is at most 104 bytes, which the folder
// that t.TempDir makes for a long test name can pass).
func pipeName(t *testing.T, label string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\ranz-mimic-%s-%d-%d`, label, os.Getpid(), pipeCounter.Add(1))
	}
	dir, err := os.MkdirTemp("", "rzm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, label+".sock")
}

// logSink is where the log of a sidecar goes; the test prints it when it ends, never while a goroutine
// of the sidecar still logs.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// testLogger makes a logger whose text the test prints at its end. Make it before the first sidecar
// of the test: the cleanups run in the reverse order, so it prints after they stopped.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	sink := &logSink{}
	t.Cleanup(func() {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		t.Log("the log of the sidecar:\n" + sink.b.String())
	})
	return slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// keyPair makes the key pair of a server as 64 hex digits each.
func keyPair(t *testing.T) (private, public string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k.Bytes()), hex.EncodeToString(k.PublicKey().Bytes())
}

// site is a website with a certificate that only its own server holds a key of: what the borrow
// decoy points at.
type site struct {
	addr string
	der  []byte
	body string
	srv  *http.Server
}

// startSite runs a TLS 1.3 website, HTTP/2 and HTTP/1.1, whose certificate is for name.
func startSite(t *testing.T, name, body string) *site {
	t.Helper()
	cert, err := selfSignedCert(name)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &site{addr: ln.Addr().String(), der: cert.Certificate[0], body: body}
	s.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ErrorLog:  log.New(io.Discard, "", 0),
	}
	go s.srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { s.srv.Close() })
	return s
}

// sidecarNode is a test as the node: the end of the control pipe that the sidecar connects to.
type sidecarNode struct {
	t      *testing.T
	conn   net.Conn
	w      *Writer
	ready  Message
	events chan Message // the messages after ready, but stats
	stats  chan Message
	done   chan error // what Run returned
	cancel context.CancelFunc
	once   sync.Once
}

// startSidecar runs Run on a control pipe, sends start and waits for ready.
func startSidecar(t *testing.T, start Message, opts Options) *sidecarNode {
	t.Helper()
	opts.Logger = testLogger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	name := pipeName(t, "control")
	ln, err := listenPipe(name)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n := &sidecarNode{t: t, events: make(chan Message, 1024), stats: make(chan Message, 16), done: make(chan error, 1), cancel: cancel}
	t.Cleanup(n.stop)

	go func() {
		conn, err := dialPipe(ctx, name)
		if err != nil {
			n.done <- err
			return
		}
		n.done <- Run(ctx, conn, opts)
	}()
	timer := time.AfterFunc(testTimeout, func() { ln.Close() })
	conn, err := ln.Accept()
	timer.Stop()
	ln.Close()
	if err != nil {
		t.Fatalf("the sidecar did not connect to the control pipe: %v", err)
	}
	n.conn = conn
	n.w = NewWriter(conn)
	if err := n.w.Write(start); err != nil {
		t.Fatal(err)
	}

	r := NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(testTimeout))
	m, err := r.Read()
	if err != nil {
		t.Fatalf("waiting for ready: %v", err)
	}
	if m.Type != TypeReady {
		t.Fatalf("start was answered with %+v, not ready", m)
	}
	conn.SetReadDeadline(time.Time{})
	n.ready = m
	go n.readLoop(r)
	return n
}

// readLoop sorts the messages of the sidecar until the control pipe ends.
func (n *sidecarNode) readLoop(r *Reader) {
	for {
		m, err := r.Read()
		if err != nil {
			return
		}
		ch := n.events
		if m.Type == TypeStats {
			ch = n.stats
		}
		select {
		case ch <- m:
		default:
		}
	}
}

// stop closes the control pipe, as the node does when it stops, and waits for the sidecar to end.
func (n *sidecarNode) stop() {
	n.once.Do(func() {
		if n.conn != nil {
			n.conn.Close()
		}
		select {
		case err := <-n.done:
			if err != nil {
				n.t.Errorf("the sidecar ended with an error after the node closed the pipe: %v", err)
			}
		case <-time.After(testTimeout):
			n.t.Errorf("the sidecar did not end after the node closed the pipe")
		}
		n.cancel()
	})
}

// event waits for a message of the type typ.
func (n *sidecarNode) event(typ string) Message {
	n.t.Helper()
	timeout := time.After(testTimeout)
	for {
		select {
		case m := <-n.events:
			if m.Type == typ {
				return m
			}
		case <-timeout:
			n.t.Fatalf("no %s message from the sidecar", typ)
		}
	}
}

// counters asks the sidecar for its counters.
func (n *sidecarNode) counters() Message {
	n.t.Helper()
	if err := n.w.Write(Message{Type: TypeStats}); err != nil {
		n.t.Fatal(err)
	}
	select {
	case m := <-n.stats:
		return m
	case <-time.After(testTimeout):
		n.t.Fatal("no stats from the sidecar")
	}
	return Message{}
}

// countersUntil asks for the counters until counted accepts them or testTimeout has passed, and returns the last ones,
// which the caller checks: a count that never comes is a failure of that check. The sidecar writes the binding of a stream
// to the data pipe before it counts the stream, so a node that has read the binding can ask for the counters before the
// count is made.
func (n *sidecarNode) countersUntil(counted func(Message) bool) Message {
	n.t.Helper()
	deadline := time.Now().Add(testTimeout)
	m := n.counters()
	for !counted(m) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		m = n.counters()
	}
	return m
}

// A stream that the sidecar opened on the data pipe, as the node reads it.
type stream struct {
	conn    net.Conn
	binding string
}

// dataServer is the node's end of the data pipe of a server sidecar, which accepts its streams.
type dataServer struct {
	name    string
	streams chan stream
}

// listenData creates the data pipe, as the node does before it starts a server sidecar, and reads the
// first line of each stream that arrives.
func listenData(t *testing.T) *dataServer {
	t.Helper()
	d := &dataServer{name: pipeName(t, "data"), streams: make(chan stream, 64)}
	ln, err := listenPipe(d.name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				line, err := readLine(conn, 200)
				binding, ok := strings.CutPrefix(line, "bind ")
				if err != nil || !ok {
					conn.Close()
					return
				}
				d.streams <- stream{conn: conn, binding: binding}
			}()
		}
	}()
	return d
}

// next waits for the next stream.
func (d *dataServer) next(t *testing.T) stream {
	t.Helper()
	select {
	case s := <-d.streams:
		return s
	case <-time.After(testTimeout):
		t.Fatal("no stream reached the data pipe")
	}
	return stream{}
}

// dialLink asks a client sidecar for a stream to the link at address, as the node does.
func dialLink(pipe, address string) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	conn, err := dialPipe(ctx, pipe)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.WriteString(conn, "dial "+address+"\n"); err != nil {
		conn.Close()
		return nil, "", err
	}
	conn.SetReadDeadline(time.Now().Add(testTimeout))
	line, err := readLine(conn, 1024)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	binding, ok := strings.CutPrefix(line, "ok ")
	if !ok {
		conn.Close()
		return nil, "", errors.New(line)
	}
	return conn, binding, nil
}

// exchange writes size random bytes to a and reads them from b, and the other way round, and checks
// them against each other: what a stream carries comes out the same.
func exchange(t *testing.T, a, b net.Conn, size int) {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	want := sha256.Sum256(data)

	write := make(chan error, 1)
	go func() {
		_, err := a.Write(data)
		write <- err
	}()
	got := make([]byte, size)
	b.SetReadDeadline(time.Now().Add(testTimeout))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("reading %d bytes: %v", size, err)
	}
	b.SetReadDeadline(time.Time{})
	if err := <-write; err != nil {
		t.Fatalf("writing %d bytes: %v", size, err)
	}
	if sha256.Sum256(got) != want {
		t.Fatalf("the %d bytes that came out are not those that went in", size)
	}
}

// tap is a connection that records what is written to it and when. A client sidecar dials its server
// through one (the dialOuter option), so that a test sees what the network sees.
type tap struct {
	net.Conn
	mu     sync.Mutex
	writes []tapWrite
}

type tapWrite struct {
	at   time.Time
	data []byte
}

func (c *tap) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, tapWrite{at: time.Now(), data: append([]byte(nil), p...)})
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *tap) all() []tapWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]tapWrite(nil), c.writes...)
}

// tapDialer makes a dialOuter option whose connections are taps; taps gets each of them.
func tapDialer(taps chan<- *tap) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		t := &tap{Conn: c}
		taps <- t
		return t, nil
	}
}
