//go:build windows

package port

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// The test plays the front door of the node (SDN-29): it accepts a TCP connection itself,
// duplicates its socket into the process of the pipe's server with WSADuplicateSocketW, writes the
// handoff message and reads the answer, as FrontDoorSend of src/Core/FrontDoor.c does, and closes
// its own handle after. The controller's end is this process too.

var pipeSeq atomic.Int32

// testPipe is a pipe name of its own for each test.
func testPipe() string {
	return fmt.Sprintf(`\\.\pipe\ranz-port-test-%d-%d`, os.Getpid(), pipeSeq.Add(1))
}

// encodeHandoff is the handoff message of the WSAPROTOCOL_INFOW info, as the front door writes it.
func encodeHandoff(info *windows.WSAProtocolInfo) ([]byte, error) {
	var b bytes.Buffer
	err := binary.Write(&b, binary.LittleEndian, struct {
		Magic, Size uint32
		Info        windows.WSAProtocolInfo
	}{handoffMagic, HandoffSize, *info})
	if err == nil && b.Len() != HandoffSize {
		err = fmt.Errorf("the handoff message has %d bytes, not %d: WSAPROTOCOL_INFOW is not %d bytes", b.Len(), HandoffSize, protocolInfoSize)
	}
	return b.Bytes(), err
}

func handoffBytes(t *testing.T, info *windows.WSAProtocolInfo) []byte {
	t.Helper()
	b, err := encodeHandoff(info)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// send writes msg to the handoff pipe, as one front door, and returns the answer; msg nil writes
// nothing and closes the pipe at once.
func send(pipe string, msg func(pid uint32) ([]byte, error)) (byte, error) {
	return sendThen(pipe, msg, nil)
}

// sendThen is send, and before is called once the exchange is over and before the pipe closes: the
// controller starts to serve the socket when its end of the pipe ends, so what the front door does
// to its own handle in before cannot overlap the controller's use of the socket.
func sendThen(pipe string, msg func(pid uint32) ([]byte, error), before func()) (byte, error) {
	timeout := 5 * time.Second
	p, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return 0, err
	}
	defer func() {
		if before != nil {
			before()
		}
		p.Close()
	}()
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(p.(interface{ Fd() uintptr }).Fd()), &pid); err != nil {
		return 0, err
	}
	b, err := msg(pid)
	if err != nil {
		return 0, err
	}
	_ = p.SetDeadline(time.Now().Add(timeout))
	if _, err := p.Write(b); err != nil {
		return 0, err
	}
	answer := []byte{0xFF}
	if _, err := io.ReadFull(p, answer); err != nil {
		return 0, err
	}
	return answer[0], nil
}

// handOver hands the accepted socket raw to the pipe and closes the front door's own handle of it,
// whatever the answer. The handle closes before the pipe does: the controller waits for the end of
// the pipe before it serves the socket, so its TLS handshake never runs while the front door's
// handle of the same connection is closing in this process (the test's front door is the
// controller's process; the real one is another, and has no such overlap to look at).
func handOver(pipe string, raw windows.Handle) (byte, error) {
	var once sync.Once
	closeRaw := func() { once.Do(func() { windows.Closesocket(raw) }) }
	defer closeRaw()
	return sendThen(pipe, func(pid uint32) ([]byte, error) {
		var info windows.WSAProtocolInfo
		if err := windows.WSADuplicateSocket(raw, pid, &info); err != nil {
			return nil, err
		}
		return encodeHandoff(&info)
	}, closeRaw)
}

// writerFunc is an io.Writer of a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// testLog is the log of the Server of a test, which the test prints when it fails.
func testLog(t *testing.T) *slog.Logger {
	var mu sync.Mutex
	var b bytes.Buffer
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if t.Failed() {
			t.Logf("the log of the Server:\n%s", b.String())
		}
	})
	return slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return b.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

var procAccept = windows.NewLazySystemDLL("ws2_32.dll").NewProc("accept")

// frontDoor plays the front door on a test port: every connection that it accepts goes to the
// pipe, and the answers come on the channel. Its sockets are plain Winsock sockets, as the front
// door's are: a socket of package net belongs to the completion port of this process, and so would
// the controller's socket of the same connection.
func frontDoor(t *testing.T, pipe string) (string, chan byte) {
	t.Helper()
	ln, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.Closesocket(ln) })
	if err := windows.Bind(ln, &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := windows.Listen(ln, 16); err != nil {
		t.Fatal(err)
	}
	sa, err := windows.Getsockname(ln)
	if err != nil {
		t.Fatal(err)
	}
	answers := make(chan byte, 16)
	go func() {
		for {
			r, _, _ := procAccept.Call(uintptr(ln), 0, 0)
			if windows.Handle(r) == windows.InvalidHandle {
				return
			}
			answer, err := handOver(pipe, windows.Handle(r))
			if err != nil {
				t.Errorf("the handoff of a connection: %v", err)
			}
			answers <- answer
		}
	}()
	return fmt.Sprintf("127.0.0.1:%d", sa.(*windows.SockaddrInet4).Port), answers
}

func taken(t *testing.T, answers chan byte) {
	t.Helper()
	select {
	case a := <-answers:
		if a != handoffTaken {
			t.Errorf("the controller answered %d to a handoff of a TCP connection, not %d", a, handoffTaken)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no answer to a handoff")
	}
}

// dialed records the local address of every connection that a client dials. A client may dial more than the one connection
// that carries its request, and the front door hands over each of them.
type dialed struct {
	mu    sync.Mutex
	local []string
}

func (d *dialed) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err == nil {
		d.mu.Lock()
		d.local = append(d.local, c.LocalAddr().String())
		d.mu.Unlock()
	}
	return c, err
}

// all is the local addresses of the connections dialed so far.
func (d *dialed) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.local)
}

// A connection that the front door hands over is the controller's: its own TLS handshake with its
// own certificate, then the API over HTTP/1.1 and h2, or the control stream by its ALPN. No byte
// passes through the front door, whose handle is closed before the client speaks. The controller
// sees the client of each connection as the client dialed it: the API by the remote address of
// the request, the control stream by the one that Control gets.
func TestFrontDoorHandsOver(t *testing.T) {
	cert := certificate(t)
	type controlStream struct{ proto, remote string }
	controls := make(chan controlStream, 4)
	s := &Server{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}},
		Log: testLog(t),
		Control: func(tc *tls.Conn) {
			controls <- controlStream{tc.ConnectionState().NegotiatedProtocol, tc.RemoteAddr().String()}
			tc.Close()
		},
		HTTP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, r.Proto+" "+r.RemoteAddr)
		}),
	}
	defer s.Close()
	pipe := testPipe()
	fd, err := ListenFrontDoor(pipe, s)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if fd.Addr() != pipe {
		t.Errorf("the pipe is %q, not %q", fd.Addr(), pipe)
	}
	addr, answers := frontDoor(t, pipe)

	for _, c := range []struct {
		name  string
		http2 bool
		want  string
	}{{"HTTP/1.1", false, "HTTP/1.1"}, {"h2", true, "HTTP/2.0"}} {
		// The client may dial more than the one connection that carries its request, and the front door hands over each of
		// them, so the test does not depend on which one carried the request: it records every connection that the client
		// dials, waits for the handoff of each, and checks the remote address that the API saw against that set.
		var dials dialed
		tr := &http.Transport{
			DialContext:       dials.dial,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: c.http2,
		}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("%s through the front door: %v", c.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tr.CloseIdleConnections()
		// The front door answers once for each connection that the client dialed
		clientAddrs := dials.all()
		for range clientAddrs {
			taken(t, answers)
		}
		// The handler answers with the protocol and the remote address of the request, which is the client of the connection
		// that carried it: one of the connections that this leg dialed, and none of an older leg or of an older handoff
		proto, remote, _ := strings.Cut(string(body), " ")
		if proto != c.want {
			t.Errorf("%s through the front door: the API answered over %q, not %q", c.name, proto, c.want)
		}
		if !slices.Contains(clientAddrs, remote) {
			t.Errorf("%s through the front door: the API saw the client %q, and the client dialed from %v", c.name, remote, clientAddrs)
		}
		if !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, cert.Certificate[0]) {
			t.Errorf("%s through the front door: another certificate than the controller's", c.name)
		}
	}

	tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
	if err != nil {
		t.Fatalf("the control stream through the front door: %v", err)
	}
	defer tc.Close()
	taken(t, answers)
	select {
	case got := <-controls:
		if got.proto != control.ALPN {
			t.Errorf("Control got a connection of %q through the front door", got.proto)
		}
		if got.remote != tc.LocalAddr().String() {
			t.Errorf("Control got the connection of %s through the front door, and the client dialed from %s", got.remote, tc.LocalAddr())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Control got no connection through the front door")
	}

	// The pipe is the first instance of its name: a second controller cannot take it
	if again, err := ListenFrontDoor(pipe, s); err == nil {
		again.Close()
		t.Error("a second handoff pipe of the same name was made")
	}
}

// staleSocketEntries leaves the entries of n closed sockets in Winsock, as the standard library does with the socket that it
// makes in LoadConnectEx, in each process that dials: it makes the sockets and closes their handles with CloseHandle, not
// with closesocket. Winsock keeps the entry of a socket by the value of its handle until closesocket, and Windows gives the
// value of a closed handle to the next handle that it makes, so the next sockets that come by those values meet the entries
// of sockets that were never bound.
func staleSocketEntries(t *testing.T, n int) {
	t.Helper()
	sockets := make([]windows.Handle, n)
	for i := range sockets {
		s, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
		if err != nil {
			t.Fatal(err)
		}
		sockets[i] = s
	}
	for i := len(sockets) - 1; i >= 0; i-- {
		if err := windows.CloseHandle(sockets[i]); err != nil {
			t.Fatal(err)
		}
	}
}

// handoffsInARow hands over n connections through a front door, one after another, and checks the client of each. Before
// each one it leaves stale entries of closed sockets in Winsock (staleSocketEntries), when stale is more than 0.
//
// Each connection that the front door hands over has its own client as its remote address, whatever handoffs came before
// it: the API and the limits for a source go by that address. Winsock keeps state by the value of a socket handle, the
// remote address among it, until closesocket drops it, and the controller once closed the handle of a handoff with
// CloseHandle, so the next socket that came by the same value reported the client of an older connection (#534). One
// connection after another, nearly every handoff that follows another one has such a value. And a handoff is not refused
// for the entry of a socket that the standard library closed with CloseHandle.
func handoffsInARow(t *testing.T, n, stale int) {
	t.Helper()
	remotes := make(chan string, 1)
	s := &Server{
		TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}},
		Log: testLog(t),
		Control: func(tc *tls.Conn) {
			remotes <- tc.RemoteAddr().String()
			tc.Close()
		},
	}
	defer s.Close()
	pipe := testPipe()
	fd, err := ListenFrontDoor(pipe, s)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	addr, answers := frontDoor(t, pipe)

	for i := range n {
		if stale > 0 {
			staleSocketEntries(t, stale)
		}
		tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
		if err != nil {
			t.Fatalf("connection %d through the front door: %v", i, err)
		}
		taken(t, answers)
		select {
		case remote := <-remotes:
			if remote != tc.LocalAddr().String() {
				t.Fatalf("connection %d through the front door: Control got the connection of %s, and the client dialed from %s", i, remote, tc.LocalAddr())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("connection %d: Control got no connection through the front door", i)
		}
		tc.Close()
	}
}

// Each connection that the front door hands over has its own client as its remote address, whatever handoffs came before it.
func TestFrontDoorHandoffsKeepTheirClient(t *testing.T) {
	handoffsInARow(t, 100, 0)
}

// The standard library closes the socket that it makes in LoadConnectEx with CloseHandle, so Winsock keeps an entry of a
// socket that was never bound under the value of that handle. The socket that FileConn makes of its own for a handoff fails
// when it comes by such a value, and the handoff was refused, in one new process of a hundred: the client saw the connection
// reset (#534). Here such entries are on the free values before each connection.
func TestFrontDoorHandoffsSurviveStaleSocketEntries(t *testing.T) {
	handoffsInARow(t, 30, 8)
}

// plainConnection makes one TCP connection in this process of plain Winsock sockets, as a front door and its client hold
// them, and returns the front door's socket and the client's.
func plainConnection(t *testing.T) (server, client windows.Handle) {
	t.Helper()
	loopback := [4]byte{127, 0, 0, 1}
	ln, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.Closesocket(ln)
	if err := windows.Bind(ln, &windows.SockaddrInet4{Addr: loopback}); err != nil {
		t.Fatal(err)
	}
	if err := windows.Listen(ln, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := windows.Getsockname(ln)
	if err != nil {
		t.Fatal(err)
	}
	client, err = windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.Connect(client, &windows.SockaddrInet4{Addr: loopback, Port: sa.(*windows.SockaddrInet4).Port}); err != nil {
		t.Fatal(err)
	}
	r, _, _ := procAccept.Call(uintptr(ln), 0, 0)
	if windows.Handle(r) == windows.InvalidHandle {
		t.Fatal("accept failed")
	}
	return windows.Handle(r), client
}

// connAddrs is the local and the remote address of the socket h, as package net writes them.
func connAddrs(t *testing.T, h windows.Handle) (local, remote string) {
	t.Helper()
	format := func(sa windows.Sockaddr) string {
		a := sa.(*windows.SockaddrInet4)
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	}
	l, err := windows.Getsockname(h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := windows.Getpeername(h)
	if err != nil {
		t.Fatal(err)
	}
	return format(l), format(r)
}

// rebuild makes the socket of the controller of the handoff of a socket, with stale entries on the free values of the
// handles of this process between the duplicate of the front door and rebuild, which the socket that FileConn makes meets.
func TestRebuildSurvivesStaleSocketEntries(t *testing.T) {
	for i := range 30 {
		server, client := plainConnection(t)
		local, remote := connAddrs(t, server)
		var info windows.WSAProtocolInfo
		if err := windows.WSADuplicateSocket(server, uint32(os.Getpid()), &info); err != nil {
			t.Fatal(err)
		}
		staleSocketEntries(t, 4)
		raw, err := DecodeHandoff(handoffBytes(t, &info))
		if err != nil {
			t.Fatal(err)
		}
		c, err := rebuild(raw)
		if err != nil {
			t.Fatalf("handoff %d after entries of closed sockets: %v", i, err)
		}
		if c.LocalAddr().String() != local || c.RemoteAddr().String() != remote {
			t.Errorf("handoff %d: the connection of the controller is %s to %s, and the socket of the front door is %s to %s", i, c.LocalAddr(), c.RemoteAddr(), local, remote)
		}
		c.Close()
		windows.Closesocket(server)
		windows.Closesocket(client)
	}
}

// A handoff message that is malformed, or whose socket cannot be made, gets handoffNotTaken, and the
// controller closes its end of the pipe after it; so does a front door that sends nothing.
func TestFrontDoorRefuses(t *testing.T) {
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}}
	defer s.Close()
	pipe := testPipe()
	fd, err := ListenFrontDoor(pipe, s)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()

	tcp := windows.WSAProtocolInfo{AddressFamily: afInet, SocketType: sockStream, Protocol: ipprotoTCP, CatalogEntryId: 0xFFFFFFFF}
	udp := tcp
	udp.SocketType, udp.Protocol = 2, 17
	good := handoffBytes(t, &tcp)
	for _, c := range []struct {
		name string
		msg  []byte
	}{
		{"four bytes", []byte("RFD1")},
		{"one byte short", good[:HandoffSize-1]},
		{"one byte long", append(append([]byte(nil), good...), 0)},
		{"much longer", bytes.Repeat(good, 3)},
		{"another magic", append([]byte("XFD1"), good[4:]...)},
		{"a UDP socket", handoffBytes(t, &udp)},
		{"a socket of no provider", good},
	} {
		answer, err := send(pipe, func(uint32) ([]byte, error) { return c.msg, nil })
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if answer != handoffNotTaken {
			t.Errorf("%s: the controller answered %d, not %d", c.name, answer, handoffNotTaken)
		}
	}

	// A front door that connects and closes at once, then one that sends nothing: neither holds the
	// pipe for the next
	timeout := 5 * time.Second
	p, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	silent, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	_ = silent.SetReadDeadline(time.Now().Add(2 * handoffTimeout))
	answer := []byte{0xFF}
	if _, err := io.ReadFull(silent, answer); err != nil || answer[0] != handoffNotTaken {
		t.Errorf("a front door that sends nothing got %d (%v), not %d once the handoff timed out", answer[0], err, handoffNotTaken)
	}
	if a, err := send(pipe, func(uint32) ([]byte, error) { return []byte("RFD1"), nil }); err != nil || a != handoffNotTaken {
		t.Errorf("the next front door got %d (%v)", a, err)
	}
}

// A controller that closes its pipe leaves no goroutine of it behind, also with a front door that
// is in the middle of a handoff, and a front door that comes after finds no pipe: it closes the
// connection itself.
func TestFrontDoorCloseLeavesNothing(t *testing.T) {
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}}
	defer s.Close()
	// go-winio starts its completion goroutine with its first pipe, for good: a pipe before the count
	// starts it
	firstPipe := testPipe()
	first, err := ListenFrontDoor(firstPipe, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := send(firstPipe, func(uint32) ([]byte, error) { return []byte("RFD1"), nil }); err != nil {
		t.Fatal(err)
	}
	first.Close()
	before := runtime.NumGoroutine()

	pipe := testPipe()
	fd, err := ListenFrontDoor(pipe, s)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := send(pipe, func(uint32) ([]byte, error) { return []byte("RFD1"), nil }); err != nil || a != handoffNotTaken {
		t.Errorf("a malformed handoff got %d (%v)", a, err)
	}
	timeout := 5 * time.Second
	waiting, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Close()
	// The handoff of the waiting front door has started once its pipe instance is taken
	time.Sleep(200 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- fd.Close() }()
	select {
	case <-closed:
	case <-time.After(handoffTimeout):
		t.Fatal("Close did not end a handoff in its middle")
	}

	end := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(end) {
			buf := make([]byte, 1<<16)
			t.Fatalf("%d goroutines after Close, %d before:\n%s", runtime.NumGoroutine(), before, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err := send(pipe, func(uint32) ([]byte, error) { return []byte("RFD1"), nil }); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a front door found the pipe of a controller that closed it: %v", err)
	}
}
