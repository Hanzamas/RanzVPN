//go:build windows

package port

// THROWAWAY diagnostics of ticket #534 (TestFrontDoorHandsOver): the scenario of that test, run many times in four
// variants of the front door, with the trace of every step. This file is removed again before the pull request is done.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// diagTrace is the events of one run of the scenario, in the order that they came.
type diagTrace struct {
	mu    sync.Mutex
	start time.Time
	lines []string
	echo  func(string)
}

func newDiagTrace() *diagTrace { return &diagTrace{start: time.Now()} }

func (d *diagTrace) add(format string, args ...any) {
	line := fmt.Sprintf("%8.2fms %s", float64(time.Since(d.start).Microseconds())/1000, fmt.Sprintf(format, args...))
	d.mu.Lock()
	d.lines = append(d.lines, line)
	echo := d.echo
	d.mu.Unlock()
	if echo != nil {
		echo(line)
	}
}

func (d *diagTrace) dump() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.lines, "\n")
}

func diagAddr(sa windows.Sockaddr, err error) string {
	if err != nil {
		return "err(" + err.Error() + ")"
	}
	if a, ok := sa.(*windows.SockaddrInet4); ok {
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	}
	return fmt.Sprintf("%T", sa)
}

// diagHandleOf is the Winsock handle behind a connection of package net.
func diagHandleOf(c net.Conn) uintptr {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0
	}
	var h uintptr
	_ = rc.Control(func(fd uintptr) { h = fd })
	return h
}

// diagWriter takes the lines of the log of the Server into the trace.
type diagWriter struct{ d *diagTrace }

func (w diagWriter) Write(p []byte) (int, error) {
	w.d.add("slog: %s", strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// diagConn is the connection of a handoff, which says when the controller closes it.
type diagConn struct {
	net.Conn
	d  *diagTrace
	id string
}

func (c *diagConn) Close() error {
	c.d.add("controller: closes its socket %s", c.id)
	return c.Conn.Close()
}

// diagHandOver hands the accepted socket over as handOver does. order says when the front door closes its own handle of
// the connection: first, before its end of the pipe (what TestFrontDoorHandsOver does); after, once the pipe is closed
// (what FrontDoorSend and FrontDoorRouteCallback of the node do); late, never here: the caller closes it.
func diagHandOver(pipe string, raw windows.Handle, order string, d *diagTrace) (byte, error) {
	var once sync.Once
	closeRaw := func() {
		once.Do(func() {
			err := windows.Closesocket(raw)
			d.add("front door: closesocket raw=%#x err=%v", uintptr(raw), err)
		})
	}
	msg := func(pid uint32) ([]byte, error) {
		var info windows.WSAProtocolInfo
		if err := windows.WSADuplicateSocket(raw, pid, &info); err != nil {
			return nil, err
		}
		d.add("front door: duplicated raw=%#x for the process %d", uintptr(raw), pid)
		return encodeHandoff(&info)
	}
	switch order {
	case "first":
		defer closeRaw()
		return sendThen(pipe, msg, closeRaw)
	case "after":
		defer closeRaw()
		answer, err := sendThen(pipe, msg, nil)
		d.add("front door: the pipe is closed, answer %d", answer)
		return answer, err
	default:
		return sendThen(pipe, msg, nil)
	}
}

// diagListen makes the listening socket of a front door on a test port.
func diagListen(t *testing.T) (windows.Handle, string) {
	t.Helper()
	ln, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
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
	return ln, fmt.Sprintf("127.0.0.1:%d", sa.(*windows.SockaddrInet4).Port)
}

// diagDoor is a front door of the diagnostics: its address, the answers of the controller and the end of it.
type diagDoor struct {
	addr    string
	answers chan byte
	stop    func()
}

// diagDoorInProcess is the front door of TestFrontDoorHandsOver: a goroutine of this process.
func diagDoorInProcess(t *testing.T, pipe, order string, d *diagTrace, onAccept func(string)) diagDoor {
	t.Helper()
	ln, addr := diagListen(t)
	answers := make(chan byte, 16)
	var kept []windows.Handle
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			r, _, _ := procAccept.Call(uintptr(ln), 0, 0)
			if windows.Handle(r) == windows.InvalidHandle {
				return
			}
			raw := windows.Handle(r)
			peer := diagAddr(windows.Getpeername(raw))
			d.add("front door: accepted raw=%#x peer=%s", uintptr(raw), peer)
			onAccept(peer)
			answer, err := diagHandOver(pipe, raw, order, d)
			if order == "late" {
				kept = append(kept, raw)
			}
			d.add("front door: handoff over, answer %d err=%v", answer, err)
			answers <- answer
		}
	}()
	return diagDoor{addr, answers, func() {
		windows.Closesocket(ln)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			d.add("front door: accept did not return after closesocket")
		}
		for _, raw := range kept {
			windows.Closesocket(raw)
		}
	}}
}

const diagHelperEnv = "RANZ_DIAG_534_FRONT_DOOR"

// TestDiagFrontDoorProcess is the front door as a process of its own, as the node is: the diagnostics start this binary
// with diagHelperEnv set. Without it the test does nothing.
func TestDiagFrontDoorProcess(t *testing.T) {
	cfg := os.Getenv(diagHelperEnv)
	if cfg == "" {
		t.Skip("the front door process of TestDiag534")
	}
	pipe, order, _ := strings.Cut(cfg, "|")
	d := newDiagTrace()
	d.echo = func(line string) { fmt.Println("TRACE " + line) }
	ln, addr := diagListen(t)
	fmt.Println("LISTEN " + addr)
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()
	for {
		r, _, _ := procAccept.Call(uintptr(ln), 0, 0)
		if windows.Handle(r) == windows.InvalidHandle {
			os.Exit(1)
		}
		raw := windows.Handle(r)
		fmt.Println("ACCEPT " + diagAddr(windows.Getpeername(raw)))
		answer, err := diagHandOver(pipe, raw, order, d)
		fmt.Printf("ANSWER %d %q\n", answer, fmt.Sprint(err))
	}
}

// diagDoorProcess starts the front door as a process of its own.
func diagDoorProcess(t *testing.T, pipe, order string, d *diagTrace, onAccept func(string)) diagDoor {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDiagFrontDoorProcess$")
	cmd.Env = append(os.Environ(), diagHelperEnv+"="+pipe+"|"+order)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	answers := make(chan byte, 16)
	listening := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "LISTEN "):
				listening <- strings.TrimPrefix(line, "LISTEN ")
			case strings.HasPrefix(line, "ACCEPT "):
				onAccept(strings.TrimPrefix(line, "ACCEPT "))
			case strings.HasPrefix(line, "ANSWER "):
				n, _ := strconv.Atoi(strings.Fields(line)[1])
				answers <- byte(n)
			case strings.HasPrefix(line, "TRACE "):
				d.add("helper %s", strings.TrimPrefix(line, "TRACE "))
			}
		}
	}()
	var addr string
	select {
	case addr = <-listening:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the front door process did not listen")
	}
	return diagDoor{addr, answers, func() {
		stdin.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = cmd.Wait()
	}}
}

// diagTaken waits for the answers of n handoffs.
func diagTaken(answers chan byte, n int, flag func(kind, format string, args ...any)) {
	for i := 0; i < n; i++ {
		select {
		case a := <-answers:
			if a != handoffTaken {
				flag("answer", "the controller answered %d to a handoff, not %d", a, handoffTaken)
			}
		case <-time.After(10 * time.Second):
			flag("noanswer", "no answer to a handoff")
			return
		}
	}
}

// diagVariant is a way to play the front door.
type diagVariant struct {
	name    string
	order   string // first, after or late: when the front door closes its handle of a connection
	process bool   // the front door is a process of its own
}

// diagOutcome is what one run of the scenario found: the kinds of its anomalies, and its trace.
type diagOutcome struct {
	anomalies []string
	trace     string
}

// diagScenario is TestFrontDoorHandsOver once, with the front door of the variant and the trace of each step. It does not
// stop at what the test fails on: it flags it, and goes on.
func diagScenario(t *testing.T, cert tls.Certificate, v diagVariant) diagOutcome {
	t.Helper()
	d := newDiagTrace()
	var anomalies []string
	flag := func(kind, format string, args ...any) {
		anomalies = append(anomalies, kind)
		d.add("ANOMALY %s: %s", kind, fmt.Sprintf(format, args...))
	}

	var mu sync.Mutex
	var fdPeers, ctlPeers []string
	controls := make(chan string, 4)
	s := &Server{
		TLS: &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			remote := fmt.Sprint(hello.Conn.RemoteAddr())
			mu.Lock()
			ctlPeers = append(ctlPeers, remote)
			mu.Unlock()
			d.add("controller: ClientHello from %s on %s, ALPN %v", remote, hello.Conn.LocalAddr(), hello.SupportedProtos)
			return &cert, nil
		}},
		Control: func(tc *tls.Conn) {
			d.add("controller: Control has a connection of %s, ALPN %q", tc.RemoteAddr(), tc.ConnectionState().NegotiatedProtocol)
			controls <- tc.ConnectionState().NegotiatedProtocol
			tc.Close()
		},
		HTTP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d.add("controller: the API handler has %s from %s", r.Proto, r.RemoteAddr)
			_, _ = io.WriteString(w, r.Proto+" "+r.RemoteAddr)
		}),
		Log: slog.New(slog.NewTextHandler(diagWriter{d}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	diagRebuild = func(h windows.Handle, c net.Conn, err error) net.Conn {
		switch {
		case c == nil && err == nil:
			d.add("controller: rebuild, WSASocket gave h=%#x peer=%s local=%s", uintptr(h), diagAddr(windows.Getpeername(h)), diagAddr(windows.Getsockname(h)))
			return nil
		case err != nil:
			d.add("controller: rebuild, FileConn of h=%#x failed: %v", uintptr(h), err)
			return nil
		}
		id := fmt.Sprintf("h=%#x s=%#x remote=%v local=%v", uintptr(h), diagHandleOf(c), c.RemoteAddr(), c.LocalAddr())
		d.add("controller: rebuild, FileConn made %s", id)
		return &diagConn{Conn: c, d: d, id: id}
	}
	defer func() { diagRebuild = nil }()

	pipe := testPipe()
	fd, err := ListenFrontDoor(pipe, s)
	if err != nil {
		t.Fatal(err)
	}
	onAccept := func(peer string) {
		mu.Lock()
		fdPeers = append(fdPeers, peer)
		mu.Unlock()
	}
	var door diagDoor
	if v.process {
		door = diagDoorProcess(t, pipe, v.order, d, onAccept)
	} else {
		door = diagDoorInProcess(t, pipe, v.order, d, onAccept)
	}

	for _, leg := range []struct {
		name  string
		http2 bool
		want  string
	}{{"HTTP/1.1", false, "HTTP/1.1"}, {"h2", true, "HTTP/2.0"}} {
		var cmu sync.Mutex
		var dials, gots []string
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			local := info.Conn.LocalAddr().String()
			cmu.Lock()
			gots = append(gots, local)
			cmu.Unlock()
			d.add("client %s: GotConn local=%s reused=%v", leg.name, local, info.Reused)
		}}
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: leg.http2,
			DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, a)
				if err == nil {
					cmu.Lock()
					dials = append(dials, conn.LocalAddr().String())
					cmu.Unlock()
					d.add("client %s: dialed local=%s", leg.name, conn.LocalAddr())
				}
				return conn, err
			},
		}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "https://"+door.addr+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		resp, err := client.Do(req)
		if err != nil {
			flag("request", "%s: the request failed: %v", leg.name, err)
		} else {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			d.add("client %s: the API answered %q", leg.name, body)
		}
		tr.CloseIdleConnections()
		cmu.Lock()
		dialed := len(dials)
		carrier := ""
		if len(gots) > 0 {
			carrier = gots[len(gots)-1]
		}
		cmu.Unlock()
		if dialed != 1 {
			flag("dials", "%s: the client dialed %d connections", leg.name, dialed)
		}
		if err == nil {
			if want := leg.want + " " + carrier; string(body) != want {
				flag("mismatch", "%s: the API answered %q, not %q", leg.name, body, want)
			}
		}
		diagTaken(door.answers, dialed, flag)
	}

	conn, err := net.Dial("tcp", door.addr)
	if err != nil {
		flag("control", "the control stream: dial: %v", err)
	} else {
		d.add("client control: dialed local=%s", conn.LocalAddr())
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}, ServerName: "127.0.0.1"})
		if err := tc.Handshake(); err != nil {
			flag("control", "the control stream: the TLS handshake: %v", err)
			tc.Close()
		} else {
			defer tc.Close()
			select {
			case p := <-controls:
				if p != control.ALPN {
					flag("control", "Control got a connection of %q", p)
				}
			case <-time.After(10 * time.Second):
				flag("control", "Control got no connection")
			}
		}
		diagTaken(door.answers, 1, flag)
	}

	mu.Lock()
	if len(fdPeers) != len(ctlPeers) {
		flag("peers", "the front door accepted %d connections %v, the controller got %d ClientHellos %v", len(fdPeers), fdPeers, len(ctlPeers), ctlPeers)
	}
	for i := 0; i < len(fdPeers) && i < len(ctlPeers); i++ {
		if fdPeers[i] != ctlPeers[i] {
			flag("peers", "connection %d: the front door accepted %s, the controller says its client is %s", i, fdPeers[i], ctlPeers[i])
		}
	}
	mu.Unlock()
	if n := len(door.answers); n != 0 {
		flag("extra", "%d answers of handoffs that nobody waited for", n)
	}

	door.stop()
	fd.Close()
	s.Close()
	return diagOutcome{anomalies: anomalies, trace: d.dump()}
}

// TestDiag534 runs the scenario in each variant of the front door for a while, and prints what it found.
func TestDiag534(t *testing.T) {
	if os.Getenv("RANZ_DIAG_534") == "" {
		t.Skip("the throwaway diagnostics of #534")
	}
	cert := certificate(t)
	variants := []struct {
		diagVariant
		budget time.Duration
	}{
		{diagVariant{"in-process, handle closed before the pipe (TestFrontDoorHandsOver now)", "first", false}, 60 * time.Second},
		{diagVariant{"in-process, handle closed after the pipe (the order of the node)", "after", false}, 60 * time.Second},
		{diagVariant{"in-process, handle closed when the run ends", "late", false}, 60 * time.Second},
		{diagVariant{"front door as a process, handle closed after the pipe (as the node)", "after", true}, 150 * time.Second},
	}
	failed := false
	for _, v := range variants {
		end := time.Now().Add(v.budget)
		runs, bad, shown := 0, 0, 0
		kinds := map[string]int{}
		for runs < 3000 && time.Now().Before(end) {
			runs++
			out := diagScenario(t, cert, v.diagVariant)
			if len(out.anomalies) == 0 {
				continue
			}
			bad++
			for _, k := range out.anomalies {
				kinds[k]++
			}
			if shown < 3 {
				shown++
				fmt.Printf("---- %s: run %d\n%s\n", v.name, runs, out.trace)
			}
		}
		fmt.Printf("==== %s: %d runs, %d with an anomaly, kinds %v\n", v.name, runs, bad, kinds)
		if bad > 0 {
			failed = true
		}
	}
	if failed {
		t.Fail()
	}
}
