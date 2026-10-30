//go:build windows

package port

// THROWAWAY diagnostics of ticket #534 (TestFrontDoorHandsOver), removed again before the pull request is done: the stale
// entries that Winsock keeps by the value of a socket handle, tried one by one. The standard library closes the socket of
// LoadConnectEx with CloseHandle, and the question is what a later socket that comes by the same value gets from that.

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

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

// diagStale makes what the standard library leaves behind in LoadConnectEx: a TCP socket that is closed with CloseHandle, so
// that Winsock keeps its entry for the value of the handle. It returns the value.
func diagStale() windows.Handle {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		panic(err)
	}
	if err := windows.CloseHandle(s); err != nil {
		panic(err)
	}
	return s
}

func diagEvent() (windows.Handle, error) { return windows.CreateEvent(nil, 1, 0, nil) }

func diagSocket() (windows.Handle, error) {
	return windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
}

func diagClose(h windows.Handle) { _ = windows.CloseHandle(h) }

func diagCloseSocket(h windows.Handle) { _ = windows.Closesocket(h) }

// diagDup is what the controller does with the socket of a handoff before FileConn: the WSADuplicateSocket of the front door
// for this process, and WSASocket of the info.
func diagDup(src windows.Handle) (windows.Handle, error) {
	var info windows.WSAProtocolInfo
	if err := windows.WSADuplicateSocket(src, uint32(os.Getpid()), &info); err != nil {
		return 0, err
	}
	return windows.WSASocket(fromProtocolInfo, fromProtocolInfo, fromProtocolInfo, &info, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
}

// diagLand calls alloc until it returns the handle want, and holds the handles that it returned on the way, so that the next
// call gets another slot of the handle table; it frees those at the end. It returns want, or 0 when want did not come by, and
// the number of calls.
func diagLand(want windows.Handle, alloc func() (windows.Handle, error), free func(windows.Handle)) (windows.Handle, int) {
	var hold []windows.Handle
	defer func() {
		for _, h := range hold {
			free(h)
		}
	}()
	for i := 1; i <= 512; i++ {
		h, err := alloc()
		if err != nil {
			fmt.Printf("DIAG   alloc: %v\n", err)
			return 0, i
		}
		if h == want {
			return h, i
		}
		hold = append(hold, h)
	}
	return 0, 512
}

// diagProbe says what Winsock answers for a handle.
func diagProbe(label string, h windows.Handle) {
	typ, terr := windows.GetsockoptInt(h, windows.SOL_SOCKET, diagSoType)
	fmt.Printf("DIAG   %s: handle %#x: SO_TYPE %d (%v), getsockname %s, getpeername %s\n", label, uintptr(h), typ, terr, diagAddr(windows.Getsockname(h)), diagAddr(windows.Getpeername(h)))
}

// diagPair makes a connection in this process with plain Winsock calls: the listener, the accepted socket (the front door's
// handle) and the client.
func diagPair(t *testing.T) (server, client, ln windows.Handle) {
	t.Helper()
	loop := [4]byte{127, 0, 0, 1}
	ln, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.Bind(ln, &windows.SockaddrInet4{Addr: loop}); err != nil {
		t.Fatal(err)
	}
	if err := windows.Listen(ln, 16); err != nil {
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
	if err := windows.Connect(client, &windows.SockaddrInet4{Addr: loop, Port: sa.(*windows.SockaddrInet4).Port}); err != nil {
		t.Fatal(err)
	}
	r, _, _ := procAccept.Call(uintptr(ln), 0, 0)
	if windows.Handle(r) == windows.InvalidHandle {
		t.Fatal("accept failed")
	}
	return windows.Handle(r), client, ln
}

// TestDiag534Winsock makes a stale entry of a socket that is closed with CloseHandle, as LoadConnectEx leaves one, and tries
// what comes by its handle value: an event, a socket of a handoff, a socket that is made with socket(), and the socket that
// FileConn makes of its own. Then the ways to get rid of the entry.
func TestDiag534Winsock(t *testing.T) {
	server, client, ln := diagPair(t)
	defer windows.Closesocket(ln)
	defer windows.Closesocket(client)
	defer windows.Closesocket(server)
	fmt.Printf("DIAG setup: the accepted socket %#x, the client %#x with the address %s, the server's view of its peer %s\n",
		uintptr(server), uintptr(client), diagAddr(windows.Getsockname(client)), diagAddr(windows.Getpeername(server)))
	dup := func() (windows.Handle, error) { return diagDup(server) }

	// T0: an event on the value of a stale entry: does Winsock answer for it, and does closesocket drop the entry?
	v0 := diagStale()
	e, tries := diagLand(v0, diagEvent, diagClose)
	fmt.Printf("DIAG T0: the stale value is %#x; an event landed on it: %v (%d tries)\n", uintptr(v0), e == v0, tries)
	if e == v0 {
		_, serr := windows.GetsockoptInt(e, windows.SOL_SOCKET, diagSoType)
		fmt.Printf("DIAG T0: getsockopt SO_TYPE of the event: %v\n", serr)
		fmt.Printf("DIAG T0: closesocket of the event: %v\n", windows.Closesocket(e))
		e2, tries2 := diagLand(v0, diagEvent, diagClose)
		fmt.Printf("DIAG T0: a second event landed on the value: %v (%d tries)\n", e2 == v0, tries2)
		if e2 == v0 {
			_, serr := windows.GetsockoptInt(e2, windows.SOL_SOCKET, diagSoType)
			fmt.Printf("DIAG T0: getsockopt SO_TYPE of the second event: %v\n", serr)
			diagClose(e2)
		}
	}

	// T1: a socket of a handoff on the value of a stale entry
	v1 := diagStale()
	h1, tries := diagLand(v1, dup, diagCloseSocket)
	fmt.Printf("DIAG T1: the stale value is %#x; a socket of a handoff landed on it: %v (%d tries)\n", uintptr(v1), h1 == v1, tries)
	if h1 == v1 {
		diagProbe("T1 the socket of the handoff", h1)
		f := os.NewFile(uintptr(h1), "diag")
		c, err := net.FileConn(f)
		fmt.Printf("DIAG T1: FileConn: %v\n", err)
		if c != nil {
			fmt.Printf("DIAG T1: FileConn made the handle %#x, remote %v\n", diagHandleOf(c), c.RemoteAddr())
			c.Close()
		}
		closeSocketFile(f, h1)
		h1b, tries := diagLand(v1, dup, diagCloseSocket)
		fmt.Printf("DIAG T1: after the closesocket of it, a socket of a handoff landed on the value again: %v (%d tries)\n", h1b == v1, tries)
		if h1b == v1 {
			diagProbe("T1 again", h1b)
			diagCloseSocket(h1b)
		}
	}

	// T2: a socket that is made with socket() on the value of a stale entry, and closed with closesocket: is the entry gone?
	v2 := diagStale()
	s2, tries := diagLand(v2, diagSocket, diagCloseSocket)
	fmt.Printf("DIAG T2: the stale value is %#x; a socket() landed on it: %v (%d tries)\n", uintptr(v2), s2 == v2, tries)
	if s2 == v2 {
		fmt.Printf("DIAG T2: bind: %v\n", windows.Bind(s2, &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}))
		diagProbe("T2 the socket() after bind", s2)
		diagCloseSocket(s2)
		h2, tries := diagLand(v2, dup, diagCloseSocket)
		fmt.Printf("DIAG T2: after its closesocket, a socket of a handoff landed on the value: %v (%d tries)\n", h2 == v2, tries)
		if h2 == v2 {
			diagProbe("T2 the socket of the handoff", h2)
			diagCloseSocket(h2)
		}
	}

	// T3: a socket of a handoff on the value of a stale entry, copied to another value before anything else is done to it, and
	// the old value closed with closesocket
	v3 := diagStale()
	h3, tries := diagLand(v3, dup, diagCloseSocket)
	fmt.Printf("DIAG T3: the stale value is %#x; a socket of a handoff landed on it: %v (%d tries)\n", uintptr(v3), h3 == v3, tries)
	if h3 == v3 {
		var cp windows.Handle
		self := windows.CurrentProcess()
		derr := windows.DuplicateHandle(self, h3, self, &cp, 0, false, windows.DUPLICATE_SAME_ACCESS)
		fmt.Printf("DIAG T3: DuplicateHandle: the copy is %#x, %v\n", uintptr(cp), derr)
		fmt.Printf("DIAG T3: closesocket of the old value: %v\n", windows.Closesocket(h3))
		if derr == nil {
			diagProbe("T3 the copy", cp)
			f := os.NewFile(uintptr(cp), "diag")
			c, err := net.FileConn(f)
			fmt.Printf("DIAG T3: FileConn of the copy: %v\n", err)
			if c != nil {
				fmt.Printf("DIAG T3: FileConn made the handle %#x, remote %v, local %v\n", diagHandleOf(c), c.RemoteAddr(), c.LocalAddr())
				c.Close()
			}
			closeSocketFile(f, cp)
		}
		h3b, tries := diagLand(v3, dup, diagCloseSocket)
		fmt.Printf("DIAG T3: after that, a socket of a handoff landed on the value again: %v (%d tries)\n", h3b == v3, tries)
		if h3b == v3 {
			diagProbe("T3 again", h3b)
			diagCloseSocket(h3b)
		}
	}

	// T4: the socket that FileConn makes of its own gets the value of a stale entry (the slot of a closed handle is the next
	// to be given), and FileConn is tried a second time
	d4, err := diagDup(server)
	if err != nil {
		t.Fatal(err)
	}
	v4 := diagStale()
	f4 := os.NewFile(uintptr(d4), "diag")
	c1, err1 := net.FileConn(f4)
	fmt.Printf("DIAG T4: the socket of the handoff is %#x, the stale value %#x; FileConn the first time: %v\n", uintptr(d4), uintptr(v4), err1)
	if c1 != nil {
		fmt.Printf("DIAG T4: FileConn made the handle %#x, remote %v\n", diagHandleOf(c1), c1.RemoteAddr())
		c1.Close()
	}
	c2, err2 := net.FileConn(f4)
	fmt.Printf("DIAG T4: FileConn the second time: %v\n", err2)
	if c2 != nil {
		fmt.Printf("DIAG T4: FileConn made the handle %#x, remote %v\n", diagHandleOf(c2), c2.RemoteAddr())
		c2.Close()
	}
	closeSocketFile(f4, d4)
}

// TestDiag534Dummy is the first dial of a process: the standard library loads ConnectEx with a socket that it closes with
// CloseHandle. Which entries does Winsock hold before the dial, and which after it?
func TestDiag534Dummy(t *testing.T) {
	before := diagScan()
	server, client, ln := diagPair(t)
	afterPair := diagScan()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", func() int {
		sa, _ := windows.Getsockname(ln)
		return sa.(*windows.SockaddrInet4).Port
	}()))
	if err != nil {
		t.Fatal(err)
	}
	after := diagScan()
	fmt.Printf("DIAG dummy: stale entries before %#x, after the plain sockets %#x, after the first dial of the standard library %#x\n", before, afterPair, after)
	c.Close()
	windows.Closesocket(server)
	windows.Closesocket(client)
	windows.Closesocket(ln)
}
