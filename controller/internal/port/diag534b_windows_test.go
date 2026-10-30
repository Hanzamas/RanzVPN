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

// diagPoison leaves the entries of n sockets that were closed with CloseHandle, as LoadConnectEx leaves one: the sockets take
// the n free slots at the top of the handle table, and give them back to the next handles that are made.
func diagPoison(n int) []windows.Handle {
	hs := make([]windows.Handle, n)
	for i := range hs {
		s, err := diagSocket()
		if err != nil {
			panic(err)
		}
		hs[i] = s
	}
	for i := len(hs) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(hs[i])
	}
	return hs
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

// TestDiag534Winsock tries what comes by the handle value of a stale entry that an event, and what drops the entry.
func TestDiag534Winsock(t *testing.T) {
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
}

// TestDiag534Rebuild hands a socket over to rebuild with entries of closed sockets on the top of the free slots of the handle
// table, before the duplicate of the front door is made (the socket of the handoff comes by one), and between that and rebuild
// (the socket that FileConn makes of its own comes by one). The variant of rebuild is diagRebuild.
func TestDiag534Rebuild(t *testing.T) {
	server, client, ln := diagPair(t)
	defer windows.Closesocket(ln)
	defer windows.Closesocket(client)
	defer windows.Closesocket(server)
	want := diagAddr(windows.Getsockname(client))
	fmt.Printf("DIAG rebuild: the variant is %q, the client is %s\n", diagRebuild, want)
	for _, c := range []struct {
		name            string
		before, between int
	}{
		{"nothing is stale", 0, 0},
		{"the socket of the handoff is on a stale value", 4, 0},
		{"the socket of FileConn is on a stale value", 0, 4},
		{"both are", 4, 4},
	} {
		ok, bad := 0, 0
		var first error
		for i := 0; i < 40; i++ {
			if c.before > 0 {
				diagPoison(c.before)
			}
			var info windows.WSAProtocolInfo
			if err := windows.WSADuplicateSocket(server, uint32(os.Getpid()), &info); err != nil {
				t.Fatal(err)
			}
			if c.between > 0 {
				diagPoison(c.between)
			}
			msg, err := encodeHandoff(&info)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := DecodeHandoff(msg)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := rebuild(raw)
			if err != nil {
				bad++
				if first == nil {
					first = err
				}
				continue
			}
			if got := conn.RemoteAddr().String(); got != want {
				bad++
				if first == nil {
					first = fmt.Errorf("the remote address is %s, not %s", got, want)
				}
			} else {
				ok++
			}
			conn.Close()
		}
		fmt.Printf("DIAG rebuild %s: %d of 40 made a connection with the right client, %d did not; the first error: %v\n", c.name, ok, bad, first)
	}
}
