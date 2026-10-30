//go:build windows

package port

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// On Windows the controller takes the connections that the front door of the node on the same host
// hands over (SDN-73, #352; ADR-0035): the node owns TCP 443 and routes each connection by its TLS
// ClientHello, and the ones of the web UI, the API and the control stream come to the handoff pipe of
// the controller. One handoff is one connection of the front door to the pipe: it writes the handoff
// message (handoff.go), the controller makes its own socket of it, answers, waits until the front
// door closed its end, so that the answer is read, and serves the socket with ServeConn, its own TLS
// handshake with its own certificate included. A message that is malformed, or a socket that cannot
// be made of it, gets handoffNotTaken, and the front door closes the connection. FrontDoorPipe.c is
// the same end in C.

// DefaultFrontDoorPipe is the handoff pipe of the controller, which the front door of a node knows
// by this name (FRONT_DOOR_CONTROLLER_PIPE of src/Core/FrontDoor.h).
const DefaultFrontDoorPipe = `\\.\pipe\ranz-controller-front-door`

// frontDoorSDDL lets the accounts write the pipe that run a node: LocalSystem and the
// Administrators, and the controller's own account. The pipe takes local clients only (go-winio
// rejects remote clients).
const frontDoorSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"

// handoffTimeout bounds a handoff, from the connection of the front door to its close:
// FRONT_DOOR_HANDOFF_TIMEOUT.
const handoffTimeout = 5 * time.Second

// fromProtocolInfo is FROM_PROTOCOL_INFO: WSASocketW takes the family, the type and the protocol of
// the WSAPROTOCOL_INFOW.
const fromProtocolInfo = -1

// FrontDoor is the handoff pipe of a controller.
type FrontDoor struct {
	ln  net.Listener
	srv *Server
	log *slog.Logger

	mu     sync.Mutex
	closed bool
	pipes  map[net.Conn]struct{} // the handoffs that run
	wg     sync.WaitGroup
}

// ListenFrontDoor makes the handoff pipe name, the first instance of it, so a process that took the
// name first makes it fail, and serves each socket that comes through it with s.ServeConn until
// Close.
func ListenFrontDoor(name string, s *Server) (*FrontDoor, error) {
	s.init()
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: frontDoorSDDL, MessageMode: true, InputBufferSize: 4096, OutputBufferSize: 4096})
	if err != nil {
		return nil, fmt.Errorf("port: the handoff pipe %s: %w", name, err)
	}
	f := &FrontDoor{ln: ln, srv: s, log: s.log, pipes: map[net.Conn]struct{}{}}
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

// Addr is the name of the pipe.
func (f *FrontDoor) Addr() string {
	return f.ln.Addr().String()
}

func (f *FrontDoor) accept() {
	defer f.wg.Done()
	for {
		p, err := f.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			f.log.Warn("accepting a front door on the handoff pipe", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			p.Close()
			return
		}
		f.pipes[p] = struct{}{}
		f.wg.Add(1)
		f.mu.Unlock()
		go f.handoff(p)
	}
}

// handoff serves one front door on the pipe p: its message, the socket, the answer.
func (f *FrontDoor) handoff(p net.Conn) {
	defer f.wg.Done()
	_ = p.SetDeadline(time.Now().Add(handoffTimeout))
	// One byte more than a message of this version: a longer one is none
	buf := make([]byte, HandoffSize+1)
	n, err := p.Read(buf)
	var c net.Conn
	if err == nil {
		var info [protocolInfoSize]byte
		if info, err = DecodeHandoff(buf[:n]); err == nil {
			c, err = rebuild(info)
		}
	}
	answer := byte(handoffNotTaken)
	if c != nil {
		answer = handoffTaken
		f.log.Debug("diag: handoff rebuilt", "remote", fmt.Sprint(c.RemoteAddr()), "local", fmt.Sprint(c.LocalAddr()))
	} else {
		f.log.Debug("a handoff of the front door is refused", "err", err)
	}
	// The answer has a time of its own, also after a front door that sent nothing in time
	_ = p.SetDeadline(time.Now().Add(handoffTimeout))
	_, werr := p.Write([]byte{answer})
	f.log.Debug("diag: answer written", "err", werr)
	// The front door reads the answer and closes its end, which ends this read: a close before it
	// would drop the answer
	if werr == nil {
		_, _ = p.Read(buf[:1])
	}
	f.log.Debug("diag: the front door closed its end")
	f.mu.Lock()
	delete(f.pipes, p)
	closed := f.closed
	f.mu.Unlock()
	p.Close()
	if c == nil {
		return
	}
	// A front door that took no answer closed the connection already
	if werr != nil || closed {
		c.Close()
		return
	}
	go f.srv.ServeConn(c)
}

// diagRebuild is the throwaway switch of the measurement of #534 to candidate fixes of rebuild, words in one string: "check"
// copies a handle that Winsock has a stale entry of, "retry" tries FileConn up to three times, "scan" lists the stale entries
// before FileConn and says them when it fails, and "heal" closes the stale entries that the first handoff finds.
var diagRebuild = os.Getenv("RANZ_DIAG_REBUILD")

func diagHas(word string) bool { return strings.Contains(diagRebuild, word) }

// diagSoType is SO_TYPE, which package windows has no name for.
const diagSoType = 0x1008

var diagHealOnce sync.Once

// diagScan lists the handle values that Winsock answers for although they are events of this process: it makes events until
// it has 256, asks each for the type of its socket, and closes them in the reverse order, so that the free slots of the handle
// table come back in the order that they had.
func diagScan() []windows.Handle {
	var held, stale []windows.Handle
	for i := 0; i < 256; i++ {
		e, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			break
		}
		if _, err := windows.GetsockoptInt(e, windows.SOL_SOCKET, diagSoType); err == nil {
			stale = append(stale, e)
		}
		held = append(held, e)
	}
	for i := len(held) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(held[i])
	}
	return stale
}

// diagHeal closes, with closesocket, the events of diagScan that Winsock holds an entry of a socket for.
func diagHeal() {
	var held []windows.Handle
	healed := 0
	for i := 0; i < 256; i++ {
		e, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			break
		}
		if _, err := windows.GetsockoptInt(e, windows.SOL_SOCKET, diagSoType); err == nil {
			_ = windows.Closesocket(e)
			healed++
			continue
		}
		held = append(held, e)
	}
	for i := len(held) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(held[i])
	}
	fmt.Fprintf(os.Stderr, "DIAG healed %d\n", healed)
}

// diagCheck takes the handle of a handoff that is not a connected socket for one that Winsock holds a stale entry of, and
// copies it to another value: the copy has no entry, and closesocket of the old value drops the stale one.
func diagCheck(h windows.Handle) windows.Handle {
	if _, err := windows.Getpeername(h); err == nil {
		return h
	}
	fmt.Fprintf(os.Stderr, "DIAG stale d1 h=%#x\n", uintptr(h))
	var c windows.Handle
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, h, self, &c, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		fmt.Fprintf(os.Stderr, "DIAG check: DuplicateHandle: %v\n", err)
		return h
	}
	_ = windows.Closesocket(h)
	if _, err := windows.Getpeername(c); err != nil {
		fmt.Fprintf(os.Stderr, "DIAG check: getpeername of the copy %#x: %v\n", uintptr(c), err)
	}
	return c
}

// diagFail says what is known when FileConn fails for good.
func diagFail(h windows.Handle, err error, stale []windows.Handle) {
	_, nerr := windows.Getsockname(h)
	_, perr := windows.Getpeername(h)
	fmt.Fprintf(os.Stderr, "DIAG filecon failed: handle %#x, getsockname %v, getpeername %v, stale entries before FileConn %#x, err %v\n", uintptr(h), nerr, perr, stale, err)
}

// handleFlagProtectFromClose is HANDLE_FLAG_PROTECT_FROM_CLOSE: CloseHandle does not close a handle that has it.
const handleFlagProtectFromClose = 0x2

// closeSocketFile closes file, which holds the handle h of a socket, and the socket with it, as closesocket does.
// os.File closes a handle with CloseHandle, which Winsock does not hear of: Winsock keeps state by the value of each
// socket handle, the remote address among it, until closesocket drops it, and a socket that comes by the same value
// later starts with that state. The next handoff then got a connection that reported the client of an older one as its
// remote address (#534), which the API and the limits for a source go by. So h is protected from the close of the file,
// which then fails and leaves it open, and closesocket closes it.
func closeSocketFile(file *os.File, h windows.Handle) {
	// A debugger takes the close of a protected handle for an exception, which would end the process, so there the file
	// closes the handle itself
	if windows.RtlGetCurrentPeb().BeingDebugged != 0 || windows.SetHandleInformation(h, handleFlagProtectFromClose, handleFlagProtectFromClose) != nil {
		file.Close()
		return
	}
	if file.Close() == nil {
		// The handle is closed after all, and no longer ours to close
		return
	}
	_ = windows.SetHandleInformation(h, handleFlagProtectFromClose, 0)
	_ = windows.Closesocket(h)
}

// rebuild makes the controller's own socket of the WSAPROTOCOL_INFOW of a handoff and returns it as
// a TCP connection of package net.
func rebuild(info [protocolInfoSize]byte) (net.Conn, error) {
	var pi windows.WSAProtocolInfo
	if err := binary.Read(bytes.NewReader(info[:]), binary.LittleEndian, &pi); err != nil {
		return nil, err
	}
	if diagHas("heal") {
		diagHealOnce.Do(diagHeal)
	}
	h, err := windows.WSASocket(fromProtocolInfo, fromProtocolInfo, fromProtocolInfo, &pi, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, fmt.Errorf("port: WSASocketW of a handoff: %w", err)
	}
	if diagHas("probe") {
		if _, err := windows.Getpeername(h); err != nil {
			_, nerr := windows.Getsockname(h)
			typ, terr := windows.GetsockoptInt(h, windows.SOL_SOCKET, diagSoType)
			fmt.Fprintf(os.Stderr, "DIAG d1 odd: handle %#x, getpeername %v, getsockname %v, SO_TYPE %d (%v)\n", uintptr(h), err, nerr, typ, terr)
		}
	}
	if diagHas("check") {
		h = diagCheck(h)
	}
	// FileConn takes a socket of its own of the file, so the file closes after
	file := os.NewFile(uintptr(h), "front door handoff")
	var stale []windows.Handle
	if diagHas("scan") {
		stale = diagScan()
	}
	tries := 1
	if diagHas("retry8") {
		tries = 8
	} else if diagHas("retry") {
		tries = 3
	}
	var c net.Conn
	for i := 1; ; i++ {
		c, err = net.FileConn(file)
		if err == nil || i >= tries {
			break
		}
		fmt.Fprintf(os.Stderr, "DIAG filecon retry %d: %v\n", i, err)
	}
	if err != nil {
		diagFail(h, err, stale)
	}
	closeSocketFile(file, h)
	if err != nil {
		return nil, fmt.Errorf("port: the socket of a handoff: %w", err)
	}
	return c, nil
}

// Close closes the pipe and the handoffs that run, and returns once they ended; the connections that
// came through it before are the Server's.
func (f *FrontDoor) Close() error {
	f.mu.Lock()
	f.closed = true
	for p := range f.pipes {
		p.Close()
	}
	f.mu.Unlock()
	err := f.ln.Close()
	f.wg.Wait()
	return err
}
