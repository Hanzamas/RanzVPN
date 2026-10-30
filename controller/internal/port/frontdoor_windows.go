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
	} else {
		f.log.Debug("a handoff of the front door is refused", "err", err)
	}
	// The answer has a time of its own, also after a front door that sent nothing in time
	_ = p.SetDeadline(time.Now().Add(handoffTimeout))
	_, werr := p.Write([]byte{answer})
	// The front door reads the answer and closes its end, which ends this read: a close before it
	// would drop the answer
	if werr == nil {
		_, _ = p.Read(buf[:1])
	}
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

// fileConnTries is how often fileConn tries net.FileConn.
const fileConnTries = 8

// fileConn is net.FileConn of file, tried again after an error.
//
// FileConn makes a socket of its own of the one in file: WSADuplicateSocket and WSASocket in this process, which give the
// new socket the next free value of a handle. Winsock keeps an entry of each socket by the value of its handle until
// closesocket, and Windows gives the value of a closed handle to the next handle that it makes. The entry of a socket that
// was closed with CloseHandle stays, so a socket that comes by its value gets the entry of the older one, a socket that
// was never bound, and FileConn fails in getsockname or in WSASocket. The standard library leaves such an entry in each
// process that dials: the socket that LoadConnectEx makes is closed with CloseHandle. The next try does not meet the same
// entry, as FileConn closes the socket of a try that failed in getsockname with closesocket, which drops the entry. Without
// the next try about one new process in a hundred refused a handoff, and its client saw the connection reset (#534).
func fileConn(file *os.File) (c net.Conn, err error) {
	tries := fileConnTries
	if os.Getenv("RANZ_DIAG_TRIES") == "1" { // THROWAWAY (#534): the measurement of the test without the next try
		tries = 1
	}
	for range tries {
		if c, err = net.FileConn(file); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// rebuild makes the controller's own socket of the WSAPROTOCOL_INFOW of a handoff and returns it as
// a TCP connection of package net.
func rebuild(info [protocolInfoSize]byte) (net.Conn, error) {
	var pi windows.WSAProtocolInfo
	if err := binary.Read(bytes.NewReader(info[:]), binary.LittleEndian, &pi); err != nil {
		return nil, err
	}
	h, err := windows.WSASocket(fromProtocolInfo, fromProtocolInfo, fromProtocolInfo, &pi, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, fmt.Errorf("port: WSASocketW of a handoff: %w", err)
	}
	// FileConn takes a socket of its own of the file, so the file closes after
	file := os.NewFile(uintptr(h), "front door handoff")
	c, err := fileConn(file)
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
