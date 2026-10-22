//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/sidecar"
)

// nodePipeSDDL is the DACL that the node gives its pipe (NODE_BGP_PIPE_SDDL, src/Cedar/NodeBgp.c):
// SYSTEM, the Administrators and the owner, nothing for anyone else.
const nodePipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"

const pipeTimeout = 30 * time.Second

// read returns the next message of the sidecar that has the type typ.
func read(t *testing.T, conn net.Conn, r *sidecar.Reader, typ string) sidecar.Message {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(pipeTimeout))
	for {
		m, err := r.Read()
		if err != nil {
			t.Fatalf("waiting for %s: %v", typ, err)
		}
		if m.Type == typ {
			return m
		}
	}
}

// ranz-bgp on a named pipe that the test creates the way the node does: it connects, starts BGP
// with the settings of start, answers a message it cannot apply with an error, and exits with 0
// when the pipe closes.
func TestPipe(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\ranz-bgp-test-%d`, os.Getpid())
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: nodePipeSDDL})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	timer := time.AfterFunc(pipeTimeout, func() { l.Close() })
	defer timer.Stop()

	logPath := filepath.Join(t.TempDir(), "ranz-bgp.log")
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), []string{"-pipe", name, "-log", logPath}, io.Discard, io.Discard)
	}()

	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("ranz-bgp did not connect to %s: %v", name, err)
	}
	r := sidecar.NewReader(conn)
	w := sidecar.NewWriter(conn)

	err = w.Write(sidecar.Message{
		Type:       sidecar.TypeStart,
		ASN:        65001,
		RouterID:   "192.0.2.1",
		ListenPort: -1,
		Peers:      []sidecar.Peer{{Address: "192.0.2.99", ASN: 65002, Passive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := read(t, conn, r, sidecar.TypeReady)
	if ready.Protocol != sidecar.ProtocolVersion {
		t.Errorf("ready: protocol %d, want %d", ready.Protocol, sidecar.ProtocolVersion)
	}

	if err := w.Write(sidecar.Message{Type: sidecar.TypeWithdraw, Prefix: "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if e := read(t, conn, r, sidecar.TypeError); e.Prefix != "198.51.100.0/24" {
		t.Errorf("error for a prefix that is not announced: %+v", e)
	}

	conn.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("ranz-bgp exited with %d after the node closed the pipe, want 0", code)
		}
	case <-time.After(pipeTimeout):
		t.Fatal("ranz-bgp did not exit after the node closed the pipe")
	}

	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"connected to the node", "BGP started", "the node closed the pipe"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("the log has no %q:\n%s", want, log)
		}
	}
}

// Without the pipe of the node, ranz-bgp exits with 1.
func TestNoPipe(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\ranz-bgp-missing-%d`, os.Getpid())
	if code := run(context.Background(), []string{"-pipe", name}, io.Discard, io.Discard); code != 1 {
		t.Errorf("exit code %d without the pipe of the node, want 1", code)
	}
}
