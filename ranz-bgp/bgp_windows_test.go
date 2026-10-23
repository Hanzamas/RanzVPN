//go:build windows

package bgpcmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/mitigation"
	"github.com/Hanzamas/RanzVPN/ranz-bgp/internal/sidecar"
)

// nodePipeSDDL is the strict DACL that the node gives its pipe (NODE_BGP_PIPE_SDDL,
// src/Cedar/NodeBgp.c; ADR-0039 decision 3): the owner alone, the account of the node, which
// the sidecar runs as.
const nodePipeSDDL = "D:P(A;;GA;;;OW)"

const pipeTimeout = 30 * time.Second

// mainEnv makes the test binary run Main itself, on the pipe it names: the `ranz bgp` process of
// TestMitigations.
const mainEnv = "RANZ_BGP_TEST_MAIN"

func TestMain(m *testing.M) {
	if pipe := os.Getenv(mainEnv); pipe != "" {
		os.Exit(Main([]string{"-pipe", pipe, "-log", os.Getenv(mainEnv + "_LOG")}))
	}
	os.Exit(m.Run())
}

// `ranz bgp`, its Main in a process of its own as the node starts it, sets its process mitigations
// before it connects to the pipe of the node (internal/mitigation) and runs BGP under them: read
// from outside once BGP started, the process has every one that is not off, and each DLL it
// loaded is in System32. Its log says which mitigations are on, and it exits with 0 when the pipe
// closes.
func TestMitigations(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\ranz-bgp-mitigations-%d`, os.Getpid())
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: nodePipeSDDL})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	timer := time.AfterFunc(pipeTimeout, func() { l.Close() })
	defer timer.Stop()

	logPath := filepath.Join(t.TempDir(), "ranz-bgp.log")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), mainEnv+"="+name, mainEnv+"_LOG="+logPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := l.Accept()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("ranz bgp did not connect to %s: %v", name, err)
	}
	err = sidecar.NewWriter(conn).Write(sidecar.Message{
		Type:       sidecar.TypeStart,
		ASN:        65001,
		RouterID:   "192.0.2.1",
		ListenPort: -1,
		Peers:      []sidecar.Peer{{Address: "192.0.2.99", ASN: 65002, Passive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	read(t, conn, sidecar.NewReader(conn), sidecar.TypeReady)

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	lacks, err := mitigation.Check(h)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, lack := range lacks {
		t.Errorf("ranz bgp: %s", lack)
	}

	conn.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("ranz bgp did not exit with 0 after the node closed the pipe: %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range mitigation.Policies {
		want := `msg="process mitigation on" name=` + p.Name
		if p.Off != "" {
			want = `msg="process mitigation off" name=` + p.Name
		}
		if !strings.Contains(string(log), want) {
			t.Errorf("the log has no %q:\n%s", want, log)
		}
	}
	if !strings.Contains(string(log), "DLLs load from System32 only") {
		t.Errorf("the log does not say that DLLs load from System32 only:\n%s", log)
	}
}

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

// `ranz bgp` on a named pipe that the test creates the way the node does: it connects, starts BGP
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
		done <- run(context.Background(), []string{"-pipe", name, "-log", logPath}, io.Discard)
	}()

	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("ranz bgp did not connect to %s: %v", name, err)
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
			t.Errorf("ranz bgp exited with %d after the node closed the pipe, want 0", code)
		}
	case <-time.After(pipeTimeout):
		t.Fatal("ranz bgp did not exit after the node closed the pipe")
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

// Without the pipe of the node, `ranz bgp` exits with 1.
func TestNoPipe(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\ranz-bgp-missing-%d`, os.Getpid())
	if code := run(context.Background(), []string{"-pipe", name}, io.Discard); code != 1 {
		t.Errorf("exit code %d without the pipe of the node, want 1", code)
	}
}
