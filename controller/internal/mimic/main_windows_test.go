//go:build windows

package mimic

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/mitigation"
)

// mainEnv makes the test binary run Main itself, on the control pipe it names: the `ranz mimic`
// process of TestMitigations.
const mainEnv = "RANZ_MIMIC_TEST_MAIN"

func TestMain(m *testing.M) {
	if pipe := os.Getenv(mainEnv); pipe != "" {
		os.Exit(Main([]string{"-pipe", pipe, "-log", os.Getenv(mainEnv + "_LOG")}))
	}
	os.Exit(m.Run())
}

// `ranz mimic`, its Main in a process of its own as the node starts it, sets its process mitigations
// before it connects to the control pipe of the node (ADR-0039, SEC-1): it is the process of the
// node that faces the network, so it runs under them as the BGP sidecar does. Read from outside once
// it runs, the process has every mitigation that is not off, and each DLL it loaded is in System32.
// Its log says which mitigations are on, and it exits with 0 when the node closes the pipe.
func TestMitigations(t *testing.T) {
	control := pipeName(t, "mitigations")
	ln, err := listenPipe(control)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	timer := time.AfterFunc(testTimeout, func() { ln.Close() })
	defer timer.Stop()

	logPath := filepath.Join(t.TempDir(), "ranz-mimic.log")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), mainEnv+"="+control, mainEnv+"_LOG="+logPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("ranz mimic did not connect to %s: %v", control, err)
	}
	defer conn.Close()

	start := Message{Type: TypeStart, Role: RoleClient, Pipe: pipeName(t, "data"), Client: clientSettings(t)}
	if err := NewWriter(conn).Write(start); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(testTimeout))
	if m, err := NewReader(conn).Read(); err != nil || m.Type != TypeReady {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("start was answered with %+v, %v", m, err)
	}

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
		t.Errorf("ranz mimic: %s", lack)
	}

	conn.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("ranz mimic did not exit with 0 after the node closed the pipe: %v", err)
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
