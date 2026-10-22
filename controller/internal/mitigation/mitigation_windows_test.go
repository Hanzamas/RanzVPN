//go:build windows

package mitigation

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
)

// pidEnv names a running process for TestProcess: the controller service, which
// .github/scripts/controller-service.ps1 checks this way.
const pidEnv = "RANZ_MITIGATION_PID"

// childEnv makes the test binary the child process of TestApply: it calls Apply, prints each
// error, then "applied", and waits until its standard input closes.
const childEnv = "RANZ_MITIGATION_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		results, dllErr := Apply()
		for _, r := range results {
			if r.Err != nil {
				os.Stdout.WriteString("error: " + r.Err.Error() + "\n")
			}
		}
		if dllErr != nil {
			os.Stdout.WriteString("error: " + dllErr.Error() + "\n")
		}
		os.Stdout.WriteString("applied\n")
		bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Apply, in a process of its own: read from outside, the process has every policy of Policies
// that is not off, and each DLL it loaded is in System32. A policy that is off says why.
func TestApply(t *testing.T) {
	for _, p := range Policies {
		if p.Off != "" {
			t.Logf("%s is off: %s", p.Name, p.Off)
		}
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"=1")
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
	defer cmd.Wait()
	defer stdin.Close()

	lines := bufio.NewScanner(stdout)
	applied := false
	for !applied && lines.Scan() {
		if applied = lines.Text() == "applied"; !applied {
			t.Errorf("the child process: %s", lines.Text())
		}
	}
	if !applied {
		t.Fatal("the child process exited before it applied the mitigations")
	}

	checkProcess(t, uint32(cmd.Process.Pid))
}

// The process that pidEnv names, read from outside: it has every policy of Policies that is not
// off, and each DLL it loaded is in System32. A process of another account, such as a service
// that runs as its virtual account, needs the debug privilege of an elevated test.
func TestProcess(t *testing.T) {
	s := os.Getenv(pidEnv)
	if s == "" {
		t.Skip(pidEnv + " names no process")
	}
	pid, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		t.Fatalf("%s=%s: %v", pidEnv, s, err)
	}
	enableDebugPrivilege(t)
	checkProcess(t, uint32(pid))
}

// checkProcess fails t for each thing that Check finds missing in the process pid.
func checkProcess(t *testing.T, pid uint32) {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		t.Fatalf("OpenProcess %d: %v", pid, err)
	}
	defer windows.CloseHandle(h)
	lacks, err := Check(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lacks {
		t.Errorf("process %d: %s", pid, l)
	}
	if len(lacks) == 0 {
		t.Logf("process %d: every mitigation that is not off is set, and every DLL is in System32", pid)
	}
}

// enableDebugPrivilege enables SeDebugPrivilege in the token of the test, which an elevated
// administrator holds.
func enableDebugPrivilege(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		t.Fatal(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
}
