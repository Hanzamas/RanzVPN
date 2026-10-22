//go:build windows

package mitigation

import (
	"bufio"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

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

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	lacks, err := Check(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lacks {
		t.Errorf("the child process: %s", l)
	}
}
