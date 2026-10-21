package sidecar

import (
	"os"
	"os/exec"
	"syscall"
)

// prepare has the kernel kill rqlited when the controller exits (PR_SET_PDEATHSIG).
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// bind does nothing: prepare tied rqlited to the controller already.
func bind(*os.Process) (func(), error) {
	return func() {}, nil
}
