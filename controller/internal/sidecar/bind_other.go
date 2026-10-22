//go:build !linux && !windows

package sidecar

import (
	"os"
	"os/exec"
)

// prepare does nothing: only Linux and Windows tie rqlited to the controller.
func prepare(*exec.Cmd) {}

// bind does nothing: only Linux and Windows tie rqlited to the controller.
func bind(*os.Process) (func(), error) {
	return func() {}, nil
}
