//go:build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// nodePipeBusy bounds the wait of a verb for the admin pipe while another caller holds it, or while
// a service that just started has not made it yet: the pipe has one instance, and the service
// answers one caller at a time.
const nodePipeBusy = 10 * time.Second

// nodeMaxAnswer bounds the answer of the Node service: one JSON line (NODE_ADMIN_REPLY of
// src/Cedar/Node.h).
const nodeMaxAnswer = 4096

// errNodeNotRunning is the error of the admin pipe when no Node service serves it
var errNodeNotRunning = errors.New("the Node service " + install.NodeServiceName + " does not run here (its admin pipe is not there): start it with Start-Service " + install.NodeServiceName)

// errNodeAdmin is the error of the admin pipe for a caller without administrator rights
var errNodeAdmin = errors.New("ranz node needs administrator rights: run it in a window that was opened as Administrator")

// adminPipe is the Node service of this PC, reached on its admin pipe
type adminPipe struct{}

func (adminPipe) ask(command string) ([]byte, error) {
	f, err := openAdminPipe()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(command + "\n"); err != nil {
		return nil, fmt.Errorf("the admin pipe of the Node service: %w", err)
	}
	line, err := bufio.NewReaderSize(f, nodeMaxAnswer).ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("the admin pipe of the Node service gave no answer: %w", err)
	}
	return line, nil
}

func (adminPipe) restart() error {
	return install.RestartNode()
}

// openAdminPipe opens the admin pipe of the Node service, and waits while another caller holds it or
// the service is starting
func openAdminPipe() (*os.File, error) {
	deadline := time.Now().Add(nodePipeBusy)
	for {
		f, err := os.OpenFile(nodeAdminPipe, os.O_RDWR, 0)
		waiting := time.Now().Before(deadline)
		switch {
		case err == nil:
			return f, nil
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, errNodeAdmin
		case (errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)) && waiting:
			time.Sleep(100 * time.Millisecond)
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, errNodeNotRunning
		default:
			return nil, fmt.Errorf("the admin pipe of the Node service: %w", err)
		}
	}
}
