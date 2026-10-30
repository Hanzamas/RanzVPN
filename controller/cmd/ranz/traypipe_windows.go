//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// trayPipePrefix is where the named pipes of Windows are, and trayPipeDefault the pipe of the logged-in user of the
// Node service (NODE_CLIENT_PIPE of src/Cedar/Node.h), which the Client setting may name another of
const (
	trayPipePrefix  = `\\.\pipe\`
	trayPipeDefault = "ranz-node-client"
)

// trayPipeWait bounds the wait for the pipe while another caller holds it (it has one instance, and the Node
// serves one caller at a time), trayPipeIO each read and write of a command, and trayMaxAnswer the answer of the Node
// (NODE_CLIENT_REPLY of src/Cedar/Node.h)
const (
	trayPipeWait  = 3 * time.Second
	trayPipeIO    = 10 * time.Second
	trayMaxAnswer = 16384
)

// userPipe is the pipe of the logged-in user of the Node service: overlapped I/O through go-winio, so that a Node
// that hangs ends a call by its time limit
type userPipe struct {
	path string
}

// newClientPipe returns the pipe called name, a bare name or a path under \\.\pipe\, the default one for ""
func newClientPipe(name string) clientPipe {
	switch {
	case name == "":
		name = trayPipeDefault
	case strings.HasPrefix(strings.ToLower(name), strings.ToLower(trayPipePrefix)):
		return userPipe{path: name}
	}
	return userPipe{path: trayPipePrefix + name}
}

func (p userPipe) ask(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), trayPipeWait)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, p.path)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return nil, errClientPipeMissing
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return nil, errClientPipeDenied
	case err != nil:
		return nil, fmt.Errorf("the pipe of the logged-in user of the Node service: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(trayPipeIO)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return nil, fmt.Errorf("the pipe of the logged-in user of the Node service: %w", err)
	}
	line, err := bufio.NewReaderSize(conn, trayMaxAnswer).ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("the pipe of the logged-in user of the Node service gave no answer: %w", err)
	}
	return append([]byte(nil), line...), nil
}

// nodeServiceState is what the Service Control Manager says of the Node service
func nodeServiceState() serviceState { return serviceStateOf(install.NodeServiceName) }

// serviceStateOf is what the Service Control Manager says of the service called serviceName. A user without administrator
// rights may ask: the default access list of a service lets the interactive users read its status.
func serviceStateOf(serviceName string) serviceState {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return serviceUnknown
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return serviceUnknown
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return serviceMissing
	case err != nil:
		return serviceUnknown
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return serviceUnknown
	}
	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return serviceRunning
	case windows.SERVICE_START_PENDING:
		return serviceStarting
	}
	return serviceStopped
}
