//go:build !windows

package main

import (
	"fmt"
	"io"
)

// newClientPipe is the pipe of the logged-in user of the Node service, which is not there on an OS without the Node service
func newClientPipe(string) clientPipe { return noNodePipe{} }

type noNodePipe struct{}

func (noNodePipe) ask(string) ([]byte, error) { return nil, errNodeWindows }

// nodeServiceState asks no Service Control Manager on this OS
func nodeServiceState() serviceState { return serviceUnknown }

// trayWindowRun is the window of the tray, which Windows alone has
func trayWindowRun(_ *trayApp, stderr io.Writer) int {
	fmt.Fprintln(stderr, "ranz tray: the tray runs on Windows only")
	return 2
}
