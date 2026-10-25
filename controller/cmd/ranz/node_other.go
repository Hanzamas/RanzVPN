//go:build !windows

package main

import "errors"

// errNodeWindows is the error of the verbs of ranz node on an OS without the Node service
var errNodeWindows = errors.New("the Node service runs on Windows only")

// adminPipe is the Node service of this PC, which is not there on this OS
type adminPipe struct{}

func (adminPipe) ask(string) ([]byte, error) { return nil, errNodeWindows }

func (adminPipe) restart() error { return errNodeWindows }
