//go:build !windows

package install

import (
	"errors"
	"io"
)

var errNotWindows = errors.New("install: the Ranz VPN Node and Controller install as Windows services; there is nothing to install on this OS")

// Install refuses: there is no Windows service on this OS.
func Install(io.Writer, bool) error { return errNotWindows }

// Uninstall refuses: there is no Windows service on this OS.
func Uninstall(io.Writer, UninstallOptions) error { return errNotWindows }
